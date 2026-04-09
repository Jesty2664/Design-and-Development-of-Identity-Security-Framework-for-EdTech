"""
WebAuthn Routes — Passkey & Face Lock
Endpoints:
  POST /webauthn/register/begin    — generate registration challenge (logged-in users only, >= 5 logins)
  POST /webauthn/register/complete — verify and store credential
  POST /webauthn/login/begin       — generate authentication challenge
  POST /webauthn/login/complete    — verify and complete login (then redirect to TOTP)
  POST /webauthn/disable           — remove a credential
"""
import os
import json
import base64
from datetime import datetime

from flask import Blueprint, request, session, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user, login_user

import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from models import db, User, AuditLog

webauthn_bp = Blueprint('webauthn', __name__, url_prefix='/webauthn')

# ── Config ─────────────────────────────────────────────────────────────────
# RP_ID should be the domain (e.g., 'localhost', 'edtech.edu')
RP_ID   = os.getenv('WEBAUTHN_RP_ID', 'localhost')
RP_NAME = os.getenv('WEBAUTHN_RP_NAME', 'EdTech Aether-Chasm')
# ORIGIN must include the protocol, host, and port if not 80/443 (e.g., 'http://localhost:5000')
ORIGIN  = os.getenv('WEBAUTHN_ORIGIN', f'http://{RP_ID}:5000')


# ── Helpers ─────────────────────────────────────────────────────────────────
def _audit(action: str, user_id: int, details: str):
    db.session.add(AuditLog(action=action, user_id=user_id, details=details))
    db.session.commit()


def _json_error(msg, status=400):
    return jsonify({'status': 'error', 'message': msg}), status


# ══════════════════════════════════════════════════════════════════════════════
#  REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

@webauthn_bp.route('/register/begin', methods=['POST'])
@login_required
def register_begin():
    """Generate a WebAuthn registration challenge. Requires >= 5 logins."""
    if current_user.login_count < 5:
        return _json_error('Complete 5 successful logins before enabling passkey or face lock.', 403)

    data   = request.get_json(silent=True) or {}
    method = data.get('method')  # 'passkey' or 'face_lock'
    if method not in ('passkey', 'face_lock'):
        return _json_error('Invalid method. Use "passkey" or "face_lock".')

    # Authenticator selection
    if method == 'face_lock':
        authenticator_selection = AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        )
    else:
        authenticator_selection = AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        )

    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(current_user.id).encode(),
        user_name=current_user.email,
        user_display_name=current_user.email.split('@')[0],
        authenticator_selection=authenticator_selection,
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    # Store challenge in session
    session['webauthn_reg_challenge'] = bytes_to_base64url(options.challenge)
    session['webauthn_reg_method']    = method

    return jsonify(json.loads(webauthn.options_to_json(options)))


@webauthn_bp.route('/register/complete', methods=['POST'])
@login_required
def register_complete():
    """Verify the browser's registration response and persist the credential."""
    challenge_b64 = session.pop('webauthn_reg_challenge', None)
    method        = session.pop('webauthn_reg_method', None)

    if not challenge_b64 or not method:
        return _json_error('No pending registration session. Please start again.', 400)

    body = request.get_json(silent=True)
    if not body:
        return _json_error('Missing credential JSON.')

    try:
        credential = webauthn.helpers.structs.RegistrationCredential.parse_raw(json.dumps(body))
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=(method == 'face_lock'),
        )
    except Exception as e:
        return _json_error(f'Registration verification failed: {str(e)}', 400)

    cred_id_b64  = bytes_to_base64url(verification.credential_id)
    pub_key_b64  = bytes_to_base64url(verification.credential_public_key)
    sign_count   = verification.sign_count

    if method == 'passkey':
        current_user.webauthn_passkey_id         = cred_id_b64
        current_user.webauthn_passkey_public_key = pub_key_b64
        current_user.webauthn_passkey_sign_count = sign_count
        current_user.has_passkey_enabled         = True
        _audit('WEBAUTHN_PASSKEY_REGISTERED', current_user.id, f'Method=passkey, credId={cred_id_b64[:20]}...')
    else:
        current_user.webauthn_face_id            = cred_id_b64
        current_user.webauthn_face_public_key    = pub_key_b64
        current_user.webauthn_face_sign_count    = sign_count
        current_user.has_face_lock_enabled       = True
        _audit('WEBAUTHN_FACE_REGISTERED', current_user.id, f'Method=face_lock, credId={cred_id_b64[:20]}...')

    db.session.commit()
    return jsonify({'status': 'ok', 'message': f'{method.replace("_", " ").title()} registered successfully.'})


# ══════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

@webauthn_bp.route('/login/begin', methods=['POST'])
def login_begin():
    """
    Generate an authentication challenge.
    Requires the user's email + method so we can fetch their stored credential.
    """
    data   = request.get_json(silent=True) or {}
    email  = (data.get('email') or '').strip().lower()
    method = data.get('method')

    if not email:
        return _json_error('Email is required.')
    if method not in ('passkey', 'face_lock'):
        return _json_error('Invalid method.')

    user = User.query.filter_by(email=email).first()
    if not user:
        # Generic message — don't reveal whether account exists
        return _json_error('No credential found for this account. Please sign in with password.', 404)

    # Check the relevant credential is actually set up
    if method == 'passkey' and not user.has_passkey_enabled:
        return _json_error('Passkey not enabled. Please sign in with your password and enable it from Security Settings.', 404)
    if method == 'face_lock' and not user.has_face_lock_enabled:
        return _json_error('Face Lock not enabled. Please sign in with your password and enable it from Security Settings.', 404)

    # Account lockout check
    if user.locked_until and user.locked_until > datetime.utcnow():
        delta = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
        return _json_error(f'Account locked. Try again in {delta} minutes.', 403)

    cred_id_b64 = user.webauthn_passkey_id if method == 'passkey' else user.webauthn_face_id

    # Build allowed credentials list
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    allowed = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id_b64))]

    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allowed,
        user_verification=UserVerificationRequirement.REQUIRED if method == 'face_lock'
                          else UserVerificationRequirement.PREFERRED,
    )

    session['webauthn_auth_challenge'] = bytes_to_base64url(options.challenge)
    session['webauthn_auth_user_id']   = user.id
    session['webauthn_auth_method']    = method

    return jsonify(json.loads(webauthn.options_to_json(options)))


@webauthn_bp.route('/login/complete', methods=['POST'])
def login_complete():
    """
    Verify the authentication response.
    On success → store user in session as pending_2fa_user_id (TOTP still required).
    """
    challenge_b64 = session.pop('webauthn_auth_challenge', None)
    user_id       = session.pop('webauthn_auth_user_id', None)
    method        = session.pop('webauthn_auth_method', None)

    if not challenge_b64 or not user_id or not method:
        return _json_error('No pending authentication session. Please start again.', 400)

    body = request.get_json(silent=True)
    if not body:
        return _json_error('Missing credential JSON.')

    user = User.query.get(user_id)
    if not user:
        return _json_error('User not found.', 404)

    if method == 'passkey':
        stored_cred_id  = user.webauthn_passkey_id
        stored_pub_key  = user.webauthn_passkey_public_key
        stored_count    = user.webauthn_passkey_sign_count or 0
    else:
        stored_cred_id  = user.webauthn_face_id
        stored_pub_key  = user.webauthn_face_public_key
        stored_count    = user.webauthn_face_sign_count or 0

    try:
        credential = webauthn.helpers.structs.AuthenticationCredential.parse_raw(json.dumps(body))
        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(stored_pub_key),
            credential_current_sign_count=stored_count,
            require_user_verification=(method == 'face_lock'),
        )
    except Exception as e:
        # Increment failure counter
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= 5:
            from datetime import timedelta
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
        return _json_error(f'Authentication failed: {str(e)}', 401)

    # Update sign count (replay-attack protection)
    if method == 'passkey':
        user.webauthn_passkey_sign_count = verification.new_sign_count
    else:
        user.webauthn_face_sign_count = verification.new_sign_count

    user.failed_attempts = 0
    user.locked_until    = None
    db.session.commit()

    _audit(f'WEBAUTHN_{method.upper()}_LOGIN', user.id, f'WebAuthn {method} authentication successful.')

    # ── Key decision: Passkey/Face Lock = password replacement only.
    # TOTP is STILL required if the user has it set up.
    if user.is_2fa_required and user.totp_secret:
        session['pending_2fa_user_id'] = user.id
        return jsonify({'status': 'ok', 'redirect': url_for('auth.verify_2fa')})
    else:
        user.login_count += 1
        db.session.commit()
        login_user(user)
        return jsonify({'status': 'ok', 'redirect': url_for('profile.dashboard')})


# ══════════════════════════════════════════════════════════════════════════════
#  DISABLE
# ══════════════════════════════════════════════════════════════════════════════

@webauthn_bp.route('/disable', methods=['POST'])
@login_required
def disable():
    """Remove a WebAuthn credential from the user's account."""
    data   = request.get_json(silent=True) or {}
    method = data.get('method')

    if method == 'passkey':
        current_user.webauthn_passkey_id         = None
        current_user.webauthn_passkey_public_key = None
        current_user.webauthn_passkey_sign_count = 0
        current_user.has_passkey_enabled         = False
        _audit('WEBAUTHN_PASSKEY_DISABLED', current_user.id, 'Passkey credential removed.')
    elif method == 'face_lock':
        current_user.webauthn_face_id            = None
        current_user.webauthn_face_public_key    = None
        current_user.webauthn_face_sign_count    = 0
        current_user.has_face_lock_enabled       = False
        _audit('WEBAUTHN_FACE_DISABLED', current_user.id, 'Face Lock credential removed.')
    else:
        return _json_error('Invalid method.')

    db.session.commit()
    return jsonify({'status': 'ok', 'message': f'{method.replace("_", " ").title()} disabled.'})
