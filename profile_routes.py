from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_required, current_user
from models import db
import utils
from utils import sss
import json

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@profile_bp.route('/backup-codes')
@login_required
def backup_codes_display():
    codes = session.pop('new_backup_codes', None)
    if not codes:
        flash('Backup codes are only displayed once.', 'warning')
        return redirect(url_for('profile.dashboard'))
    return render_template('backup_codes.html', codes=codes)

@profile_bp.route('/security', methods=['GET'])
@login_required
def security_settings():
    return render_template('security.html', user=current_user)

@profile_bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    # Only allow if login_count >= 5
    if current_user.login_count < 5:
        flash('You must have at least 5 successful logins to disable mandatory 2FA.', 'danger')
        return redirect(url_for('profile.security_settings'))
        
    current_user.is_2fa_required = False
    db.session.commit()
    flash('Two-Factor Authentication is now disabled.', 'info')
    return redirect(url_for('profile.security_settings'))
    
@profile_bp.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    # Allow voluntary re-enable
    return redirect(url_for('auth.setup_2fa'))

@profile_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    old = request.form.get('old_password')
    new = request.form.get('new_password')
    
    if current_user.password_hash == "OAUTH":
        flash('Your account is secured via Google Login.', 'warning')
        return redirect(url_for('profile.security_settings'))
        
    if utils.check_hash(old, current_user.password_hash):
        current_user.password_hash = utils.hash_string(new)
        # Update Fragments
        current_user.pw_fragment_start = new[:2] if len(new) >= 2 else new
        current_user.pw_fragment_end = new[-2:] if len(new) >= 2 else new
        db.session.commit()
        flash('Password successfully updated!', 'success')
    else:
        flash('Incorrect old password.', 'danger')
        
    return redirect(url_for('profile.security_settings'))

@profile_bp.route('/setup-recovery', methods=['POST'])
@login_required
def setup_recovery():
    """Splits the TOTP secret into 3 shards for social recovery."""
    if not current_user.totp_secret:
        flash('You must have 2FA enabled to setup social recovery.', 'danger')
        return redirect(url_for('profile.security_settings'))
        
    # Generate 3 shards, 2 required to recover
    shards = sss.secret_to_shards(current_user.totp_secret, min_shares=2, total_shares=3)
    
    # Distribution logic:
    # Shard 1: Local (returned to JS for localStorage)
    # Shard 2: Guardian (returned to user to share)
    # Shard 3: Vault (stored in DB metadata as a check/hint)
    
    current_user.recovery_shards = {
        'vault_shard': shards[2], # Index 2
        'status': 'ACTIVE',
        'threshold': 2
    }
    db.session.commit()
    
    return json.dumps({
        'status': 'ok',
        'shards': {
            'local': shards[0],
            'guardian': shards[1]
        }
    })
