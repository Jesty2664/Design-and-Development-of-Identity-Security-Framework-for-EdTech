from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    google_id = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    
    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_required = db.Column(db.Boolean, default=True)
    
    # --- Aether-Chasm Evolution Fields ---
    public_hardware_key = db.Column(db.Text, nullable=True) # RSA Public Key from browser TPM
    recovery_shards = db.Column(db.JSON, nullable=True)   # Encrypted Shamir shards metadata
    network_node_id = db.Column(db.String(64), nullable=True) # Unique hardware/browser fingerprint
    # ------------------------------------

    # --- WebAuthn: Passkey & Face Lock ---
    webauthn_passkey_id = db.Column(db.Text, nullable=True)           # Base64url credential ID
    webauthn_passkey_public_key = db.Column(db.Text, nullable=True)   # CBOR public key (Base64url)
    webauthn_passkey_sign_count = db.Column(db.Integer, default=0)    # Replay-attack counter
    has_passkey_enabled = db.Column(db.Boolean, default=False)

    webauthn_face_id = db.Column(db.Text, nullable=True)              # Base64url credential ID
    webauthn_face_public_key = db.Column(db.Text, nullable=True)      # CBOR public key (Base64url)
    webauthn_face_sign_count = db.Column(db.Integer, default=0)       # Replay-attack counter
    has_face_lock_enabled = db.Column(db.Boolean, default=False)
    # -------------------------------------
    
    login_count = db.Column(db.Integer, default=0)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    failed_2fa_attempts = db.Column(db.Integer, default=0)
    locked_2fa_until = db.Column(db.DateTime, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # --- Cipher Fragment Security ---
    pw_fragment_start = db.Column(db.String(2), nullable=True) # First 2 chars
    pw_fragment_end = db.Column(db.String(2), nullable=True)   # Last 2 chars

class BackupCode(db.Model):
    __tablename__ = 'backup_codes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    code_hash = db.Column(db.String(256), nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('backup_codes', lazy=True, cascade="all, delete-orphan"))

class AllowedStudentId(db.Model):
    __tablename__ = 'allowed_student_ids'
    id = db.Column(db.Integer, primary_key=True)
    campus_id = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AllowedTeacherEmail(db.Model):
    __tablename__ = 'allowed_teacher_emails'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class IPBlacklist(db.Model):
    __tablename__ = 'ip_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)

class ClearanceRequest(db.Model):
    __tablename__ = 'clearance_requests'
    id = db.Column(db.Integer, primary_key=True)
    request_type = db.Column(db.String(20), nullable=False) # 'identity' or 'ip'
    identifier = db.Column(db.String(100), nullable=False)
    role_requested = db.Column(db.String(20), nullable=True) # student/teacher
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    details = db.Column(db.Text, nullable=True)
    # Quantum Armor Signature
    pqc_signature = db.Column(db.LargeBinary, nullable=True) 

class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = db.Column(db.String(256), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True, cascade="all, delete-orphan"))
