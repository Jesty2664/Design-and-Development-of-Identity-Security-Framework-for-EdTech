# High-Level Design (HLD) - Identity Security Framework for EdTech

## 1. System Architecture
The application runs as a modular Flask web server leveraging a local SQLite database designed to conform strictly to EdTech paradigms and FERPA principles. 

### 1.1 Core Components
*   **Web Framework:** Flask / Flask-Login (Routing and HTTP cookie management).
*   **Database Interface:** Flask-SQLAlchemy interfacing with `edtech.db`.
*   **OAuth Engine:** Authlib interacting with Google OpenID connectors.
*   **TOTP Engine:** PyOTP validating 6-digit Time-Based codes.
*   **WebAuthn Engine:** FIDO2/WebAuthn implementation for Passkeys and Biometric (Face Lock) authentication.
*   **Frontend Representation:** Tailwind CSS injection across HTML Jinja2 templates.

### 1.2 Authentication & Authorization Pathing
*   **Authentication:** Users identify themselves via:
    - Standard Email/Password.
    - Google OAuth (SSO).
    - **WebAuthn Passkeys/Face Lock** (Password replacements for modern browsers).
    - All paths terminate into a mandatory 2-Factor (TOTP) check if configured.
*   **Authorization:** The `@admin_required` decorators ensure students physically cannot access whitelisting routes, preventing privilege escalation.

## 2. Security Defense Mechanics
*   **Brute-Force (Login):** Intercepted via `failed_attempts` integers. Locks the account after 5 misses for 15 minutes.
*   **Brute-Force (Registration Spam):** Intercepted via `request.remote_addr`. Invalid identifiers bounce the payload and strike the IP address on the `ip_blacklist` table, completely dropping connections after 5 strikes.
*   **WebAuthn Signature Counter:** Protects against replay attacks by verifying the signature count on every FIDO2 handshake.
*   **Cross-Site Request Forgery (CSRF):** Overlain across all HTML forms via Flask-WTF `{{ csrf_token() }}`.

## 3. Database Schema Overview
### 3.1 Primary Users Table
*   `id` (PK)
*   `email` (VARCHAR(100), UNIQUE)
*   `password_hash` (VARCHAR(256))
*   `google_id`, `role`, `is_2fa_required`
*   **WebAuthn Fields**: 
    - `webauthn_passkey_id`, `webauthn_passkey_public_key`, `webauthn_passkey_sign_count`
    - `webauthn_face_id`, `webauthn_face_public_key`, `webauthn_face_sign_count`
*   `login_count`: Tracks session integrity; unlocks voluntary 2FA/WebAuthn disable after 5 successful logins.
*   `failed_attempts`, `locked_until` (Brute-force tracking).

### 3.2 Auxiliary Protection Tables
*   `ip_blacklist`: Logs failed remote IP hits for 15-minute global timeouts.
*   `allowed_student_ids`: Whitelist registry required for Student Roles (Campus ID).
*   `allowed_teacher_emails`: Whitelist registry required for Teacher Roles.
*   `backup_codes`: Single-use bcrypt hashed emergency fallback strings.
*   `audit_logs`: Detailed tracking of security events with PQC signatures.

