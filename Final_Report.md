# Final Report: Identity Security Framework for EdTech

## 1. Introduction
*   Context on Educational Technology (EdTech) scale breaches and the need for zero-trust identity architectures.
*   The necessity for identity management complying with FERPA parameters, specifically separating Student footprints from Teacher administrative rights using whitelisted identifiers.

## 2. Technology Stack & Framework
*   **Backend & DB:** Python, Flask, SQLite / SQLAlchemy ORM.
*   **Core Security Libraries:** Flask-Login, PyOTP, bcrypt, Authlib, webauthn (FIDO2).
*   **Frontend Representation:** Tailwind CSS implementation for a professional SaaS-grade UI.

## 3. Implementation of Security Algorithms
### 3.1 OAuth & Brute-Force Monitoring
*   Implemented strict 5-lock iterations across multiple vectors. Brute-force is mitigated via global login timeouts and IP-based connection dropping for registration spam.

### 3.2 Two-Factor Authentication Lifecycle
*   Employed standard RFC 6238 TOTP via Google Authenticator.
*   **Backup Strategy**: Single-use hashed backup codes for account restoration.

### 3.3 WebAuthn: Passkeys & Face Lock
*   Successfully implemented FIDO2 WebAuthn support.
*   Users can bind hardware passkeys or platform biometrics (Face Lock) as password replacements.
*   Enforces a "Trust Threshold": Biometric enrollment is only available after 5 successful manual logins.

### 3.4 Future-Proofing: Quantum Guard
*   Implemented Lattice-based cryptographic signatures for high-fidelity audit logs, ensuring non-repudiation in a post-quantum environment.

## 4. Conclusion
*   The project successfully demonstrates a multi-layered security framework designed specifically for EdTech. 
*   By combining Google SSO, TOTP, WebAuthn, and decentralized recovery (Shamir's Shards), the platform provides a production-ready solution for securing educational identities.

