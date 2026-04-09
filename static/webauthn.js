/**
 * Aether-Chasm WebAuthn Helper
 * Handles Passkey and Face Lock registration and authentication.
 *
 * Base64url encoding/decoding is required because WebAuthn uses ArrayBuffers
 * but JSON only supports strings.
 */

// ══════════════════════════════════════════════════════════════════════════════
//  BASE64URL HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const byte of bytes) str += String.fromCharCode(byte);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToBuffer(b64url) {
    const padded = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const str    = atob(padded);
    const bytes  = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes.buffer;
}

/**
 * Recursively walk the object returned from the server and convert any
 * base64url string fields that WebAuthn expects as ArrayBuffers.
 */
function decodeCredentialCreationOptions(opts) {
    opts.challenge = base64urlToBuffer(opts.challenge);
    opts.user.id   = base64urlToBuffer(opts.user.id);
    if (opts.excludeCredentials) {
        opts.excludeCredentials = opts.excludeCredentials.map(c => ({
            ...c, id: base64urlToBuffer(c.id)
        }));
    }
    return opts;
}

function decodeCredentialRequestOptions(opts) {
    opts.challenge = base64urlToBuffer(opts.challenge);
    if (opts.allowCredentials) {
        opts.allowCredentials = opts.allowCredentials.map(c => ({
            ...c, id: base64urlToBuffer(c.id)
        }));
    }
    return opts;
}

/**
 * Encode a PublicKeyCredential (either create or get) back to JSON
 * so it can be sent to the server.
 */
function encodeCredential(credential) {
    const cred = {
        id:   credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
    };

    if (credential.response.attestationObject !== undefined) {
        // Registration response
        cred.response = {
            clientDataJSON:    bufferToBase64url(credential.response.clientDataJSON),
            attestationObject: bufferToBase64url(credential.response.attestationObject),
        };
    } else {
        // Authentication response
        cred.response = {
            clientDataJSON:    bufferToBase64url(credential.response.clientDataJSON),
            authenticatorData: bufferToBase64url(credential.response.authenticatorData),
            signature:         bufferToBase64url(credential.response.signature),
            userHandle: credential.response.userHandle
                ? bufferToBase64url(credential.response.userHandle) : null,
        };
    }
    return cred;
}

// ══════════════════════════════════════════════════════════════════════════════
//  FEATURE DETECTION
// ══════════════════════════════════════════════════════════════════════════════

async function isFaceLockSupported() {
    if (!window.PublicKeyCredential) return false;
    try {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (_) {
        return false;
    }
}

async function isPasskeySupported() {
    return !!window.PublicKeyCredential;
}

// ══════════════════════════════════════════════════════════════════════════════
//  CSRF TOKEN HELPER
// ══════════════════════════════════════════════════════════════════════════════

function getCsrfToken() {
    const el = document.querySelector('input[name="csrf_token"]') ||
               document.querySelector('meta[name="csrf-token"]');
    return el ? (el.value || el.content) : '';
}

// ══════════════════════════════════════════════════════════════════════════════
//  REGISTRATION (Security Settings page)
// ══════════════════════════════════════════════════════════════════════════════

async function registerWebAuthn(method) {
    logToTerminal(`[WEBAUTHN] Starting ${method} registration...`);

    try {
        // 1. Get registration options from server
        const beginResp = await fetch('/webauthn/register/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ method })
        });
        const options = await beginResp.json();

        if (!beginResp.ok) {
            throw new Error(options.message || 'Server error during registration begin.');
        }

        logToTerminal(`[WEBAUTHN] Challenge received. Prompting device authenticator...`);

        // Convert base64url fields to ArrayBuffers
        const publicKey = decodeCredentialCreationOptions(options);

        // 2. Invoke browser's WebAuthn create()
        let credential;
        try {
            credential = await navigator.credentials.create({ publicKey });
        } catch (err) {
            if (err.name === 'NotSupportedError' || err.name === 'NotAllowedError') {
                throw new Error(
                    method === 'face_lock'
                        ? 'Face recognition not available on this device. Your camera may be missing or blocked.'
                        : 'Passkey creation was cancelled or not supported by this device.'
                );
            }
            throw err;
        }

        logToTerminal(`[WEBAUTHN] Credential created. Verifying with server...`);

        // 3. Send credential to server for verification
        const completeResp = await fetch('/webauthn/register/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify(encodeCredential(credential))
        });
        const result = await completeResp.json();

        if (!completeResp.ok) {
            throw new Error(result.message || 'Server verification failed.');
        }

        logToTerminal(`[WEBAUTHN] ${method} registered successfully.`);
        return { success: true, message: result.message };

    } catch (err) {
        logToTerminal(`[WEBAUTHN] ERROR: ${err.message}`);
        return { success: false, message: err.message };
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  AUTHENTICATION (Login page)
// ══════════════════════════════════════════════════════════════════════════════

async function loginWithWebAuthn(method, email) {
    logToTerminal(`[WEBAUTHN] Initiating ${method} authentication for ${email}...`);

    try {
        // 1. Get authentication options from server
        const beginResp = await fetch('/webauthn/login/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ method, email })
        });
        const options = await beginResp.json();

        if (!beginResp.ok) {
            throw new Error(options.message || 'Server error during authentication begin.');
        }

        logToTerminal(`[WEBAUTHN] Challenge received. Prompting device authenticator...`);

        // Convert base64url → ArrayBuffer
        const publicKey = decodeCredentialRequestOptions(options);

        // 2. Invoke browser's WebAuthn get()
        let credential;
        try {
            credential = await navigator.credentials.get({ publicKey });
        } catch (err) {
            if (err.name === 'NotSupportedError' || err.name === 'NotAllowedError') {
                if (method === 'face_lock') {
                    logToTerminal('[WEBAUTHN] Face Lock not available. Redirecting to TOTP...');
                    window.location.href = '/verify-2fa?reason=no_camera';
                    return { success: false, redirected: true };
                }
                throw new Error('Passkey authentication was cancelled or not supported.');
            }
            throw err;
        }

        logToTerminal(`[WEBAUTHN] Credential obtained. Verifying with server...`);

        // 3. Send to server
        const completeResp = await fetch('/webauthn/login/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify(encodeCredential(credential))
        });
        const result = await completeResp.json();

        if (!completeResp.ok) {
            throw new Error(result.message || 'Server verification failed.');
        }

        logToTerminal(`[WEBAUTHN] Authentication successful. Redirecting...`);

        // Server tells us where to go next (TOTP or dashboard)
        window.location.href = result.redirect;
        return { success: true };

    } catch (err) {
        logToTerminal(`[WEBAUTHN] ERROR: ${err.message}`);
        return { success: false, message: err.message };
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  UI HELPERS  (used in security.html and login.html)
// ══════════════════════════════════════════════════════════════════════════════

/** Log tactical messages to the terminal-style UI element */
function logToTerminal(msg) {
    const logEl = document.getElementById('webauthn-log');
    if (!logEl) return;
    const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const logLine = document.createElement('div');
    logLine.innerHTML = `<span class="text-neon/40 mr-2">[${time}]</span> ${msg}`;
    logLine.className = 'mb-1';
    logEl.appendChild(logLine);
    logEl.scrollTop = logEl.scrollHeight;
}

/** Show a status banner on the page */
function showWebAuthnStatus(elementId, success, message) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = message;
    
    // Applying Slate Signal Colors
    el.className = 'text-[10px] font-mono mt-4 uppercase tracking-widest font-bold ' + 
        (success ? 'text-emerald-400' : 'text-rose-400');
    
    el.classList.remove('hidden');
    
    // Trigger localized scanner heartbeat on UI state change
    if (typeof triggerScanner === 'function') triggerScanner();
}

/** Disable a button and show a tactical state */
function setButtonLoading(btn, text = 'SYNCING...') {
    if (!btn) return;
    btn.disabled = true;
    btn._originalText = btn.textContent;
    btn.textContent = text;
    gsap.to(btn, { opacity: 0.5, scale: 0.95, duration: 0.2 });
}

function resetButton(btn, text) {
    if (!btn) return;
    btn.disabled = false;
    btn.textContent = text || btn._originalText || 'INITIATE';
    gsap.to(btn, { opacity: 1, scale: 1, duration: 0.4, ease: "elastic.out(1, 0.3)" });
}

/**
 * Higher-level UI Handlers called by the templates
 */

async function handleRegister(method) {
    const btn = event.currentTarget || event.target;
    if (btn.tagName !== 'BUTTON') {
        const parentBtn = btn.closest('button');
        if (parentBtn) btn = parentBtn;
    }

    setButtonLoading(btn);
    logToTerminal(`[SYSTEM] Initializing ${method} handshake protocol...`);

    const result = await registerWebAuthn(method);
    
    if (result.success) {
        logToTerminal(`[SUCCESS] ${result.message}`);
        setTimeout(() => window.location.reload(), 1500);
    } else {
        logToTerminal(`[FAILED] ${result.message}`);
        resetButton(btn);
    }
}

async function handleBiometricLogin(method) {
    const emailInput = document.querySelector('input[name="email"]');
    if (!emailInput || !emailInput.value) {
        logToTerminal(">> UNAUTHORIZED: Identity_ID required for biometric handshake.");
        emailInput.focus();
        return;
    }
    
    const btn = event.currentTarget || event.target;
    setButtonLoading(btn, "VERIFYING...");
    
    const result = await loginWithWebAuthn(method, emailInput.value);
    
    if (!result.success && !result.redirected) {
        logToTerminal(`>> HANDSHAKE_FAILED: ${result.message}`);
        resetButton(btn, "RETRY");
    }
}
