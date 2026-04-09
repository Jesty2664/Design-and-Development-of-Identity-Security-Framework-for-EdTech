/**
 * LUMINA.JS - Solar-Frost Aesthetic Micro-Interactions
 * Integrated into IDENTITY.SENTINEL
 */

document.addEventListener('DOMContentLoaded', () => {
    initSonarRipples();
    initNexusAnimations();
});

/**
 * Implements the "Auth-Pulse" sonar ripple effect on buttons.
 */
function initSonarRipples() {
    document.querySelectorAll('.btn-solar, .btn-neon').forEach(button => {
        button.addEventListener('click', function(e) {
            // Create the ripple element
            const ripple = document.createElement('div');
            ripple.classList.add('auth-pulse');
            
            // Positioning within the button (or relative to parent panel)
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            
            ripple.style.width = ripple.style.height = `${size}px`;
            ripple.style.left = `${e.clientX - rect.left - size/2}px`;
            ripple.style.top = `${e.clientY - rect.top - size/2}px`;
            
            this.appendChild(ripple);
            
            // Cleanup
            setTimeout(() => {
                ripple.remove();
            }, 800);
        });
    });
}

/**
 * Handles nexus-specific animations and hover behaviors.
 */
function initNexusAnimations() {
    // Reveal scanlines on nexus hover
    const nexusPanels = document.querySelectorAll('.frost-panel');
    
    nexusPanels.forEach(panel => {
        panel.addEventListener('mouseenter', () => {
            const scanner = panel.querySelector('.nexus-scanner');
            if (scanner) {
                scanner.style.animationPlayState = 'running';
            }
        });
    });
}

/**
 * Toggles password visibility for a given input ID.
 */
function togglePassword(inputId, button) {
    const input = document.getElementById(inputId);
    if (!input) return;
    
    if (input.type === 'password') {
        input.type = 'text';
        button.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.88 9.88 3.59 3.59"/><path d="M21 21l-6.39-6.39"/><path d="M2 12s3-7 10-7a9.91 9.91 0 0 1 5 1.39"/><path d="M5.66 5.66A9.9 9.9 0 0 0 2 12c0 0 3 7 10 7a9.93 9.93 0 0 0 5-1.39"/><path d="M10.78 10.78a3 3 0 1 0 4.22 4.22"/><circle cx="12" cy="12" r="3" class="opacity-0"/></svg>
        `;
    } else {
        input.type = 'password';
        button.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        `;
    }
}
