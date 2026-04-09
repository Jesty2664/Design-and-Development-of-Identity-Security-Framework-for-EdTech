/**
 * MAGIC.JS - Kinetic Feedback and High-Fidelity Physics Engine
 * Powered by GSAP
 */

// --- AI TUTOR: ORION LOGIC (OFFLINE ENGINE) ---
function toggleTutor() {
    const drawer = document.getElementById('ai-tutor-drawer');
    drawer.classList.toggle('translate-x-full');
}

function appendMessage(sender, text) {
    const log = document.getElementById('orion-log');
    const msg = document.createElement('div');
    msg.className = `cyber-glass p-4 ${sender === 'ORION' ? 'border-cyber-indigo/20' : 'border-white/5 bg-white/2 ml-8'}`;
    
    msg.innerHTML = `
        <p class="text-[11px] font-academic text-white/80 leading-relaxed">
            <span class="${sender === 'ORION' ? 'text-cyber-indigo' : 'text-cyber-violet'} font-bold mr-2">[${sender}]</span> ${text}
        </p>
    `;
    
    log.appendChild(msg);
    log.scrollTop = log.scrollHeight;
}

function sendToOrion(query) {
    if (!query) return;

    appendMessage('USER', query);

    // Simulated "Processing" Delay
    setTimeout(() => {
        const response = generateOrionResponse(query.toLowerCase());
        appendMessage('ORION', response);
    }, 600 + Math.random() * 600);
}

function generateOrionResponse(query) {
    if (query.includes('security') || query.includes('passkey')) {
        return "Security protocols are currently at level 'Solar-Frost 5.0'. I recommend synchronizing your Physical Passkey to eliminate traditional password vulnerabilities.";
    }
    if (query.includes('quantum') || query.includes('class')) {
        return "Your Quantum Physics module is scheduled for 12:00 AM. Dr. Nexus has uploaded new holograms regarding entanglement in the Course Preview section.";
    }
    if (query.includes('hello') || query.includes('hi')) {
        return "Greetings, Operative. My neural nodes are fully synchronized. How can I facilitate your learning pathway today?";
    }
    if (query.includes('progress') || query.includes('grade')) {
        return "Current academic mastery is at 70%. You have 2 pending deadlines in the Tactical Queue. Focus on Neural Net Lab for maximum growth metrics.";
    }
    if (query.includes('system') || query.includes('audit')) {
        return "System Audit Protocol Alpha engaged. All core nodes are operational. Network integrity at 99.9%. No unauthorized lateral movement detected within the mesh.";
    }
    if (query.includes('threat') || query.includes('active')) {
        return "Global IPS is monitoring 7 unique vectors. 1 recent IP ban recorded. Suggest upgrading WAF signatures in the Command Center.";
    }
    if (query.includes('identity')) {
        return "The Identity framework binding is active. All session tokens are encrypted under the Cyber-Glass protocol layer.";
    }
    if (query.includes('class') || query.includes('student')) {
        return "Class alpha-cohort shows steady interaction. 3 nodes currently flagged for attendance anomalies.";
    }
    return "I am currently scanning the library for more data on that query. Is there a specific educational or security protocol you wish to discuss?";
}

function openClearanceModal(type) {
    // Close Orion Drawer
    document.getElementById('ai-tutor-drawer').classList.add('translate-x-full');
    
    const modal = document.getElementById('clearance-modal');
    const content = document.getElementById('clearance-modal-content');
    const roleGroup = document.getElementById('clearance-role-group');
    const title = document.getElementById('clearance-title');
    const idLabel = document.getElementById('clearance-id-label');
    const typeInput = document.getElementById('clearance-type');
    
    // Setup View based on type
    typeInput.value = type;
    if (type === 'ip') {
        title.innerText = 'IP_Quarantine_Release';
        idLabel.innerText = 'Quarantined_Node_IP';
        roleGroup.style.display = 'none';
        
        // Auto-fill IP if possible or leave empty for user to type
        document.getElementById('clearance-identifier').placeholder = "Enter your IP Address...";
        
        content.classList.replace('border-cyber-indigo', 'border-rose-500');
        title.classList.replace('text-white', 'text-rose-500');
    } else {
        title.innerText = 'Identity_Whitelist_Req';
        idLabel.innerText = 'Target_Identifier (Email/Campus_ID)';
        roleGroup.style.display = 'block';
        
        content.classList.replace('border-rose-500', 'border-cyber-indigo');
        title.classList.replace('text-rose-500', 'text-white');
    }
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
    
    // Animate in
    setTimeout(() => {
        modal.classList.remove('opacity-0');
        content.classList.remove('scale-95');
    }, 10);
}

function closeClearanceModal() {
    const modal = document.getElementById('clearance-modal');
    const content = document.getElementById('clearance-modal-content');
    
    modal.classList.add('opacity-0');
    content.classList.add('scale-95');
    
    setTimeout(() => {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }, 300);
}

document.addEventListener('DOMContentLoaded', () => {
    initMagneticButtons();
    initScrollReveal();
    initParallax();
    initParticleEngine();
    initTactileFeedback();
});

/**
 * MAGNETIC PULL
 * Buttons lean toward the cursor when approached.
 */
function initMagneticButtons() {
    const magneticBtns = document.querySelectorAll('.btn-magnetic, .magic-press');
    
    magneticBtns.forEach(btn => {
        btn.addEventListener('mousemove', (e) => {
            const rect = btn.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;
            
            gsap.to(btn, {
                x: x * 0.3,
                y: y * 0.3,
                duration: 0.5,
                ease: "power2.out"
            });
        });
        
        btn.addEventListener('mouseleave', () => {
            gsap.to(btn, {
                x: 0,
                y: 0,
                duration: 0.5,
                ease: "elastic.out(1, 0.3)"
            });
        });
    });
}

/**
 * REVEAL ON SCROLL
 * Slide + Fade + Blur observers.
 */
function initScrollReveal() {
    const revealElements = document.querySelectorAll('.reveal-on-scroll');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                gsap.to(entry.target, {
                    opacity: 1,
                    filter: "blur(0px)",
                    y: 0,
                    duration: 1.2,
                    ease: "power3.out"
                });
            }
        });
    }, { threshold: 0.1 });
    
    revealElements.forEach(el => observer.observe(el));
}

/**
 * PARALLAX LAYERING
 * Level 1 Background dots and Level 3 Floating particles.
 */
function initParallax() {
    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        
        // Background dots move slow
        const gridDots = document.getElementById('grid-dots');
        if (gridDots) {
            gridDots.style.transform = `translateY(${scrolled * 0.2}px)`;
        }
        
        // Floating dust particles move fast
        const dust = document.getElementById('floating-dust');
        if (dust) {
            dust.style.transform = `translateY(-${scrolled * 0.5}px)`;
        }
    });
}

/**
 * TACTILE FEEDBACK
 * Scale down on click and Glow flash.
 */
function initTactileFeedback() {
    document.addEventListener('mousedown', (e) => {
        const target = e.target.closest('.magic-press, .btn-magnetic');
        if (target) {
            gsap.to(target, { scale: 0.96, duration: 0.15 });
            target.classList.add('glow-flash-active');
        }
    });
    
    document.addEventListener('mouseup', (e) => {
        const target = e.target.closest('.magic-press, .btn-magnetic');
        if (target) {
            gsap.to(target, { scale: 1, duration: 0.4, ease: "elastic.out(1, 0.3)" });
            setTimeout(() => target.classList.remove('glow-flash-active'), 150);
        }
    });
}

/**
 * PARTICLE ENGINE (Canvas Dust)
 * High-performance background particles.
 */
function initParticleEngine() {
    const canvas = document.getElementById('particle-canvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const particles = [];
    for (let i = 0; i < 60; i++) {
        particles.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            size: Math.random() * 2,
            speed: Math.random() * 0.5 + 0.1,
            opacity: Math.random()
        });
    }
    
    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "rgba(99, 102, 241, 0.4)";
        
        particles.forEach(p => {
            p.y -= p.speed;
            if (p.y < 0) p.y = canvas.height;
            
            ctx.globalAlpha = p.opacity;
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            ctx.fill();
        });
        
        requestAnimationFrame(animate);
    }
    animate();
}

/**
 * NEURAL SEARCH OVERLAY
 * Toggle blur and visibility.
 */
function toggleNeuralSearch() {
    const overlay = document.getElementById('neural-search-overlay');
    if (!overlay) return;
    
    overlay.classList.toggle('active');
    if (overlay.classList.contains('active')) {
        document.getElementById('search-input-neural').focus();
    }
}
