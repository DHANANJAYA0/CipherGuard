/* ═══════════════════════════════════════════
   CipherGuard — Landing Page Scripts
   Particles, animations, terminal demo
   ═══════════════════════════════════════════ */

// ─── Particle Background ────────────────────
class ParticleField {
    constructor(canvas) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.particles = [];
        this.mouse = { x: null, y: null, radius: 150 };
        this.connectionDistance = 120;
        this.particleCount = 80;
        this.animationId = null;

        this.resize();
        this.init();
        this.animate();

        window.addEventListener('resize', () => this.resize());
        window.addEventListener('mousemove', (e) => {
            this.mouse.x = e.clientX;
            this.mouse.y = e.clientY;
        });
        window.addEventListener('mouseout', () => {
            this.mouse.x = null;
            this.mouse.y = null;
        });
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        // Adjust particle count based on screen size
        this.particleCount = Math.floor((this.canvas.width * this.canvas.height) / 18000);
        this.particleCount = Math.min(this.particleCount, 100);
        this.particleCount = Math.max(this.particleCount, 30);
    }

    init() {
        this.particles = [];
        for (let i = 0; i < this.particleCount; i++) {
            this.particles.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                radius: Math.random() * 1.5 + 0.5,
                opacity: Math.random() * 0.5 + 0.1,
                // Random color from palette
                color: this.getRandomColor(),
            });
        }
    }

    getRandomColor() {
        const colors = [
            '79, 143, 255',   // Blue
            '0, 229, 255',    // Cyan
            '168, 85, 247',   // Purple
            '34, 197, 94',    // Green
        ];
        return colors[Math.floor(Math.random() * colors.length)];
    }

    animate() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        this.particles.forEach((p, i) => {
            // Move
            p.x += p.vx;
            p.y += p.vy;

            // Wrap edges
            if (p.x < 0) p.x = this.canvas.width;
            if (p.x > this.canvas.width) p.x = 0;
            if (p.y < 0) p.y = this.canvas.height;
            if (p.y > this.canvas.height) p.y = 0;

            // Mouse interaction - gentle repulsion
            if (this.mouse.x !== null) {
                const dx = p.x - this.mouse.x;
                const dy = p.y - this.mouse.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < this.mouse.radius) {
                    const force = (this.mouse.radius - dist) / this.mouse.radius * 0.02;
                    p.vx += dx * force;
                    p.vy += dy * force;
                }
            }

            // Limit speed
            const speed = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
            if (speed > 1) {
                p.vx = (p.vx / speed) * 1;
                p.vy = (p.vy / speed) * 1;
            }

            // Draw particle
            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            this.ctx.fillStyle = `rgba(${p.color}, ${p.opacity})`;
            this.ctx.fill();

            // Draw connections
            for (let j = i + 1; j < this.particles.length; j++) {
                const p2 = this.particles[j];
                const dx = p.x - p2.x;
                const dy = p.y - p2.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < this.connectionDistance) {
                    const opacity = (1 - dist / this.connectionDistance) * 0.15;
                    this.ctx.beginPath();
                    this.ctx.moveTo(p.x, p.y);
                    this.ctx.lineTo(p2.x, p2.y);
                    this.ctx.strokeStyle = `rgba(79, 143, 255, ${opacity})`;
                    this.ctx.lineWidth = 0.5;
                    this.ctx.stroke();
                }
            }
        });

        this.animationId = requestAnimationFrame(() => this.animate());
    }
}


// ─── Terminal Typing Animation ──────────────
class TerminalAnimation {
    constructor() {
        this.lines = [
            { id: 'termLine1', textId: 'termText1', text: 'cat keylogger_output.txt', isTyping: true },
            { id: 'termLine2', delay: 400 },
            { id: 'termLine3', delay: 200 },
            { id: 'termLine4', delay: 1000 },
            { id: 'termLine5', delay: 200 },
            { id: 'termLine6', delay: 600 },
        ];
        this.hasPlayed = false;
    }

    async play() {
        if (this.hasPlayed) return;
        this.hasPlayed = true;

        // Type the command
        const line1 = this.lines[0];
        const textEl = document.getElementById(line1.textId);
        if (!textEl) return;

        for (let i = 0; i < line1.text.length; i++) {
            textEl.textContent += line1.text[i];
            await this.wait(40 + Math.random() * 40);
        }

        // Remove cursor after typing
        textEl.classList.remove('typing');
        await this.wait(300);

        // Reveal remaining lines
        for (let i = 1; i < this.lines.length; i++) {
            const line = this.lines[i];
            const el = document.getElementById(line.id);
            if (!el) continue;

            await this.wait(line.delay || 200);
            el.classList.remove('hidden');
            el.style.opacity = '0';
            el.style.transform = 'translateY(8px)';
            requestAnimationFrame(() => {
                el.style.transition = 'opacity 0.3s, transform 0.3s';
                el.style.opacity = '1';
                el.style.transform = 'translateY(0)';
            });
        }
    }

    wait(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}


// ─── Scrambled Text Animation (Module Demo) ─
class ScrambleAnimator {
    constructor(elementId) {
        this.el = document.getElementById(elementId);
        if (!this.el) return;
        this.originalText = this.el.textContent;
        this.chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
        this.interval = null;
        this.hasPlayed = false;
    }

    play() {
        if (!this.el || this.hasPlayed) return;
        this.hasPlayed = true;

        let iterations = 0;
        const maxIterations = 15;

        this.interval = setInterval(() => {
            this.el.textContent = this.originalText
                .split('')
                .map((char, idx) => {
                    if (idx < iterations) return this.originalText[idx];
                    return this.chars[Math.floor(Math.random() * this.chars.length)];
                })
                .join('');

            iterations += 1 / 2;

            if (iterations >= this.originalText.length) {
                clearInterval(this.interval);
                this.el.textContent = this.originalText;
            }
        }, 50);
    }
}


// ─── Scroll Animations (Intersection Observer) ─
class ScrollAnimator {
    constructor() {
        this.observer = new IntersectionObserver(
            (entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const delay = parseInt(entry.target.dataset.delay || 0);
                        setTimeout(() => {
                            entry.target.classList.add('visible');
                        }, delay);
                        this.observer.unobserve(entry.target);
                    }
                });
            },
            { threshold: 0.15, rootMargin: '0px 0px -40px 0px' }
        );

        document.querySelectorAll('[data-animate]').forEach(el => {
            this.observer.observe(el);
        });
    }
}


// ─── Navbar Scroll Effect ───────────────────
class NavbarController {
    constructor() {
        this.navbar = document.getElementById('navbar');
        this.toggle = document.getElementById('navToggle');
        this.links = document.getElementById('navLinks');
        this.isOpen = false;

        window.addEventListener('scroll', () => this.onScroll());
        if (this.toggle) {
            this.toggle.addEventListener('click', () => this.toggleMenu());
        }

        // Close menu on link click
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                if (this.isOpen) this.toggleMenu();
            });
        });
    }

    onScroll() {
        if (window.scrollY > 60) {
            this.navbar.classList.add('scrolled');
        } else {
            this.navbar.classList.remove('scrolled');
        }
    }

    toggleMenu() {
        this.isOpen = !this.isOpen;
        this.links.classList.toggle('open', this.isOpen);
        this.toggle.classList.toggle('open', this.isOpen);
        document.body.style.overflow = this.isOpen ? 'hidden' : '';
    }
}


// ─── Smooth Counter Animation ───────────────
class CounterAnimator {
    constructor() {
        this.observed = false;
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting && !this.observed) {
                    this.observed = true;
                    this.animateCounters();
                    observer.disconnect();
                }
            });
        }, { threshold: 0.5 });

        const statsSection = document.querySelector('.hero-stats');
        if (statsSection) observer.observe(statsSection);
    }

    animateCounters() {
        document.querySelectorAll('[data-count]').forEach(el => {
            const target = parseInt(el.dataset.count);
            const duration = 1500;
            const start = performance.now();

            const update = (now) => {
                const elapsed = now - start;
                const progress = Math.min(elapsed / duration, 1);
                // Ease out cubic
                const eased = 1 - Math.pow(1 - progress, 3);
                const current = Math.round(eased * target);
                el.textContent = current;

                if (progress < 1) {
                    requestAnimationFrame(update);
                }
            };

            requestAnimationFrame(update);
        });
    }
}


// ─── Copy Install Command ───────────────────
function copyInstallCmd() {
    const commands = `git clone https://github.com/DHANANJAYA0/CipherGuard.git
cd CipherGuard
pip install -r requirements.txt
python main.py`;

    navigator.clipboard.writeText(commands).then(() => {
        const btn = document.querySelector('.copy-btn');
        const originalHTML = btn.innerHTML;
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!`;
        btn.style.color = '#22c55e';
        btn.style.borderColor = 'rgba(34, 197, 94, 0.3)';

        setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.style.color = '';
            btn.style.borderColor = '';
        }, 2000);
    }).catch(() => {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = commands;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    });
}


// ─── Download Button Handler ────────────────
function setupDownloadButton() {
    const btn = document.getElementById('downloadBtn');
    if (!btn) return;

    btn.addEventListener('click', (e) => {
        e.preventDefault();

        // ═══════════════════════════════════════════════
        // 🔧 CONFIGURE YOUR DOWNLOAD LINK HERE
        // Replace this URL with your actual download link:
        //   - GitHub Releases: https://github.com/YOUR-USERNAME/CipherGuard/releases/latest
        //   - Google Drive link
        //   - Any direct download URL
        // ═══════════════════════════════════════════════
        const downloadUrl = 'CipherGuard-v1.0.0.zip';

        // Show a brief download animation
        const originalHTML = btn.innerHTML;
        btn.innerHTML = `
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="spin"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
            Preparing Download...
        `;
        btn.style.pointerEvents = 'none';

        setTimeout(() => {
            // Trigger direct download
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = 'CipherGuard-v1.0.0.zip';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            btn.innerHTML = `
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                Download Started!
            `;

            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.style.pointerEvents = '';
            }, 2500);
        }, 1000);
    });
}


// ─── Initialize Everything ──────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Particles
    const canvas = document.getElementById('particle-canvas');
    if (canvas) new ParticleField(canvas);

    // Navbar
    new NavbarController();

    // Scroll animations
    new ScrollAnimator();

    // Counter animation
    new CounterAnimator();

    // Terminal animation — trigger when hero terminal is visible
    const terminal = document.querySelector('.hero-terminal');
    const terminalAnim = new TerminalAnimation();
    if (terminal) {
        const termObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    setTimeout(() => terminalAnim.play(), 800);
                    termObserver.disconnect();
                }
            });
        }, { threshold: 0.3 });
        termObserver.observe(terminal);
    }

    // Scramble animation for module demo
    const scrambleAnim = new ScrambleAnimator('scrambledDemo');
    const moduleSection = document.getElementById('modules');
    if (moduleSection && scrambleAnim.el) {
        const scrambleObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    setTimeout(() => scrambleAnim.play(), 500);
                    scrambleObserver.disconnect();
                }
            });
        }, { threshold: 0.2 });
        scrambleObserver.observe(moduleSection);
    }

    // Download button
    setupDownloadButton();

    // Add spin animation for download button
    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .spin { animation: spin 1s linear infinite; }
    `;
    document.head.appendChild(style);
});
