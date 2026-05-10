// ================================================================
// ComplianceFlow AI — Landing Page Interactions
// ================================================================

// --- Terminal Demo ---
const terminal = document.getElementById('terminal-output');
const runBtn = document.getElementById('run-autopilot');
const statusIndicator = document.querySelector('.status-indicator');

const logs = [
    { text: "$ complianceflow audit --client acme-corp --mode autonomous", color: "#94a3b8", delay: 600 },
    { text: "[System] Establishing secure STS session → arn:aws:iam::***:role/ComplianceFlowAudit", color: "#818cf8", delay: 500 },
    { text: "[System] Connected to AWS Infrastructure (us-east-1, eu-west-1)", color: "#818cf8", delay: 400 },
    { text: "", color: "", delay: 200 },
    { text: "[Scanner] Executing deep cloud scan across 104 controls...", color: "#22d3ee", delay: 800 },
    { text: "[Scanner] ▸ IAM: 12 checks | Network: 8 checks | Storage: 16 checks", color: "#22d3ee", delay: 400 },
    { text: "[Scanner] ▸ Monitoring: 6 checks | Compute: 12 checks | Edge: 11 checks", color: "#22d3ee", delay: 400 },
    { text: "", color: "", delay: 200 },
    { text: "[Finding] ✗ CRITICAL — S3 bucket 'finance-records' has public access enabled", color: "#ef4444", delay: 700 },
    { text: "[Gemini] Evaluating blast radius... safetyScore: 0.95 → AUTO_FIX", color: "#c084fc", delay: 600 },
    { text: "[Agent]  ⚡ Remediated: S3 PublicAccessBlock enforced on 'finance-records'", color: "#22c55e", delay: 500 },
    { text: "", color: "", delay: 200 },
    { text: "[Finding] ✗ HIGH — CloudTrail multi-region logging disabled", color: "#f59e0b", delay: 600 },
    { text: "[Gemini] Evaluating blast radius... safetyScore: 0.92 → AUTO_FIX", color: "#c084fc", delay: 500 },
    { text: "[Agent]  ⚡ Remediated: Multi-region trail enabled with log integrity", color: "#22c55e", delay: 400 },
    { text: "", color: "", delay: 200 },
    { text: "[Finding] ✗ HIGH — 3 IAM users have MFA disabled", color: "#f59e0b", delay: 600 },
    { text: "[Gemini] Evaluating blast radius... safetyScore: 0.45 → ESCALATE", color: "#c084fc", delay: 500 },
    { text: "[Agent]  ⏸ Escalated to CISO — requires user coordination for MFA enrollment", color: "#f59e0b", delay: 400 },
    { text: "", color: "", delay: 200 },
    { text: "[Evidence] Generating SHA-256 signed evidence for SOC2 CC6.1, CC6.7, CC7.2...", color: "#818cf8", delay: 600 },
    { text: "[Evidence] Mapping to HIPAA §164.312(a)(1) and GDPR Art. 32...", color: "#818cf8", delay: 400 },
    { text: "", color: "", delay: 200 },
    { text: "[Report] ──────────────────────────────────────────", color: "#64748b", delay: 300 },
    { text: "[Report] Autonomous Remediation Summary", color: "#f1f5f9", delay: 300 },
    { text: "[Report] ▸ 97 controls passed  |  5 auto-fixed  |  2 escalated", color: "#22c55e", delay: 400 },
    { text: "[Report] ▸ Compliance posture: 99.1% — AUDIT READY", color: "#22d3ee", delay: 400 },
    { text: "[Report] ──────────────────────────────────────────", color: "#64748b", delay: 300 },
    { text: "[System] Weekly report emailed to leadership@acme.com", color: "#818cf8", delay: 400 },
    { text: "[System] ✓ Audit cycle complete. Agent sleeping until next cron.", color: "#22c55e", delay: 500 },
];

function typewriteLine(container, text, color, speed = 18) {
    return new Promise(resolve => {
        if (!text) {
            const spacer = document.createElement('div');
            spacer.style.height = '0.3rem';
            container.appendChild(spacer);
            resolve();
            return;
        }
        const line = document.createElement('div');
        line.className = 'line';
        line.style.color = color;
        line.style.opacity = '1';
        line.style.transform = 'none';
        line.style.animation = 'none';
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;

        let i = 0;
        const interval = setInterval(() => {
            line.textContent = text.slice(0, ++i);
            container.scrollTop = container.scrollHeight;
            if (i >= text.length) {
                clearInterval(interval);
                resolve();
            }
        }, speed);
    });
}

async function runDemo() {
    runBtn.disabled = true;
    runBtn.textContent = "Agent Running...";
    statusIndicator.innerHTML = '<span class="pulse" style="background:#f59e0b;box-shadow:0 0 10px #f59e0b"></span> Scanning...';
    terminal.innerHTML = '';

    for (const log of logs) {
        await typewriteLine(terminal, log.text, log.color);
        await new Promise(r => setTimeout(r, log.delay));
    }

    statusIndicator.innerHTML = '<span class="pulse"></span> Audit Complete';
    runBtn.disabled = false;
    runBtn.textContent = '▶ Run AI Autopilot';
}

runBtn.addEventListener('click', runDemo);

// --- Scroll Reveal ---
const revealElements = document.querySelectorAll('.reveal');
const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            revealObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.15, rootMargin: '0px 0px -60px 0px' });

revealElements.forEach(el => revealObserver.observe(el));

// --- Animated Counters ---
const counterElements = document.querySelectorAll('.metric-value[data-target]');
const counterObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            animateCounter(entry.target);
            counterObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.5 });

counterElements.forEach(el => counterObserver.observe(el));

function animateCounter(el) {
    const target = parseInt(el.dataset.target);
    const prefix = el.dataset.prefix || '';
    const suffix = el.dataset.suffix || '';
    const duration = 1800;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(eased * target);
        el.textContent = prefix + current + suffix;
        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

// --- Nav Scroll Effect ---
const nav = document.getElementById('main-nav');
window.addEventListener('scroll', () => {
    nav.classList.toggle('scrolled', window.scrollY > 50);
}, { passive: true });
