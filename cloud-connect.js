// ─── ComplianceFlow AI: Cloud Connect Module ───
// Simulates OAuth connection to AWS, GCP, Azure

window.CloudConnect = (() => {
    const state = { providers: {} };

    const STEPS = [
        'Initiating OAuth 2.0 handshake...',
        'Redirecting to provider IAM console...',
        'Validating permissions scope (read/write)...',
        'Exchanging authorization code for token...',
        'Syncing resource inventory metadata...',
        'Connection established.'
    ];

    function init() {
        document.querySelectorAll('.provider-card').forEach(card => {
            card.addEventListener('click', () => {
                const provider = card.dataset.provider;
                if (state.providers[provider]) return; // already connected
                connect(provider, card);
            });
        });
    }

    function connect(provider, card) {
        if (state.providers[provider]) return;

        card.classList.add('selected');
        const statusEl = document.getElementById('status-' + provider);
        const barEl = document.getElementById('bar-' + provider);
        const stepsContainer = document.getElementById('connect-steps');

        statusEl.textContent = 'Connecting...';
        statusEl.className = 'status-line connecting';

        // Build steps UI
        stepsContainer.innerHTML = '<h4 style="margin-bottom:0.75rem; font-size:0.9rem;">Connection Progress</h4>';
        const stepEls = STEPS.map((text, i) => {
            const div = document.createElement('div');
            div.className = 'step-item';
            div.innerHTML = `<span class="check">○</span> ${text}`;
            stepsContainer.appendChild(div);
            return div;
        });

        // Emit to terminal
        LiveTerminal.log('system', `Initiating connection to ${provider.toUpperCase()}...`);

        let stepIndex = 0;
        const interval = setInterval(() => {
            if (stepIndex < STEPS.length) {
                // Mark previous as done
                if (stepIndex > 0) {
                    stepEls[stepIndex - 1].classList.remove('active');
                    stepEls[stepIndex - 1].classList.add('done');
                    stepEls[stepIndex - 1].querySelector('.check').textContent = '✓';
                }
                stepEls[stepIndex].classList.add('active');
                stepEls[stepIndex].querySelector('.check').innerHTML = '<span class="spinner"></span>';

                const pct = Math.round(((stepIndex + 1) / STEPS.length) * 100);
                barEl.style.width = pct + '%';

                LiveTerminal.log('agent', STEPS[stepIndex]);
                stepIndex++;
            } else {
                clearInterval(interval);

                // Mark final step done
                stepEls[STEPS.length - 1].classList.remove('active');
                stepEls[STEPS.length - 1].classList.add('done');
                stepEls[STEPS.length - 1].querySelector('.check').textContent = '✓';

                barEl.style.width = '100%';
                statusEl.textContent = '✓ Connected';
                statusEl.className = 'status-line connected';
                card.classList.remove('selected');
                card.classList.add('connected');

                state.providers[provider] = true;
                LiveTerminal.log('output', `${provider.toUpperCase()} connected successfully. Resources synced.`);

                updateChips();
            }
        }, 700);
    }

    function updateChips() {
        const container = document.getElementById('connection-chips');
        container.innerHTML = '';
        Object.keys(state.providers).forEach(p => {
            const chip = document.createElement('div');
            chip.className = 'conn-chip';
            chip.innerHTML = `<span class="dot"></span> ${p.toUpperCase()}`;
            container.appendChild(chip);
        });
    }

    function isConnected() {
        return Object.keys(state.providers).length > 0;
    }

    function getProviders() {
        return Object.keys(state.providers);
    }

    return { init, isConnected, getProviders };
})();

document.addEventListener('DOMContentLoaded', CloudConnect.init);
