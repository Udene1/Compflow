// ─── ComplianceFlow AI: Cloud Connect Module ───
// Simulates OAuth connection to AWS, GCP, Azure

window.CloudConnect = (() => {
    const state = { 
        providers: {},
        credentials: {} // Store keys in memory only
    };

    const STEPS = [
        'Initiating hand-off to cloud agent...',
        'Validating API keys with provider...',
        'Checking IAM permission scope (ReadOnlyAccess)...',
        'Verifying S3/EC2 enumeration capabilities...',
        'Establishing secure session...',
        'Cloud environment connected.'
    ];

    function init() {
        document.querySelectorAll('.provider-card').forEach(card => {
            card.addEventListener('click', () => {
                const provider = card.dataset.provider;
                if (state.providers[provider]) return; // already connected
                
                // If no creds, open settings first
                if (!state.credentials[provider]) {
                    openSettings(provider);
                    return;
                }

                connect(provider, card);
            });
        });
    }

    function openSettings(provider = 'aws') {
        const modal = document.getElementById('modal-settings');
        const providerSelect = document.getElementById('setting-provider');
        if (providerSelect) providerSelect.value = provider;
        modal.classList.add('active');
    }

    function closeSettings() {
        document.getElementById('modal-settings').classList.remove('active');
    }

    function saveSettings() {
        const provider = document.getElementById('setting-provider').value;
        const accessKey = document.getElementById('setting-access-key').value;
        const secretKey = document.getElementById('setting-secret-key').value;
        const region = document.getElementById('setting-region').value;

        if (!accessKey || !secretKey) {
            alert('Please provide both access key and secret key.');
            return;
        }

        state.credentials[provider] = {
            accessKeyId: accessKey,
            secretAccessKey: secretKey,
            region: region
        };

        closeSettings();
        LiveTerminal.log('system', `Credentials saved for ${provider.toUpperCase()}. Ready to connect.`);
        
        // Find the card and trigger connect
        const card = document.querySelector(`.provider-card[data-provider="${provider}"]`);
        if (card) connect(provider, card);
    }

    async function connect(provider, card) {
        if (state.providers[provider]) return;

        card.classList.add('selected');
        const statusEl = document.getElementById('status-' + provider);
        const barEl = document.getElementById('bar-' + provider);
        const stepsContainer = document.getElementById('connect-steps');

        statusEl.textContent = 'Connecting...';
        statusEl.className = 'status-line connecting';

        // Build steps UI (still useful for UX, but now driven by progress)
        stepsContainer.innerHTML = '<h4 style="margin-bottom:0.75rem; font-size:0.9rem;">Connection Progress</h4>';
        const stepEls = STEPS.map((text, i) => {
            const div = document.createElement('div');
            div.className = 'step-item';
            div.innerHTML = `<span class="check">○</span> ${text}`;
            stepsContainer.appendChild(div);
            return div;
        });

        LiveTerminal.log('system', `Initiating real connection to ${provider.toUpperCase()}...`);

        try {
            // Update UI to first step
            updateStepUI(0, stepEls, barEl);
            LiveTerminal.log('agent', STEPS[0]);

            const response = await fetch(`/api/validate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    provider, 
                    credentials: state.credentials[provider] 
                })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || "Connection failed");
            }

            // Success Path - Fast-forward UI steps
            for (let i = 1; i < STEPS.length; i++) {
                await new Promise(r => setTimeout(r, 400));
                updateStepUI(i, stepEls, barEl);
                LiveTerminal.log('agent', STEPS[i]);
            }

            barEl.style.width = '100%';
            statusEl.textContent = '✓ Connected';
            statusEl.className = 'status-line connected';
            card.classList.remove('selected');
            card.classList.add('connected');

            state.providers[provider] = true;
            LiveTerminal.log('output', `${provider.toUpperCase()} Identity Verified: ${data.identity || 'Session Active'}`);
            LiveTerminal.log('insight', `SUCCESS: Cloud environment connected and validated in real-time.`);

            updateChips();

        } catch (err) {
            console.error("Connection failed:", err);
            statusEl.textContent = '✕ Failed';
            statusEl.className = 'status-line failed';
            card.classList.remove('selected');
            
            // Mark current step as failed
            const currentStep = stepEls.find(el => el.classList.contains('active')) || stepEls[0];
            currentStep.classList.remove('active');
            currentStep.classList.add('error');
            currentStep.querySelector('.check').textContent = '✕';
            
            LiveTerminal.log('insight', `CONNECTION ERROR: ${err.message}`);
            showToast(`Connection failed: ${err.message}`);
        }
    }

    function updateStepUI(index, stepEls, barEl) {
        // Mark previous as done
        for (let i = 0; i < index; i++) {
            stepEls[i].classList.remove('active');
            stepEls[i].classList.add('done');
            stepEls[i].querySelector('.check').textContent = '✓';
        }
        
        stepEls[index].classList.add('active');
        stepEls[index].querySelector('.check').innerHTML = '<span class="spinner"></span>';

        const pct = Math.round(((index + 1) / STEPS.length) * 100);
        barEl.style.width = pct + '%';
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

    const XOR_KEY = 'CompFlow_Guard_2026';

    function obfuscate(str) {
        if (!str) return '';
        // Simple XOR + Base64 to prevent plain-text sniffing
        let out = "";
        for (let i = 0; i < str.length; i++) {
            out += String.fromCharCode(str.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
        }
        return btoa(out);
    }

    function getCredentials(provider) {
        const creds = state.credentials[provider];
        if (!creds) return null;
        
        // Return obfuscated creds for secure transit
        return {
            accessKeyId: obfuscate(creds.accessKeyId),
            secretAccessKey: obfuscate(creds.secretAccessKey),
            region: creds.region, // non-sensitive
            isObfuscated: true
        };
    }

    return { init, isConnected, getProviders, getCredentials, openSettings, closeSettings, saveSettings };
})();

document.addEventListener('DOMContentLoaded', CloudConnect.init);
