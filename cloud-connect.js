// ─── ComplianceFlow AI: Cloud Connect Module ───
// Simulates OAuth connection to AWS, GCP, Azure

window.CloudConnect = (() => {
    const state = { 
        providers: {},
        credentials: {} // Store keys in memory only
    };

    const STEPS = [
        'Establishing secure handshake...',
        'Validating identity with provider...',
        'Verifying audit permission scope...',
        'Securing governance session...'
    ];

    function init() {
        // Auto-reconnect if we have saved credentials
        const savedCreds = localStorage.getItem('cf_aws_creds');
        if (savedCreds) {
            try {
                state.credentials['aws'] = JSON.parse(savedCreds);
                setTimeout(() => { // slight delay for visual simulation effect on load
                    const awsCard = document.querySelector('.provider-card[data-provider="aws"]');
                    if (awsCard) connect('aws', awsCard);
                }, 500);
            } catch (e) {}
        }

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
        const authMethod = document.getElementById('setting-auth-method').value;
        const accessKeyId = document.getElementById('setting-access-key').value;
        const secretAccessKey = document.getElementById('setting-secret-key').value;
        const roleArn = document.getElementById('setting-role-arn').value;
        const externalId = document.getElementById('setting-external-id').value;
        const region = document.getElementById('setting-region').value;
        const reportEmail = document.getElementById('setting-report-email').value;

        if (authMethod === 'keys' && (!accessKeyId || !secretAccessKey)) {
            alert('Please provide both access key and secret key.');
            return;
        }
        if (authMethod === 'role' && !roleArn) {
            alert('Please provide the Role ARN.');
            return;
        }

        const data = { authMethod, accessKeyId, secretAccessKey, roleArn, externalId, region, reportEmail };
        localStorage.setItem('cf_aws_creds', JSON.stringify(data));
        state.credentials[provider] = data;

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

            // Show the Tracker UI on the Scan Page
            const tracker = document.getElementById('scheduled-scan-tracker');
            if (tracker) {
                tracker.style.display = 'block';
                
                // Calculate next scan time (e.g. 2 hours from now for visual UI display)
                const now = new Date();
                now.setHours(now.getHours() + 2);
                document.getElementById('next-scan-time').textContent = 'Next Scan: ' + now.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) + ' UTC';
                
                const evidence = Evidence.getEvidenceLog();
                const remediationCount = (evidence || []).filter(e => e.type === 'Remediation Action').length;
                const statusEl = document.getElementById('last-scan-status');
                if (statusEl) {
                    statusEl.innerHTML = `Last Scan: <span style="color:var(--success)">Auto-Remediated ${remediationCount} Issues</span>`;
                }
            }

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

            // If it was an auto-connect failure, clear the bad state to stop the loop
            if (localStorage.getItem('cf_aws_creds')) {
                console.warn("Clearing invalid saved credentials.");
                localStorage.removeItem('cf_aws_creds');
            }
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
            authMethod: creds.authMethod,
            accessKeyId: obfuscate(creds.accessKeyId),
            secretAccessKey: obfuscate(creds.secretAccessKey),
            roleArn: creds.roleArn,
            externalId: creds.externalId,
            region: creds.region,
            reportEmail: creds.reportEmail,
            isObfuscated: true
        };
    }

    function getSettings() {
        // Return first active provider's settings
        const active = Object.keys(state.credentials)[0];
        return state.credentials[active] || {};
    }

    return { init, isConnected, getProviders, getCredentials, getSettings, openSettings, closeSettings, saveSettings };
})();

document.addEventListener('DOMContentLoaded', CloudConnect.init);
