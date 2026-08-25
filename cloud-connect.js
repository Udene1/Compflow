// ─── ComplianceFlow AI: Cloud Connect & Onboarding Module ───
// Server-side tenant integration (Zero localStorage secrets, AssumeRole-first)

window.CloudConnect = (() => {
    const state = { 
        providers: {},
        activeTenant: null,
        credentials: {} // In-memory runtime session only (NEVER in localStorage)
    };

    const STEPS = [
        'Establishing secure handshake...',
        'Validating AssumeRole trust policy...',
        'Verifying read-only security audit permissions...',
        'Registering cloud environment in registry...'
    ];

    function init() {
        // Purge any legacy localStorage credentials for security compliance
        ['aws', 'azure', 'gcp', 'hetzner', 'digitalocean'].forEach(p => {
            localStorage.removeItem(`cf_creds_${p}`);
        });
        localStorage.removeItem('cf_aws_creds');

        // Check if server already has tenants for this org
        checkExistingConnections();
    }

    async function checkExistingConnections() {
        try {
            const fetchFn = (window.AuthUI && window.AuthUI.authFetch) ? window.AuthUI.authFetch : fetch;
            const res = await fetchFn(`${window.COMPLIANCE_API_URL}/api/tenants`);
            if (res.ok) {
                const data = await res.json();
                const tenants = data.tenants || [];
                if (tenants.length > 0) {
                    state.activeTenant = tenants[0];
                    state.providers[tenants[0].provider] = true;
                    updateUIForConnectedState(tenants[0]);
                }
            }
        } catch (e) {
            console.warn('Initial connection check skipped:', e);
        }
    }

    function updateUIForConnectedState(tenant) {
        const stepConnect = document.getElementById('step-connect');
        const numEl = document.getElementById('step-connect-num');
        const btnRunScan = document.getElementById('btn-run-first-scan');
        const connectStatus = document.getElementById('aws-connect-status-badge');
        
        if (stepConnect) stepConnect.classList.add('completed');
        if (numEl) numEl.textContent = '✓';
        if (btnRunScan) {
            btnRunScan.disabled = false;
            btnRunScan.classList.remove('btn-disabled');
            btnRunScan.classList.add('pulse-glow');
        }
        if (connectStatus) {
            connectStatus.style.display = 'inline-flex';
            connectStatus.className = 'status-line connected';
            connectStatus.textContent = `✓ Connected (${tenant.name || tenant.provider.toUpperCase()})`;
        }

        const tracker = document.getElementById('scheduled-scan-tracker');
        if (tracker) tracker.style.display = 'block';

        updateChips();
    }

    /**
     * Primary Guided AWS Onboarding Path (CloudFormation -> Role ARN)
     */
    async function testAndConnectAWS() {
        const roleArnInput = document.getElementById('input-aws-role-arn');
        const externalIdInput = document.getElementById('input-aws-external-id');
        const emailInput = document.getElementById('input-aws-email');
        const statusEl = document.getElementById('aws-connect-status-inline');
        const btnTest = document.getElementById('btn-test-aws-connection');

        const roleArn = roleArnInput ? roleArnInput.value.trim() : '';
        const externalId = externalIdInput ? externalIdInput.value.trim() : '';
        const email = emailInput ? emailInput.value.trim() : '';

        if (!roleArn) {
            if (window.showToast) window.showToast('Please paste the Role ARN from your CloudFormation stack output.');
            if (roleArnInput) roleArnInput.focus();
            return;
        }

        if (btnTest) {
            btnTest.disabled = true;
            btnTest.textContent = 'Testing connection...';
        }
        if (statusEl) {
            statusEl.style.display = 'block';
            statusEl.className = 'status-line connecting';
            statusEl.textContent = 'Validating IAM AssumeRole handshake...';
        }

        if (window.LiveTerminal) {
            LiveTerminal.log('system', `Initiating real AWS STS AssumeRole handshake: ${roleArn}`);
        }

        try {
            const credentials = {
                authMethod: 'role',
                roleArn,
                externalId: externalId || 'CF-AINS-ONBOARDING-SECRET',
                region: 'us-east-1'
            };

            state.credentials['aws'] = credentials;

            const fetchFn = (window.AuthUI && window.AuthUI.authFetch) ? window.AuthUI.authFetch : fetch;
            
            // 1. Validate connection
            const valRes = await fetchFn(`${window.COMPLIANCE_API_URL}/api/validate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider: 'aws', credentials })
            });

            const valData = await valRes.json();
            if (!valRes.ok || !valData.success) {
                throw new Error(valData.error || 'AWS AssumeRole handshake failed. Please verify Role ARN and Trust Policy.');
            }

            if (window.LiveTerminal) {
                LiveTerminal.log('output', `Identity verified: ${valData.identity || 'AWS Account'}`);
            }

            // 2. Automatically register tenant on server
            const tenantName = `AWS Production (${roleArn.split('/').pop() || 'Account'})`;
            const tenantRes = await fetchFn(`${window.COMPLIANCE_API_URL}/api/tenants`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider: 'aws',
                    name: tenantName,
                    email: email || 'admin@compflow.icu',
                    roleArn,
                    externalId: externalId || 'CF-AINS-ONBOARDING-SECRET',
                    scheduleFrequency: 'daily',
                    autoRemediate: false
                })
            });

            if (!tenantRes.ok) {
                const tData = await tenantRes.json().catch(() => ({}));
                console.warn('Tenant registration note:', tData.error);
            }

            state.providers['aws'] = true;

            if (statusEl) {
                statusEl.className = 'status-line connected';
                statusEl.textContent = '✓ Connected & verified. Ready to run first scan.';
            }
            if (btnTest) {
                btnTest.disabled = false;
                btnTest.textContent = '✓ Verified';
                btnTest.className = 'btn btn-success btn-sm';
            }

            if (window.showToast) window.showToast('✅ AWS connected & verified. Ready for scan!');

            // Trigger UI transitions
            updateUIForConnectedState({ provider: 'aws', name: tenantName });
            if (window.TenantManager) TenantManager.loadTenants();

        } catch (err) {
            console.error('AWS Connect Error:', err);
            if (statusEl) {
                statusEl.className = 'status-line failed';
                statusEl.textContent = `✕ Connection failed: ${err.message}`;
            }
            if (btnTest) {
                btnTest.disabled = false;
                btnTest.textContent = 'Fix credentials & Retry';
                btnTest.className = 'btn btn-danger btn-sm';
            }
            if (window.showToast) window.showToast(`Connection failed: ${err.message}`);
        }
    }

    function isConnected() {
        return Object.values(state.providers).some(Boolean) || state.activeTenant !== null;
    }

    function getProviders() {
        const active = Object.keys(state.providers).filter(k => state.providers[k]);
        if (active.length > 0) return active;
        if (state.activeTenant) return [state.activeTenant.provider];
        return ['aws'];
    }

    function getCredentials(provider) {
        if (state.credentials[provider]) return state.credentials[provider];
        if (state.activeTenant && state.activeTenant.provider === provider) {
            return {
                authMethod: 'role',
                roleArn: state.activeTenant.roleArn,
                externalId: state.activeTenant.externalId || 'CF-AINS-ONBOARDING-SECRET',
                region: 'us-east-1'
            };
        }
        return null;
    }

    function getSettings() {
        return {
            reportEmail: (state.activeTenant && state.activeTenant.email) ? state.activeTenant.email : 'compliance@compflow.icu'
        };
    }

    function updateChips() {
        const container = document.getElementById('connection-chips');
        if (!container) return;
        
        const connected = getProviders();
        if (connected.length === 0) {
            container.innerHTML = '';
            return;
        }

        container.innerHTML = connected.map(p => `
            <span class="chip connected" style="font-size:0.75rem; background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); padding:3px 8px; border-radius:12px; display:inline-flex; align-items:center; gap:4px;">
                <span class="dot" style="width:6px; height:6px; border-radius:50%; background:#10b981;"></span>
                ${p.toUpperCase()} Connected
            </span>
        `).join('');
    }

    document.addEventListener('DOMContentLoaded', init);

    return {
        init,
        testAndConnectAWS,
        isConnected,
        getProviders,
        getCredentials,
        getSettings,
        updateChips,
        checkExistingConnections
    };
})();
