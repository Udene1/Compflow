// ─── ComplianceFlow AI: Cloud Connect & Onboarding Module ───
// Durable server-side cloud connection state. Secrets stay in SecretStore.

window.CloudConnect = (() => {
    const state = {
        providers: {},
        activeTenant: null,
        credentials: {},
        connectionIds: {}
    };

    function init() {
        ['aws', 'azure', 'gcp', 'hetzner', 'digitalocean'].forEach(p => localStorage.removeItem(`cf_creds_${p}`));
        localStorage.removeItem('cf_aws_creds');
        checkExistingConnections();
    }

    async function checkExistingConnections() {
        try {
            const fetchFn = (window.AuthUI && window.AuthUI.authFetch) ? window.AuthUI.authFetch : fetch;
            const res = await fetchFn(`${window.COMPLIANCE_API_URL}/api/onboarding/status`);
            if (!res.ok) return;
            const data = await res.json();
            const verified = (data.connections || []).filter(c => c.status === 'VERIFIED');
            if (verified.length === 0) return;
            const connection = verified[0];
            state.activeTenant = connection;
            state.providers[connection.provider] = true;
            state.connectionIds[connection.provider] = connection.id;
            updateUIForConnectedState(connection);
        } catch (e) {
            console.warn('Initial connection check skipped:', e);
        }
    }

    function updateUIForConnectedState(connection) {
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
            connectStatus.textContent = `✓ Connected (${connection.display_name || connection.name || String(connection.provider).toUpperCase()})`;
        }
        const tracker = document.getElementById('scheduled-scan-tracker');
        if (tracker) tracker.style.display = 'block';
        updateChips();
    }

    async function testAndConnectAWS() {
        const roleArnInput = document.getElementById('input-aws-role-arn');
        const externalIdInput = document.getElementById('input-aws-external-id');
        const statusEl = document.getElementById('aws-connect-status-inline');
        const btnTest = document.getElementById('btn-test-aws-connection');
        const roleArn = roleArnInput?.value?.trim() || '';
        const externalId = externalIdInput?.value?.trim() || '';

        if (!roleArn) {
            if (window.showToast) window.showToast('Please paste the Role ARN from your CloudFormation stack output.');
            roleArnInput?.focus();
            return;
        }
        if (btnTest) { btnTest.disabled = true; btnTest.textContent = 'Verifying connection...'; }
        if (statusEl) { statusEl.style.display = 'block'; statusEl.className = 'status-line connecting'; statusEl.textContent = 'Validating IAM AssumeRole handshake...'; }
        if (window.LiveTerminal) LiveTerminal.log('system', `Initiating real AWS STS AssumeRole handshake: ${roleArn}`);

        try {
            const credentials = { authMethod: 'role', roleArn, region: 'us-east-1' };
            if (externalId) credentials.externalId = externalId;

            const fetchFn = (window.AuthUI && window.AuthUI.authFetch) ? window.AuthUI.authFetch : fetch;
            const createRes = await fetchFn(`${window.COMPLIANCE_API_URL}/api/onboarding/cloud-connection`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider: 'aws', displayName: `AWS Production (${roleArn.split('/').pop() || 'Account'})`, region: 'us-east-1', credentials })
            });
            const createData = await createRes.json().catch(() => ({}));
            if (!createRes.ok) throw new Error(createData.message || createData.error || 'Cloud connection could not be created.');

            const verifyRes = await fetchFn(`${window.COMPLIANCE_API_URL}/api/onboarding/cloud-connection/${encodeURIComponent(createData.connectionId)}/verify`, { method: 'POST' });
            const verifyData = await verifyRes.json().catch(() => ({}));
            if (!verifyRes.ok || !verifyData.verified) throw new Error(verifyData.message || verifyData.error || 'AWS verification failed.');

            state.providers.aws = true;
            state.connectionIds.aws = createData.connectionId;
            state.activeTenant = { provider: 'aws', id: createData.connectionId, display_name: createData.displayName, status: 'VERIFIED' };

            if (statusEl) { statusEl.className = 'status-line connected'; statusEl.textContent = '✓ Connected & verified. Ready to run first scan.'; }
            if (btnTest) { btnTest.disabled = false; btnTest.textContent = '✓ Verified'; btnTest.className = 'btn btn-success btn-sm'; }
            if (window.showToast) window.showToast('AWS connected & verified. Initial scan queued.');
            updateUIForConnectedState(state.activeTenant);
            if (window.TenantManager) TenantManager.loadTenants();
        } catch (err) {
            console.error('AWS Connect Error:', err);
            if (statusEl) { statusEl.className = 'status-line failed'; statusEl.textContent = `✕ Connection failed: ${err.message}`; }
            if (btnTest) { btnTest.disabled = false; btnTest.textContent = 'Fix credentials & Retry'; btnTest.className = 'btn btn-danger btn-sm'; }
            if (window.showToast) window.showToast(`Connection failed: ${err.message}`);
        }
    }

    function isConnected() { return Object.values(state.providers).some(Boolean) || state.activeTenant !== null; }
    function getProviders() { return Object.keys(state.providers).filter(k => state.providers[k]); }
    function getConnectionId(provider) { return state.connectionIds[provider] || (state.activeTenant?.provider === provider ? state.activeTenant.id : null); }
    function getCredentials() { return null; }
    function getSettings() { return { reportEmail: null }; }

    function updateChips() {
        const container = document.getElementById('connection-chips');
        if (!container) return;
        const connected = getProviders();
        container.innerHTML = connected.map(p => `<span class="chip connected" style="font-size:0.75rem; background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); padding:3px 8px; border-radius:12px; display:inline-flex; align-items:center; gap:4px;"><span class="dot" style="width:6px;height:6px;border-radius:50%;background:#10b981"></span>${p.toUpperCase()} Connected</span>`).join('');
    }

    document.addEventListener('DOMContentLoaded', init);
    return { init, testAndConnectAWS, isConnected, getProviders, getConnectionId, getCredentials, getSettings, updateChips, checkExistingConnections };
})();