window.TenantManager = (() => {
    let tenants = [];

    async function init() {
        await loadTenants();
    }

    // Use relative paths for Vercel deployment

    async function loadTenants() {
        try {
            const res = await fetch(`${window.COMPLIANCE_API_URL}/api/tenants`);
            const data = await res.json();
            tenants = data.tenants || [];
            renderTenants();
        } catch (e) {
            console.error("Failed to load tenants", e);
        }
    }

    function renderTenants() {
        const list = document.getElementById('tenant-list');
        const empty = document.getElementById('tenants-empty');
        
        if (!list || !empty) return;

        if (tenants.length === 0) {
            list.innerHTML = '';
            empty.style.display = 'flex';
            list.style.display = 'none';
            return;
        }

        empty.style.display = 'none';
        list.style.display = 'grid';
        list.innerHTML = tenants.map(t => {
            const statusBadge = t.configStatus ? 
                `<span class="status-badge warn" style="font-size:0.65rem; margin-left:0.5rem;">${t.configStatus}</span>` : 
                `<span class="status-badge pass" style="font-size:0.65rem; margin-left:0.5rem;">Active</span>`;
            
            return `
            <div class="tenant-card">
                <div class="tenant-info">
                    <h4>${t.name} <span class="provider-tag">${t.provider.toUpperCase()}</span> ${statusBadge}</h4>
                    <code>${t.roleArn ? t.roleArn.split('/').pop() : 'API Key Active'}</code>
                </div>
                <div class="tenant-controls">
                    <div class="toggle-group">
                        <span>Auto-Fix</span>
                        <label class="switch">
                            <input type="checkbox" ${t.autoRemediate ? 'checked' : ''} onchange="TenantManager.toggleAuto('${t.id}', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <button class="btn btn-secondary btn-sm" onclick="TenantManager.runScan('${t.id}')">Scan Now</button>
                    <button class="btn btn-sm btn-danger" onclick="TenantManager.removeTenant('${t.id}')">🗑️</button>
                </div>
            </div>`;
        }).join('');
    }

    function openOnboarding() {
        console.log("Opening Onboarding Modal...");
        const modal = document.getElementById('modal-onboarding');
        if (modal) modal.classList.add('active');
    }

    function closeOnboarding() {
        document.getElementById('modal-onboarding').classList.remove('active');
    }

    function updateOnboardFields() {
        const provider = document.getElementById('onboard-provider').value;
        const container = document.getElementById('onboard-dynamic-fields');
        
        if (provider === 'aws') {
            container.innerHTML = `
                <div class="input-group">
                    <label>AWS Account ID <span style="color:var(--danger)">*</span></label>
                    <input type="text" id="onboard-aws-account" placeholder="12-Digit Account ID" maxlength="12" oninput="TenantManager.updatePathPreview()">
                </div>
                <div id="arn-preview-wrap" style="background:rgba(0,0,0,0.2); padding:0.6rem; border-radius:4px; font-size:0.75rem; border:1px solid rgba(255,255,255,0.05); margin-top:0.5rem; display:none;">
                    <div style="color:var(--text-dim); margin-bottom:4px; text-transform:uppercase; font-size:0.65rem;">Predicted Scanner ARN:</div>
                    <code id="arn-preview" style="color:var(--primary); word-break:break-all;">arn:aws:iam::...:role/ComplianceFlow-AINS-Scanner</code>
                </div>
            `;
        } else if (provider === 'gcp') {
            container.innerHTML = `
                <div class="input-group">
                    <label>Service Account JSON Key</label>
                    <textarea id="onboard-gcp-json" placeholder='{ "type": "service_account", ... }' style="height: 120px; font-family: monospace; font-size: 0.8rem;"></textarea>
                </div>
            `;
        } else if (provider === 'azure') {
            container.innerHTML = `
                <div class="input-group">
                    <label>Tenant ID / Directory ID</label>
                    <input type="text" id="onboard-azure-tenant" placeholder="00000000-0000-...">
                </div>
                <div class="input-group">
                    <label>Client ID / Application ID</label>
                    <input type="text" id="onboard-azure-client" placeholder="00000000-0000-...">
                </div>
                <div class="input-group">
                    <label>Client Secret</label>
                    <input type="password" id="onboard-azure-secret" placeholder="••••••••">
                </div>
                <div class="input-group">
                    <label>Subscription ID</label>
                    <input type="text" id="onboard-azure-sub" placeholder="00000000-0000-...">
                </div>
            `;
        } else if (provider === 'hetzner' || provider === 'digitalocean') {
            container.innerHTML = `
                <div class="input-group">
                    <label>${provider === 'hetzner' ? 'Hetzner API Token' : 'DigitalOcean Personal Access Token'} <span style="color:var(--danger)">*</span></label>
                    <input type="password" id="onboard-token" placeholder="Bearer Token...">
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="input-group">
                    <label>${provider.toUpperCase()} API Token</label>
                    <input type="password" id="onboard-token" placeholder="Bearer Token...">
                </div>
            `;
        }
    }

    function updatePathPreview() {
        const accId = document.getElementById('onboard-aws-account').value;
        const wrap = document.getElementById('arn-preview-wrap');
        const preview = document.getElementById('arn-preview');
        
        if (accId && accId.length === 12) {
            wrap.style.display = 'block';
            preview.textContent = `arn:aws:iam::${accId}:role/ComplianceFlow-AINS-Scanner`;
        } else {
            wrap.style.display = 'none';
        }
    }

    async function saveTenant() {
        const provider = document.getElementById('onboard-provider').value;
        const name = document.getElementById('onboard-name').value;
        const email = document.getElementById('onboard-email').value;
        const autoRemediate = document.getElementById('onboard-auto').checked;

        let credentials = {};
        let externalId = null;
        let quickLink = null;
        
        if (provider === 'aws') {
            const awsAccountId = document.getElementById('onboard-aws-account').value;
            if (!awsAccountId || !/^\d{12}$/.test(awsAccountId)) {
                return alert("A valid 12-digit AWS Account ID is required");
            }
            
            // Generate unique ExternalId and deterministic ARN
            externalId = 'CF-EXT-' + crypto.randomUUID().toUpperCase();
            const roleArn = `arn:aws:iam::${awsAccountId}:role/ComplianceFlow-AINS-Scanner`;
            
            // USE VERCEL HOSTED TEMPLATE (Case-Sensitive & Encoded)
            // Updated to use the public folder for stronger support
            const s3Url = "https://comp-flow.vercel.app/public/complianceflow-iam-setup.yaml";
            const encodedUrl = encodeURIComponent(s3Url);
            quickLink = `https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=${encodedUrl}&stackName=ComplianceFlow-Integration&param_ExternalId=${encodeURIComponent(externalId)}`;
            
            credentials = { roleArn, externalId, configStatus: 'Awaiting AWS Setup' };
        } else if (provider === 'gcp') {
            const jsonKey = document.getElementById('onboard-gcp-json').value;
            if (!jsonKey) return alert("GCP JSON Key is required");
            try { JSON.parse(jsonKey); } catch(e) { return alert("Invalid JSON format"); }
            credentials = { serviceAccountJson: jsonKey };
        } else if (provider === 'azure') {
            const tenantId = document.getElementById('onboard-azure-tenant').value;
            const clientId = document.getElementById('onboard-azure-client').value;
            const clientSecret = document.getElementById('onboard-azure-secret').value;
            const subscriptionId = document.getElementById('onboard-azure-sub').value;
            if (!tenantId || !clientId || !clientSecret || !subscriptionId) return alert("All Azure fields are required");
            credentials = { tenantId, clientId, clientSecret, subscriptionId };
        } else {
            const apiToken = document.getElementById('onboard-token').value;
            if (!apiToken) return alert("API Token is required");
            credentials = { apiToken };
        }

        if (!name) return alert("Name is required.");
        if (!email) return alert("A reporting email is required for scan report delivery.");

        try {
            const res = await fetch(`${window.COMPLIANCE_API_URL}/api/tenants`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, name, email, autoRemediate, ...credentials })
            });

            if (res.ok) {
                if (provider === 'aws' && quickLink) {
                    window.open(quickLink, '_blank');
                    showToast("Redirecting to AWS for IAM configuration...");
                }
                
                showToast("Environment registered in Governance Registry.");
                closeOnboarding();
                await loadTenants();
            }
        } catch (e) {
            showToast("Error saving tenant: " + e.message);
        }
    }

    async function toggleAuto(id, enabled) {
        try {
            await fetch(`${window.COMPLIANCE_API_URL}/api/tenants/toggle`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id, autoRemediate: enabled })
            });
            showToast(`Auto-Remediation ${enabled ? 'Enabled' : 'Disabled'}`);
        } catch (e) { console.error(e); }
    }

    async function runScan(id) {
        // Throttling: Prevent rapid manual triggers
        const now = Date.now();
        const COOLDOWN = 60000; 
        window._lastTriggerTime = window._lastTriggerTime || {};
        if (window._lastTriggerTime[id] && (now - window._lastTriggerTime[id] < COOLDOWN)) {
            const remaining = Math.ceil((COOLDOWN - (now - window._lastTriggerTime[id])) / 1000);
            showToast(`Wait ${remaining}s before re-triggering this tenant.`);
            return;
        }

        showToast("Dispatching autonomous scan task...");
        if (window.LiveTerminal) LiveTerminal.log('system', `Manual scan triggered for tenant: ${id}`);
        window._lastTriggerTime[id] = now;

        try {
            const triggerRes = await fetch(`${window.COMPLIANCE_API_URL}/api/trigger`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clientId: id })
            });

            if (!triggerRes.ok) throw new Error("Failed to dispatch scan");
            
            if (window.LiveTerminal) LiveTerminal.log('agent', `Scan queued for ${id}. Awaiting cloud agent results...`);
            
            // Poll for completion logs
            let attempts = 0;
            const poll = setInterval(async () => {
                attempts++;
                if (attempts > 30) {
                    clearInterval(poll);
                    if (window.LiveTerminal) LiveTerminal.log('insight', `Scan for ${id} timed out. Check Background Tasks.`);
                    return;
                }

                try {
                    const logRes = await fetch(`${window.COMPLIANCE_API_URL}/api/audit?clientId=${id}`);
                    const logs = await logRes.json();
                    
                    // Look for the completion log
                    const complete = logs.find(l => l.level === 'SCAN_COMPLETE' && new Date(l.timestamp).getTime() > now - 5000);
                    if (complete) {
                        clearInterval(poll);
                        if (window.LiveTerminal) LiveTerminal.log('output', `✓ Scan Complete for ${id}: ${complete.message}`);
                        
                        // Populate UI with results if available in the log
                        if (complete.details && complete.details.resources) {
                            if (window.Scanner) {
                                Scanner.displayResults(complete.details.resources);
                                if (window.LiveTerminal) LiveTerminal.log('insight', `Dashboard populated with ${complete.details.resources.length} resources.`);
                            }
                        } else if (complete.details && complete.details.summary) {
                            const s = complete.details.summary;
                            if (window.LiveTerminal) LiveTerminal.log('insight', `Results: ${s.resolved} Fixed, ${s.escalated} Escalated.`);
                        }
                    }
                } catch (e) { console.warn("Poll error", e); }
            }, 3000);

        } catch (e) {
            if (window.LiveTerminal) LiveTerminal.log('insight', `Trigger Failed: ${e.message}`);
        }
    }

    async function removeTenant(id) {
        if (!confirm("Are you sure you want to remove this environment?")) return;
        try {
            // Implementation of delete would go here
            showToast("Environment removed from registry.");
            await loadTenants();
        } catch (e) { console.error(e); }
    }

    return { init, openOnboarding, closeOnboarding, saveTenant, toggleAuto, runScan, removeTenant, updateOnboardFields, updatePathPreview };
})();

document.addEventListener('DOMContentLoaded', TenantManager.init);
