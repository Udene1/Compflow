window.TenantManager = (() => {
    let tenants = [];

    async function init() {
        await loadTenants();
    }

    async function loadTenants() {
        try {
            const res = await fetch('/api/tenants');
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
        list.innerHTML = tenants.map(t => `
            <div class="tenant-card">
                <div class="tenant-info">
                    <h4>${t.name} <span class="provider-tag">${t.provider.toUpperCase()}</span></h4>
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
            </div>
        `).join('');
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
                    <label>AWS Role ARN</label>
                    <input type="text" id="onboard-role" placeholder="arn:aws:iam::...:role/ComplianceRole">
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

    async function saveTenant() {
        const provider = document.getElementById('onboard-provider').value;
        const name = document.getElementById('onboard-name').value;
        const email = document.getElementById('onboard-email').value;
        const autoRemediate = document.getElementById('onboard-auto').checked;

        let credentials = {};
        if (provider === 'aws') {
            const roleArn = document.getElementById('onboard-role').value;
            if (!roleArn) return alert("Role ARN is required");
            credentials = { roleArn };
        } else {
            const apiToken = document.getElementById('onboard-token').value;
            if (!apiToken) return alert("API Token is required");
            credentials = { apiToken };
        }

        if (!name) return alert("Name is required.");

        try {
            const res = await fetch('/api/tenants', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, name, email, autoRemediate, ...credentials })
            });

            if (res.ok) {
                showToast("Tenant onboarded successfully!");
                closeOnboarding();
                await loadTenants();
            }
        } catch (e) {
            showToast("Error saving tenant: " + e.message);
        }
    }

    async function toggleAuto(id, enabled) {
        try {
            await fetch('/api/tenants/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id, autoRemediate: enabled })
            });
            showToast(`Auto-Remediation ${enabled ? 'Enabled' : 'Disabled'}`);
        } catch (e) { console.error(e); }
    }

    async function runScan(id) {
        showToast("Dispatching autonomous scan task...");
        LiveTerminal.log('system', `Manual scan triggered for tenant: ${id}`);
        // In Phase B, this would trigger the Scheduler Lambda
        await fetch('/api/trigger', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientId: id })
        });
    }

    async function removeTenant(id) {
        if (!confirm("Are you sure you want to remove this environment?")) return;
        try {
            // Implementation of delete would go here
            showToast("Environment removed from registry.");
            await loadTenants();
        } catch (e) { console.error(e); }
    }

    return { init, openOnboarding, closeOnboarding, saveTenant, toggleAuto, runScan, removeTenant, updateOnboardFields };
})();

document.addEventListener('DOMContentLoaded', TenantManager.init);
