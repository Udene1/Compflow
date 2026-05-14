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
        
        if (tenants.length === 0) {
            list.innerHTML = '';
            empty.style.display = 'block';
            return;
        }

        empty.style.display = 'none';
        list.innerHTML = tenants.map(t => `
            <div class="tenant-card">
                <div class="tenant-info">
                    <h4>${t.name}</h4>
                    <code>${t.roleArn.split(':').pop()}</code>
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
                </div>
            </div>
        `).join('');
    }

    function openOnboarding() {
        document.getElementById('modal-onboarding').classList.add('active');
    }

    function closeOnboarding() {
        document.getElementById('modal-onboarding').classList.remove('active');
    }

    async function saveTenant() {
        const name = document.getElementById('onboard-name').value;
        const roleArn = document.getElementById('onboard-role').value;
        const email = document.getElementById('onboard-email').value;
        const autoRemediate = document.getElementById('onboard-auto').checked;

        if (!name || !roleArn) return alert("Name and Role ARN are required.");

        try {
            const res = await fetch('/api/tenants', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, roleArn, email, autoRemediate })
            });

            if (res.ok) {
                closeOnboarding();
                await loadTenants();
            }
        } catch (e) {
            alert("Error saving tenant: " + e.message);
        }
    }

    async function toggleAuto(id, enabled) {
        try {
            await fetch('/api/tenants/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id, autoRemediate: enabled })
            });
        } catch (e) { console.error(e); }
    }

    async function runScan(id) {
        LiveTerminal.log('system', `Manual scan triggered for tenant: ${id}`);
        // In Phase B, this would trigger the Scheduler Lambda
        await fetch('/api/trigger', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientId: id })
        });
        alert(`Scan triggered! Check the Live Terminal for updates.`);
    }

    return { init, openOnboarding, closeOnboarding, saveTenant, toggleAuto, runScan };
})();

document.addEventListener('DOMContentLoaded', TenantManager.init);
