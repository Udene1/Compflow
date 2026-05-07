// ─── ComplianceFlow AI: Resource Scanner ───
// Generates a realistic cloud resource inventory and scans for compliance issues

window.Scanner = (() => {
    let scannedResources = [];

    function init() {
        const btn = document.getElementById('btn-start-scan');
        if (btn) btn.addEventListener('click', startScan);
    }

    async function startScan() {
        if (!CloudConnect.isConnected()) {
            LiveTerminal.log('insight', 'ERROR: No cloud provider connected. Go to Cloud Connect first.');
            return;
        }

        const providers = CloudConnect.getProviders();
        const provider = providers[0];
        const credentials = CloudConnect.getCredentials(provider);

        if (!credentials) {
            LiveTerminal.log('insight', 'ERROR: Missing credentials for ' + provider);
            CloudConnect.openSettings(provider);
            return;
        }

        const btn = document.getElementById('btn-start-scan');
        btn.disabled = true;
        btn.textContent = 'Scanning...';

        scannedResources = [];
        document.getElementById('resource-tbody').innerHTML = '';
        document.getElementById('scan-empty').style.display = 'none';
        document.getElementById('resource-table').style.display = 'table';
        document.getElementById('scan-stats').style.display = 'grid';
        document.getElementById('scan-progress-wrap').style.display = 'block';
        document.getElementById('scan-progress-fill').style.width = '10%';

        LiveTerminal.log('system', `Contacting real cloud APIs for ${provider.toUpperCase()}...`);
        LiveTerminal.log('agent', `Requesting enumeration of resources...`);

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, credentials })
            });
            const data = await res.json();
            
            if (data.error) throw new Error(data.error);

            scannedResources = data.resources || [];
            document.getElementById('scan-progress-fill').style.width = '100%';

            scannedResources.forEach((res, i) => {
                res.id = i;
                const controlKeys = Frameworks.getMapping(res.type, res.issue);
                res.controlKeys = controlKeys;
                
                const activeControlKey = controlKeys.find(k => k.startsWith(Frameworks.getCurrentId())) || controlKeys[0];
                const controlDetail = Frameworks.getControlDetails(activeControlKey);
                res.control = controlDetail ? controlDetail.id : 'N/A';

                addResourceRow(res);
                
                if (res.severity === 'critical') {
                    LiveTerminal.log('insight', `CRITICAL: ${res.type} "${res.name}" — ${res.issue}`);
                } else if (res.severity === 'warning') {
                    LiveTerminal.log('agent', `Warning: ${res.type} "${res.name}" — ${res.issue}`);
                }
            });

            LiveTerminal.log('output', `Scan complete: ${scannedResources.length} resources found.`);
            
            updateStatsUI();
            updateScore();
            
            // Baseline for Drift Engine
            if (window.DriftEngine) DriftEngine.setBaseline(scannedResources);

            // Evidence
            scannedResources.forEach(r => {
                if (window.Evidence) Evidence.captureFromScan(r);
            });
            updateEvidenceBadge();

            // Remediation
            if (window.Remediation) Remediation.buildFromScan(scannedResources);
            
            btn.disabled = false;
            btn.textContent = 'Re-scan';
        } catch (err) {
            console.error(err);
            LiveTerminal.log('insight', `SCAN FAILED: ${err.message}`);
            btn.disabled = false;
            btn.textContent = 'Retry Scan';
        }
    }

    async function runBackgroundScan() {
        if (!CloudConnect.isConnected()) return null;
        const providers = CloudConnect.getProviders();
        const provider = providers[0];
        const credentials = CloudConnect.getCredentials(provider);

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, credentials })
            });
            const data = await res.json();
            return data.resources || [];
        } catch (e) { return null; }
    }

    function addResourceRow(res) {
        const tbody = document.getElementById('resource-tbody');
        const tr = document.createElement('tr');
        tr.className = 'resource-row';
        tr.id = 'resource-row-' + res.id;

        const sevClass = res.severity === 'pass' ? 'pass' : res.severity === 'warning' ? 'warning' : 'critical';
        const sevLabel = res.severity === 'pass' ? '✓ Pass' : res.severity === 'warning' ? '⚠ Warning' : '✕ Critical';

        tr.innerHTML = `
            <td><div class="resource-name">${res.icon} ${res.name}</div>
                <div style="font-size:0.72rem; color:var(--text-dim); margin-top:2px;">${res.issue || 'No issues'}</div></td>
            <td><span class="resource-type">${res.type}</span></td>
            <td style="color:var(--text-muted); font-size:0.82rem;">${res.region}</td>
            <td><span class="severity-badge ${sevClass}">${sevLabel}</span></td>
            <td><span class="rem-control-tag">${res.control}</span></td>
        `;
        tbody.appendChild(tr);
    }

    function updateStatsUI() {
        const counts = getCounts();
        document.getElementById('stat-total').textContent = counts.total;
        document.getElementById('stat-pass').textContent = counts.pass;
        document.getElementById('stat-warn').textContent = counts.warn;
        document.getElementById('stat-crit').textContent = counts.crit;
        
        const badge = document.getElementById('issues-badge');
        const issues = scannedResources.filter(r => r.severity !== 'pass');
        if (issues.length > 0) {
            badge.style.display = 'inline';
            badge.textContent = issues.length;
        } else {
            badge.style.display = 'none';
        }
    }

    function getCounts() {
        const total = scannedResources.length;
        const pass = scannedResources.filter(r => r.severity === 'pass').length;
        const warn = scannedResources.filter(r => r.severity === 'warning').length;
        const crit = scannedResources.filter(r => r.severity === 'critical').length;
        return { total, pass, warn, crit };
    }

    function updateScore() {
        const counts = getCounts();
        const score = counts.total > 0 ? Math.round((counts.pass / counts.total) * 100) : 0;
        document.getElementById('sidebar-score').textContent = score + '%';
    }

    function markFixed(resourceId) {
        const res = scannedResources.find(r => r.id === resourceId);
        if (res) {
            res.severity = 'pass';
            res.issue = null;
            const row = document.getElementById('resource-row-' + resourceId);
            if (row) {
                const badge = row.querySelector('.severity-badge');
                badge.className = 'severity-badge pass';
                badge.textContent = '✓ Pass';
                const issueDiv = row.querySelector('.resource-name').parentElement.querySelector('div:nth-child(2)');
                if (issueDiv) issueDiv.textContent = 'Remediated';
            }
            updateStatsUI();
            updateScore();
        }
    }

    function updateEvidenceBadge() {
        if (!window.Evidence) return;
        const log = Evidence.getEvidenceLog();
        const badge = document.getElementById('evidence-badge');
        if (badge && log.length > 0) {
            badge.style.display = 'inline';
            badge.textContent = log.length;
        }
    }

    function simulateDrift() {
        if (scannedResources.length === 0) return;
        const passing = scannedResources.filter(r => r.severity === 'pass');
        if (passing.length === 0) return;
        
        const target = passing[Math.floor(Math.random() * passing.length)];
        target.severity = 'critical';
        target.issue = 'S3 Public Access Block disabled (Drift Detected)';
        
        LiveTerminal.log('insight', `SIMULATED DRIFT: Resource "${target.name}" has been modified externally.`);
        
        const row = document.getElementById('resource-row-' + target.id);
        if (row) {
            const badge = row.querySelector('.severity-badge');
            badge.className = 'severity-badge critical';
            badge.textContent = '✕ Critical';
            const issueDiv = row.querySelector('.resource-name').parentElement.querySelector('div:nth-child(2)');
            if (issueDiv) issueDiv.textContent = target.issue;
        }
        updateStatsUI();
        updateScore();
    }

    function getResources() { return scannedResources; }

    return { init, getResources, markFixed, updateEvidenceBadge, updateScore, runBackgroundScan, simulateDrift };
})();

document.addEventListener('DOMContentLoaded', Scanner.init);
