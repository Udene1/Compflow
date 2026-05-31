// ─── ComplianceFlow AI: Resource Scanner ───
// Connects to AWS Lambda backend, tracks jobs, and streams results to the terminal

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
        
        // Throttling: Prevent rapid re-scanning
        const now = Date.now();
        const COOLDOWN = 60000; // 60 seconds
        if (window._lastScanTime && (now - window._lastScanTime < COOLDOWN)) {
            const remaining = Math.ceil((COOLDOWN - (now - window._lastScanTime)) / 1000);
            LiveTerminal.log('system', `Please wait ${remaining}s before re-scanning.`);
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Scanning...';
        window._lastScanTime = now;

        scannedResources = [];
        document.getElementById('resource-tbody').innerHTML = '';
        document.getElementById('scan-empty').style.display = 'none';
        document.getElementById('resource-table').style.display = 'table';
        document.getElementById('scan-stats').style.display = 'grid';
        document.getElementById('scan-progress-wrap').style.display = 'block';
        document.getElementById('scan-progress-fill').style.width = '5%';

        LiveTerminal.log('system', `Contacting real cloud APIs for ${provider.toUpperCase()}...`);
        LiveTerminal.log('agent', `Requesting enumeration of resources...`);

        const BASE_URL = ""; // Use relative paths for Vercel deployment
        
        try {
            const clientId = 'adhoc_user';
            LiveTerminal.log('system', 'Directing scan request to cloud engine...');

            // ── Step 1: Trigger scan and get jobId ──
            const triggerRes = await fetch(`${BASE_URL}/api/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, credentials, clientId, email: document.getElementById('scan-report-email')?.value })
            });

            if (!triggerRes.ok) throw new Error(`HTTP ${triggerRes.status}`);

            let triggerData;
            try {
                triggerData = await triggerRes.json();
            } catch (jsonErr) {
                throw new Error("Backend returned non-JSON response. Please check if Lambda is live.");
            }
            
            if (triggerData.error) throw new Error(triggerData.error);

            const jobId = triggerData.jobId;
            if (!jobId) {
                throw new Error("No jobId returned from scan endpoint.");
            }

            LiveTerminal.log('system', `Scan job created (ID: ${jobId.slice(0, 8)}...). Streaming progress...`);

            // ── Step 2: Poll job status ──
            const results = await pollJobStatus(jobId, BASE_URL);
            if (!results) throw new Error("Scan timed out or failed on backend.");

            scannedResources = results;
            document.getElementById('scan-progress-fill').style.width = '100%';

            displayResults(scannedResources);
            
            btn.disabled = false;
            btn.textContent = 'Re-scan';
        } catch (err) {
            console.error(err);
            LiveTerminal.log('insight', `SCAN FAILED: ${err.message}`);
            btn.disabled = false;
            btn.textContent = 'Retry Scan';
        }
    }

    /**
     * Polls /api/job-status for progressive updates.
     * Streams logs to terminal and updates progress bar in real-time.
     */
    async function pollJobStatus(jobId, baseUrl) {
        const MAX_POLL_MS = 15 * 60 * 1000; // 15 minute timeout
        const POLL_INTERVAL = 3000; // 3 seconds
        const start = Date.now();
        let logIndex = 0; // Track which logs we've already rendered

        while (Date.now() - start < MAX_POLL_MS) {
            await new Promise(r => setTimeout(r, POLL_INTERVAL));

            try {
                const res = await fetch(`${baseUrl}/api/job-status?jobId=${jobId}`);
                if (!res.ok) {
                    console.warn(`[POLL] HTTP ${res.status}`);
                    continue;
                }

                const job = await res.json();

                // Stream new logs to terminal
                if (job.logs && job.logs.length > logIndex) {
                    logIndex = LiveTerminal.logBatch(job.logs, logIndex);
                }

                // Update progress bar
                if (job.progress > 0) {
                    document.getElementById('scan-progress-fill').style.width = `${Math.min(job.progress, 99)}%`;
                }

                // Check terminal states
                if (job.status === 'completed') {
                    return job.resources || [];
                }

                if (job.status === 'failed') {
                    throw new Error(job.errorMessage || 'Scan failed on backend.');
                }

            } catch (e) {
                if (e.message.includes('failed')) throw e;
                console.warn("[POLL] Error:", e.message);
            }
        }

        return null; // Timeout
    }

    function displayResults(resources) {
        document.getElementById('resource-tbody').innerHTML = '';
        resources.forEach((res, i) => {
            res.id = i;
            const controlKeys = Frameworks.getMapping(res.type, res.issue);
            res.controlKeys = controlKeys;
            
            const activeControlKey = controlKeys.find(k => k.startsWith(Frameworks.getCurrentId())) || controlKeys[0];
            const controlDetail = Frameworks.getControlDetails(activeControlKey);
            res.control = controlDetail ? controlDetail.id : 'N/A';

            addResourceRow(res);
            if (window.Evidence) Evidence.captureFromScan(res);
            
            if (res.severity === 'critical') {
                LiveTerminal.log('insight', `CRITICAL: ${res.type} "${res.name}" — ${res.issue}`);
            } else if (res.severity === 'warning') {
                LiveTerminal.log('agent', `Warning: ${res.type} "${res.name}" — ${res.issue}`);
            }
        });

        LiveTerminal.log('output', `Scan complete: ${resources.length} resources found.`);
        updateStatsUI();
        updateScore();
        
        if (window.DriftEngine) DriftEngine.setBaseline(resources);
        if (window.Remediation) Remediation.buildFromScan(resources);
        if (window.Evidence) Evidence.refreshView();
    }

    async function runBackgroundScan() {
        if (!CloudConnect.isConnected()) return null;
        const providers = CloudConnect.getProviders();
        const provider = providers[0];
        const credentials = CloudConnect.getCredentials(provider);

        const BASE_URL = "";
        try {
            const res = await fetch(`${BASE_URL}/api/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, credentials, email: document.getElementById('scan-report-email')?.value })
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

        // Generate control badges
        let controlsHtml = '';
        if (res.controls) {
            if (res.controls.soc2) controlsHtml += `<span class="rem-control-tag soc2" title="SOC2: ${res.controls.soc2.join(', ')}">S</span> `;
            if (res.controls.gdpr) controlsHtml += `<span class="rem-control-tag gdpr" title="GDPR: ${res.controls.gdpr.join(', ')}">G</span> `;
            if (res.controls.hipaa) controlsHtml += `<span class="rem-control-tag hipaa" title="HIPAA: ${res.controls.hipaa.join(', ')}">H</span> `;
            if (res.controls.iso27001) controlsHtml += `<span class="rem-control-tag iso" title="ISO 27001: ${res.controls.iso27001.join(', ')}">I</span> `;
        } else {
            controlsHtml = `<span class="rem-control-tag">${res.control || 'N/A'}</span>`;
        }

        tr.innerHTML = `
            <td><div class="resource-name">${res.icon} ${res.name}</div>
                <div style="font-size:0.72rem; color:var(--text-dim); margin-top:2px;">${res.issue || 'No issues'}</div></td>
            <td><span class="resource-type">${res.type}</span></td>
            <td style="color:var(--text-muted); font-size:0.82rem;">${res.region}</td>
            <td><span class="severity-badge ${sevClass}">${sevLabel}</span></td>
            <td><div class="control-badges-wrap">${controlsHtml}</div></td>
        `;
        tbody.appendChild(tr);
    }

    function updateStatsUI() {
        const counts = getCounts();
        document.getElementById('stat-total').textContent = counts.total;
        document.getElementById('stat-pass').textContent = counts.pass;
        document.getElementById('stat-warn').textContent = counts.warn;
        document.getElementById('stat-crit').textContent = counts.crit;
        
        // Maturity Matrix Calculation
        const maturity = { soc2: 42, gdpr: 31, hipaa: 26, iso27001: 35 };
        const failures = { soc2: 0, gdpr: 0, hipaa: 0, iso27001: 0 };

        scannedResources.forEach(res => {
            if (res.severity !== 'pass' && res.controls) {
                if (res.controls.soc2) failures.soc2 += res.controls.soc2.length;
                if (res.controls.gdpr) failures.gdpr += res.controls.gdpr.length;
                if (res.controls.hipaa) failures.hipaa += res.controls.hipaa.length;
                if (res.controls.iso27001) failures.iso27001 += res.controls.iso27001.length;
            }
        });

        const updateMaturity = (id, total, failed) => {
            const passed = Math.max(0, total - failed);
            const percent = Math.round((passed / total) * 100);
            const el = document.getElementById(`maturity-${id}`);
            const fill = document.getElementById(`fill-${id}`);
            if (el) el.textContent = `${passed}/${total}`;
            if (fill) fill.style.width = `${percent}%`;
        };

        document.getElementById('maturity-grid').style.display = 'grid';
        updateMaturity('soc2', 42, failures.soc2);
        updateMaturity('gdpr', 31, failures.gdpr);
        updateMaturity('hipaa', 26, failures.hipaa);
        updateMaturity('iso', 35, failures.iso27001);

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
