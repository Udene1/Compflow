// ─── ComplianceFlow AI: Resource Scanner ───
// Triggers the durable server-side scan pipeline. Cloud secrets never leave SecretStore.

window.Scanner = (() => {
    let scannedResources = [];

    function init() {
        const btn = document.getElementById('btn-start-scan');
        if (btn) btn.addEventListener('click', startScan);
    }

    function apiErrorMessage(response, data) {
        if (data?.message) return data.message;
        if (data?.error) return data.error;
        return `Request failed (${response.status}).`;
    }

    async function startScan() {
        if (!CloudConnect.isConnected()) {
            LiveTerminal.log('insight', 'ERROR: No verified cloud provider connected. Complete Cloud Connect first.');
            return;
        }
        const provider = CloudConnect.getProviders()[0];
        const connectionId = CloudConnect.getConnectionId(provider);
        if (!connectionId) {
            LiveTerminal.log('insight', 'ERROR: No durable cloud connection is available. Reconnect the environment.');
            return;
        }

        const btn = document.getElementById('btn-start-scan');
        const now = Date.now();
        const COOLDOWN = 60000;
        if (window._lastScanTime && now - window._lastScanTime < COOLDOWN) {
            const remaining = Math.ceil((COOLDOWN - (now - window._lastScanTime)) / 1000);
            LiveTerminal.log('system', `Scan throttled. Try again in ${remaining}s.`);
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Analyzing your perimeter...';
        window._lastScanTime = now;
        scannedResources = [];
        document.getElementById('resource-tbody').innerHTML = '';
        document.getElementById('scan-empty').style.display = 'none';
        document.getElementById('resource-table').style.display = 'table';
        document.getElementById('scan-stats').style.display = 'grid';
        document.getElementById('scan-progress-wrap').style.display = 'block';
        document.getElementById('scan-progress-fill').style.width = '5%';

        LiveTerminal.log('system', `Contacting real cloud APIs for ${provider.toUpperCase()}...`);
        LiveTerminal.log('system', 'Consulting the durable cloud scan engine...');

        const BASE_URL = window.COMPLIANCE_API_URL;
        try {
            const fetchFn = (window.AuthUI && window.AuthUI.authFetch) ? window.AuthUI.authFetch : fetch;
            const triggerRes = await fetchFn(`${BASE_URL}/api/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, connectionId, clientId: 'adhoc_user' })
            });
            const triggerData = await triggerRes.json().catch(() => ({}));
            if (!triggerRes.ok) throw new Error(apiErrorMessage(triggerRes, triggerData));

            const jobId = triggerData.jobId;
            if (!jobId) throw new Error('The scan API did not return a durable job ID.');
            LiveTerminal.log('system', `Scan job created (ID: ${jobId.slice(0, 8)}...). Streaming progress...`);

            const results = await streamJobStatus(jobId, BASE_URL);
            if (!results) throw new Error('Scan timed out or failed on backend.');
            scannedResources = results;
            document.getElementById('scan-progress-fill').style.width = '100%';
            await displayResults(scannedResources);

            const stepScan = document.getElementById('step-scan');
            if (stepScan) { stepScan.classList.add('completed'); const numEl = document.getElementById('step-scan-num'); if (numEl) numEl.textContent = '✓'; }
            const stepEvidence = document.getElementById('step-evidence');
            if (stepEvidence) stepEvidence.classList.add('ready');
            const progressBadge = document.getElementById('checklist-progress-text');
            if (progressBadge) progressBadge.textContent = '3 of 4 Steps Complete';
            if (window.AuthUI?.setMode) window.AuthUI.setMode('app');
        } catch (err) {
            console.error(err);
            LiveTerminal.log('insight', `SCAN FAILED: ${err.message}`);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Run scan';
        }
    }

    function streamJobStatus(jobId, baseUrl) {
        return new Promise((resolve, reject) => {
            const streamUrl = `${baseUrl}/api/job-stream?jobId=${encodeURIComponent(jobId)}`;
            const eventSource = new EventSource(streamUrl, { withCredentials: true });
            let logIndex = 0;
            let receivedMessage = false;
            const fallbackTimer = setTimeout(() => {
                if (!receivedMessage) {
                    pollJobStatus(jobId, baseUrl, logIndex).then(res => { eventSource.close(); resolve(res); }).catch(err => { eventSource.close(); reject(err); });
                }
            }, 2000);

            eventSource.onmessage = event => {
                receivedMessage = true;
                clearTimeout(fallbackTimer);
                try {
                    const data = JSON.parse(event.data);
                    if (data.logs && data.logs.length > logIndex) logIndex = LiveTerminal.logBatch(data.logs, logIndex);
                    else if (data.newLog) logIndex = LiveTerminal.logBatch([data.newLog], 0);
                    if (typeof data.progress === 'number' && data.progress > 0) document.getElementById('scan-progress-fill').style.width = `${Math.min(data.progress, 99)}%`;
                    if (data.status === 'completed' || data.status === 'partial') { eventSource.close(); resolve(data.resources || []); }
                    else if (data.status === 'failed') { eventSource.close(); reject(new Error(data.errorMessage || 'Scan failed on backend.')); }
                } catch (err) { console.error('[SSE] Error parsing event:', err); }
            };
            eventSource.onerror = () => {
                clearTimeout(fallbackTimer);
                eventSource.close();
                pollJobStatus(jobId, baseUrl, logIndex).then(resolve).catch(reject);
            };
        });
    }

    async function pollJobStatus(jobId, baseUrl, initialLogIndex = 0) {
        const MAX_POLL_MS = 15 * 60 * 1000;
        const POLL_INTERVAL = 3000;
        const start = Date.now();
        let logIndex = initialLogIndex;
        while (Date.now() - start < MAX_POLL_MS) {
            await new Promise(r => setTimeout(r, POLL_INTERVAL));
            const fetchFn = (window.AuthUI && window.AuthUI.authFetch) ? window.AuthUI.authFetch : fetch;
            const res = await fetchFn(`${baseUrl}/api/job-status?jobId=${encodeURIComponent(jobId)}`);
            const job = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(apiErrorMessage(res, job));
            if (job.logs && job.logs.length > logIndex) logIndex = LiveTerminal.logBatch(job.logs, logIndex);
            if (job.progress > 0) document.getElementById('scan-progress-fill').style.width = `${Math.min(job.progress, 99)}%`;
            if (job.status === 'completed' || job.status === 'partial') return job.resources || [];
            if (job.status === 'failed') throw new Error(job.errorMessage || 'Scan failed on backend.');
        }
        return null;
    }

    async function displayResults(resources) {
        document.getElementById('resource-tbody').innerHTML = '';
        for (const [i, res] of resources.entries()) {
            res.id = i;
            const controlKeys = Frameworks.getMapping(res.type, res.issue);
            res.controlKeys = controlKeys;
            const activeControlKey = controlKeys.find(k => k.startsWith(Frameworks.getCurrentId())) || controlKeys[0];
            const controlDetail = Frameworks.getControlDetails(activeControlKey);
            res.control = controlDetail ? controlDetail.id : 'N/A';
            addResourceRow(res);
            if (window.Evidence) await Evidence.captureFromScan(res);
            if (res.severity === 'critical') LiveTerminal.log('insight', `CRITICAL: ${res.type} "${res.name}" — ${res.issue}`);
            else if (res.severity === 'warning') LiveTerminal.log('agent', `Warning: ${res.type} "${res.name}" — ${res.issue}`);
        }
        LiveTerminal.log('output', `Scan complete: ${resources.length} resources found.`);
        updateStatsUI(); updateScore();
        if (window.CloudConnect) CloudConnect.updateChips();
        if (window.DriftEngine) DriftEngine.setBaseline(resources);
        if (window.Remediation) Remediation.buildFromScan(resources);
        if (window.Evidence) Evidence.refreshView();
    }

    function getScannedResources() { return scannedResources; }
    function getCounts() { const total = scannedResources.length; return { total, pass: scannedResources.filter(r => r.severity === 'pass').length, warn: scannedResources.filter(r => r.severity === 'warning').length, crit: scannedResources.filter(r => r.severity === 'critical').length }; }
    function updateStatsUI() { const counts = getCounts(); const ids = [['stat-total', counts.total], ['stat-pass', counts.pass], ['stat-warn', counts.warn], ['stat-crit', counts.crit]]; ids.forEach(([id, value]) => { const el = document.getElementById(id); if (el) el.textContent = value; }); }
    function updateScore() { return; }
    function addResourceRow(res) { const tbody = document.getElementById('resource-tbody'); if (!tbody) return; const tr = document.createElement('tr'); tr.className = 'resource-row'; tr.innerHTML = `<td><div class="resource-name">${res.icon || ''} ${res.name || 'Resource'}</div><div style="font-size:.72rem;color:var(--text-dim);margin-top:2px;">${res.issue || 'No issues'}</div></td><td><span class="resource-type">${res.type || 'UNKNOWN'}</span></td><td style="color:var(--text-muted);font-size:.82rem;">${res.region || '—'}</td><td><span class="severity-badge">${res.severity || 'unknown'}</span></td><td><div class="control-badges-wrap">${res.control || 'N/A'}</div></td>`; tbody.appendChild(tr); }

    document.addEventListener('DOMContentLoaded', init);
    return { init, startScan, getScannedResources };
})();