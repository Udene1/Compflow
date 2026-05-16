// ─── ComplianceFlow AI: Drift Engine ───
// Monitors cloud resources for configuration drift, differential reporting,
// and triggers auto-rollback with notification dispatch.

window.DriftEngine = (() => {
    let monitoringInterval = null;
    let isAutopilotEnabled = false;
    let baselineState = [];
    let scanHistory = [];
    let scheduleInterval = 15000; // Default: 15 seconds (demo), configurable

    const SCHEDULE_OPTIONS = {
        '15s': 15000,       // Demo mode
        '5m': 300000,       // 5 minutes
        '30m': 1800000,     // 30 minutes  
        '1h': 3600000,      // 1 hour
        '6h': 21600000,     // 6 hours
        '12h': 43200000,    // 12 hours
        '24h': 86400000     // 24 hours
    };

    function init() {
        console.log("Drift Engine v2 Initialized — Continuous Monitoring Ready");
    }

    function setSchedule(key) {
        if (SCHEDULE_OPTIONS[key]) {
            scheduleInterval = SCHEDULE_OPTIONS[key];
            LiveTerminal.log('system', `Monitoring interval set to ${key}.`);
            
            // Restart monitoring if active
            if (monitoringInterval) {
                stopMonitoring();
                startMonitoring();
            }
        }
    }

    function toggleAutopilot(enabled) {
        isAutopilotEnabled = enabled;
        if (enabled) {
            startMonitoring();
            LiveTerminal.log('system', 'GOVERNANCE AUTOPILOT: ENABLED. Continuous monitoring active.');
            if (window.showToast) showToast('🔄 Continuous Monitoring Active');
        } else {
            stopMonitoring();
            LiveTerminal.log('system', 'GOVERNANCE AUTOPILOT: DISABLED.');
            if (window.showToast) showToast('⏸ Monitoring Paused');
        }
        updateMonitorUI();
    }

    function startMonitoring() {
        if (monitoringInterval) return;
        
        // Take initial baseline if empty
        if (baselineState.length === 0 && window.Scanner) {
            baselineState = JSON.parse(JSON.stringify(Scanner.getResources() || []));
            recordSnapshot('baseline');
        }

        monitoringInterval = setInterval(async () => {
            if (!isAutopilotEnabled) return;
            await checkDrift();
        }, scheduleInterval);
    }

    function stopMonitoring() {
        if (monitoringInterval) {
            clearInterval(monitoringInterval);
            monitoringInterval = null;
        }
    }

    async function checkDrift() {
        if (!window.Scanner || !window.CloudConnect) return;
        
        const providers = CloudConnect.getProviders();
        if (providers.length === 0) return;

        LiveTerminal.log('system', `[${new Date().toLocaleTimeString()}] Drift Check: Scanning resources...`);
        
        const currentResources = await Scanner.runBackgroundScan();
        if (!currentResources) return;

        const diff = computeDiff(baselineState, currentResources);
        const snapshot = recordSnapshot('scheduled', currentResources, diff);

        if (diff.regressions.length > 0 || diff.newIssues.length > 0) {
            // Critical drift detected
            LiveTerminal.log('insight', `🚨 DRIFT DETECTED: ${diff.regressions.length} regression(s), ${diff.newIssues.length} new issue(s).`);
            
            if (window.showToast) {
                showToast(`🚨 Drift: ${diff.regressions.length + diff.newIssues.length} change(s) detected`);
            }

            // Auto-remediate regressions if autopilot is enabled
            for (const regression of diff.regressions) {
                LiveTerminal.log('action', `AUTOPILOT ROLLBACK: Re-applying policy to ${regression.type} "${regression.name}"`);
                if (window.Remediation) {
                    try {
                        await Remediation.fixSingle(regression.id);
                    } catch (e) {
                        LiveTerminal.log('insight', `AUTO-FIX FAILED: ${e.message}`);
                    }
                }
            }
        } else if (diff.resolvedIssues.length > 0) {
            LiveTerminal.log('output', `✅ ${diff.resolvedIssues.length} issue(s) resolved since last scan.`);
        } else {
            LiveTerminal.log('output', `✓ No drift detected. Infrastructure stable.`);
        }

        // Update baseline to current state
        baselineState = JSON.parse(JSON.stringify(currentResources));
        
        // Refresh Scanner UI
        if (window.Scanner) Scanner.updateScore();
        updateMonitorUI();
    }

    /**
     * Compute differential between two resource snapshots.
     */
    function computeDiff(previous, current) {
        const prevMap = new Map(previous.map(r => [(r.name || '') + ':' + (r.type || ''), r]));
        const currMap = new Map(current.map(r => [(r.name || '') + ':' + (r.type || ''), r]));

        const newIssues = [];
        const resolvedIssues = [];
        const regressions = [];

        for (const [key, curr] of currMap) {
            const prev = prevMap.get(key);
            if (!prev) {
                if (curr.severity !== 'pass') newIssues.push(curr);
            } else if (prev.severity === 'pass' && curr.severity !== 'pass') {
                regressions.push(curr);
            }
        }

        for (const [key, prev] of prevMap) {
            const curr = currMap.get(key);
            if (prev.severity !== 'pass' && (!curr || curr.severity === 'pass')) {
                resolvedIssues.push(prev);
            }
        }

        return { newIssues, resolvedIssues, regressions };
    }

    function recordSnapshot(trigger, resources, diff) {
        const snapshot = {
            timestamp: new Date().toISOString(),
            trigger,
            total: resources ? resources.length : baselineState.length,
            passing: (resources || baselineState).filter(r => r.severity === 'pass').length,
            failing: (resources || baselineState).filter(r => r.severity !== 'pass').length,
            diff: diff || null
        };
        scanHistory.push(snapshot);
        if (scanHistory.length > 100) scanHistory.shift();
        return snapshot;
    }

    function updateMonitorUI() {
        const badge = document.getElementById('monitor-status');
        if (badge) {
            badge.textContent = isAutopilotEnabled ? '● LIVE' : '○ OFF';
            badge.className = 'monitor-badge ' + (isAutopilotEnabled ? 'active' : '');
        }

        const historyEl = document.getElementById('monitor-history');
        if (historyEl && scanHistory.length > 0) {
            const recent = scanHistory.slice(-5).reverse();
            historyEl.innerHTML = recent.map(s => `
                <div class="monitor-entry">
                    <span class="ts">${new Date(s.timestamp).toLocaleTimeString()}</span>
                    <span class="trigger">${s.trigger}</span>
                    <span class="stats">✓${s.passing} ✕${s.failing}</span>
                    ${s.diff ? `<span class="diff-badge ${s.diff.regressions.length > 0 ? 'danger' : s.diff.resolvedIssues.length > 0 ? 'success' : ''}">${s.diff.regressions.length > 0 ? '↻' + s.diff.regressions.length : s.diff.resolvedIssues.length > 0 ? '✓' + s.diff.resolvedIssues.length : '—'}</span>` : ''}
                </div>
            `).join('');
        }
    }

    function setBaseline(resources) {
        baselineState = JSON.parse(JSON.stringify(resources));
        recordSnapshot('manual_baseline');
    }

    function getHistory() { return scanHistory; }
    function isActive() { return isAutopilotEnabled; }

    return { init, toggleAutopilot, checkDrift, setBaseline, setSchedule, getHistory, isActive };
})();
