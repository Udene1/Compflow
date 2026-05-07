// ─── ComplianceFlow AI: Drift Engine ───
// Monitors cloud resources for configuration drift and triggers auto-rollback

window.DriftEngine = (() => {
    let monitoringInterval = null;
    let isAutopilotEnabled = false;
    let baselineState = [];

    function init() {
        console.log("Drift Engine Initialized");
    }

    function toggleAutopilot(enabled) {
        isAutopilotEnabled = enabled;
        if (enabled) {
            startMonitoring();
            LiveTerminal.log('system', 'GOVERNANCE AUTOPILOT: ENABLED. Monitoring for drift...');
        } else {
            stopMonitoring();
            LiveTerminal.log('system', 'GOVERNANCE AUTOPILOT: DISABLED.');
        }
    }

    function startMonitoring() {
        if (monitoringInterval) return;
        
        // Take initial baseline if empty
        if (baselineState.length === 0 && window.Scanner) {
            baselineState = JSON.parse(JSON.stringify(Scanner.getResources() || []));
        }

        monitoringInterval = setInterval(async () => {
            if (!isAutopilotEnabled) return;
            await checkDrift();
        }, 15000); // Poll every 15 seconds
    }

    function stopMonitoring() {
        if (monitoringInterval) {
            clearInterval(monitoringInterval);
            monitoringInterval = null;
        }
    }

    async function checkDrift() {
        if (!window.Scanner || !window.CloudConnect) return;
        
        // Only run if connected
        const providers = CloudConnect.getProviders();
        if (providers.length === 0) return;

        // Perform a silent background scan
        LiveTerminal.log('system', 'Drift Check: Inspecting cloud resources...');
        
        // Use the scanner's existing logic but in background
        const currentResources = await Scanner.runBackgroundScan();
        
        if (!currentResources) return;

        const drifts = findDrifts(baselineState, currentResources);

        if (drifts.length > 0) {
            LiveTerminal.log('insight', `DRIFT DETECTED: ${drifts.length} resource(s) deviated from policy.`);
            handleDrifts(drifts);
        } else {
            // Update baseline to match current state if everything is passing
            // This ensures we don't trigger drift on intentional remediations
            baselineState = JSON.parse(JSON.stringify(currentResources));
        }
    }

    function findDrifts(baseline, current) {
        const drifts = [];
        current.forEach(curr => {
            const base = baseline.find(b => b.id === curr.id);
            // We care about "Pass -> Fail" transitions that weren't triggered by our remediation
            if (base && base.severity === 'pass' && curr.severity !== 'pass') {
                drifts.push(curr);
            }
        });
        return drifts;
    }

    async function handleDrifts(drifts) {
        for (const drift of drifts) {
            LiveTerminal.log('action', `AUTOPILOT ROLLBACK: Re-applying policy to ${drift.type} "${drift.name}"`);
            
            // Trigger auto-fix
            if (window.Remediation) {
                try {
                    await Remediation.fixSingle(drift.id);
                } catch (e) {
                    LiveTerminal.log('insight', `AUTO-FIX FAILED: ${e.message}`);
                }
            }
        }
        
        // Refresh Scanner UI to show fixed state
        if (window.Scanner) Scanner.updateScore();
    }

    function setBaseline(resources) {
        baselineState = JSON.parse(JSON.stringify(resources));
    }

    return { init, toggleAutopilot, checkDrift, setBaseline };
})();
