import { log } from '../../core/logger.js';

/**
 * Continuous Monitoring Cron Handler
 * Triggered on schedule to run differential compliance scans.
 * Detects drift from the last known baseline and dispatches alerts.
 */

// In-memory scan history (in production, use DynamoDB/Redis)
let scanHistory = [];
const MAX_HISTORY = 50;

export default async function handler(req, res) {
    const authHeader = req.headers['authorization'];
    if (process.env.NODE_ENV === 'production' && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    log.info("[MONITOR] Starting Continuous Monitoring Cycle...");

    try {
        // 1. Get the last scan baseline (if any)
        const lastScan = scanHistory.length > 0 ? scanHistory[scanHistory.length - 1] : null;

        // 2. Run current scan via the orchestrator
        const { orchestratorLoop } = await import('../../agent.js');
        const currentResults = await orchestratorLoop();

        const now = new Date().toISOString();
        const currentSnapshot = {
            timestamp: now,
            totalResources: currentResults?.resources?.length || 0,
            passing: currentResults?.resources?.filter(r => r.severity === 'pass').length || 0,
            warnings: currentResults?.resources?.filter(r => r.severity === 'warning').length || 0,
            critical: currentResults?.resources?.filter(r => r.severity === 'critical').length || 0,
            resources: currentResults?.resources || []
        };

        // 3. Differential Analysis
        let diff = { newIssues: [], resolvedIssues: [], regressions: [], unchanged: 0 };

        if (lastScan) {
            diff = computeDiff(lastScan, currentSnapshot);
            log.info(`[MONITOR] Diff: +${diff.newIssues.length} new, -${diff.resolvedIssues.length} resolved, ↻${diff.regressions.length} regressions`);
        } else {
            log.info("[MONITOR] First scan — establishing baseline.");
        }

        // 4. Store snapshot
        scanHistory.push(currentSnapshot);
        if (scanHistory.length > MAX_HISTORY) scanHistory.shift();

        // 5. Dispatch drift alert if critical changes detected
        let alertSent = false;
        if (diff.newIssues.length > 0 || diff.regressions.length > 0) {
            alertSent = await dispatchDriftAlert(diff, currentSnapshot);
        }

        res.status(200).json({
            success: true,
            timestamp: now,
            snapshot: {
                total: currentSnapshot.totalResources,
                passing: currentSnapshot.passing,
                warnings: currentSnapshot.warnings,
                critical: currentSnapshot.critical
            },
            diff: {
                newIssues: diff.newIssues.length,
                resolved: diff.resolvedIssues.length,
                regressions: diff.regressions.length
            },
            alertSent,
            historyDepth: scanHistory.length
        });

    } catch (error) {
        log.error("[MONITOR] Monitoring cycle failed:", error);
        res.status(500).json({ error: error.message });
    }
}

/**
 * Compute differential between two scan snapshots.
 */
function computeDiff(previous, current) {
    const prevMap = new Map(previous.resources.map(r => [r.name + ':' + r.type, r]));
    const currMap = new Map(current.resources.map(r => [r.name + ':' + r.type, r]));

    const newIssues = [];
    const resolvedIssues = [];
    const regressions = [];
    let unchanged = 0;

    // Check current resources against previous baseline
    for (const [key, curr] of currMap) {
        const prev = prevMap.get(key);

        if (!prev) {
            // Brand new resource that wasn't in previous scan
            if (curr.severity !== 'pass') {
                newIssues.push({
                    name: curr.name,
                    type: curr.type,
                    severity: curr.severity,
                    issue: curr.issue,
                    category: 'new_resource'
                });
            }
        } else if (prev.severity === 'pass' && curr.severity !== 'pass') {
            // REGRESSION: was passing, now failing
            regressions.push({
                name: curr.name,
                type: curr.type,
                previousSeverity: prev.severity,
                currentSeverity: curr.severity,
                issue: curr.issue,
                category: 'regression'
            });
        } else if (prev.severity !== 'pass' && curr.severity !== 'pass' && prev.issue !== curr.issue) {
            // Issue changed (still failing but different reason)
            newIssues.push({
                name: curr.name,
                type: curr.type,
                severity: curr.severity,
                issue: curr.issue,
                previousIssue: prev.issue,
                category: 'changed'
            });
        } else {
            unchanged++;
        }
    }

    // Check for resolved issues (in previous but now passing or removed)
    for (const [key, prev] of prevMap) {
        const curr = currMap.get(key);
        if (prev.severity !== 'pass' && (!curr || curr.severity === 'pass')) {
            resolvedIssues.push({
                name: prev.name,
                type: prev.type,
                previousSeverity: prev.severity,
                issue: prev.issue,
                category: 'resolved'
            });
        }
    }

    return { newIssues, resolvedIssues, regressions, unchanged };
}

/**
 * Dispatch drift alert via email (uses existing SES mailer).
 */
async function dispatchDriftAlert(diff, snapshot) {
    try {
        const { sendComplianceReport } = await import('../../core/mailer.js');
        const recipientEmail = process.env.DRIFT_ALERT_EMAIL || process.env.AWS_SES_FROM_EMAIL;

        if (!recipientEmail) {
            log.warn("[MONITOR] No DRIFT_ALERT_EMAIL configured. Skipping alert.");
            return false;
        }

        const criticalCount = diff.regressions.filter(r => r.currentSeverity === 'critical').length + 
                              diff.newIssues.filter(r => r.severity === 'critical').length;

        const subject = criticalCount > 0
            ? `🚨 CRITICAL DRIFT: ${criticalCount} critical issue(s) detected`
            : `⚠️ Compliance Drift: ${diff.newIssues.length + diff.regressions.length} change(s) detected`;

        const alertHtml = buildDriftAlertEmail(diff, snapshot, subject);

        await sendComplianceReport(recipientEmail, subject, alertHtml);
        log.info(`[MONITOR] Drift alert sent to ${recipientEmail}`);
        return true;
    } catch (e) {
        log.error("[MONITOR] Failed to send drift alert:", e);
        return false;
    }
}

function buildDriftAlertEmail(diff, snapshot, subject) {
    const regressionRows = diff.regressions.map(r => `
        <tr>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.name}</td>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.type}</td>
            <td style="padding:8px;border-bottom:1px solid #333;color:#ef4444;">↻ ${r.previousSeverity} → ${r.currentSeverity}</td>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.issue}</td>
        </tr>`).join('');

    const newIssueRows = diff.newIssues.map(r => `
        <tr>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.name}</td>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.type}</td>
            <td style="padding:8px;border-bottom:1px solid #333;color:#f59e0b;">NEW</td>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.issue}</td>
        </tr>`).join('');

    const resolvedRows = diff.resolvedIssues.map(r => `
        <tr>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.name}</td>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.type}</td>
            <td style="padding:8px;border-bottom:1px solid #333;color:#10b981;">✓ RESOLVED</td>
            <td style="padding:8px;border-bottom:1px solid #333;">${r.issue}</td>
        </tr>`).join('');

    return `
    <div style="background:#0a0a1a;color:#e2e8f0;font-family:'Inter',sans-serif;padding:2rem;max-width:700px;margin:0 auto;">
        <div style="border-bottom:2px solid #6366f1;padding-bottom:1rem;margin-bottom:1.5rem;">
            <h1 style="margin:0;font-size:1.3rem;">🛡️ ComplianceFlow Drift Alert</h1>
            <p style="color:#94a3b8;margin:0.5rem 0 0;font-size:0.85rem;">${new Date().toUTCString()}</p>
        </div>

        <div style="display:flex;gap:1rem;margin-bottom:1.5rem;">
            <div style="flex:1;background:#1e1e3a;padding:1rem;border-radius:12px;text-align:center;">
                <div style="font-size:2rem;font-weight:800;color:#ef4444;">${diff.regressions.length}</div>
                <div style="font-size:0.75rem;color:#94a3b8;">REGRESSIONS</div>
            </div>
            <div style="flex:1;background:#1e1e3a;padding:1rem;border-radius:12px;text-align:center;">
                <div style="font-size:2rem;font-weight:800;color:#f59e0b;">${diff.newIssues.length}</div>
                <div style="font-size:0.75rem;color:#94a3b8;">NEW ISSUES</div>
            </div>
            <div style="flex:1;background:#1e1e3a;padding:1rem;border-radius:12px;text-align:center;">
                <div style="font-size:2rem;font-weight:800;color:#10b981;">${diff.resolvedIssues.length}</div>
                <div style="font-size:0.75rem;color:#94a3b8;">RESOLVED</div>
            </div>
        </div>

        ${regressionRows ? `
        <h3 style="color:#ef4444;margin-top:1.5rem;">↻ Security Regressions</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.85rem;">
            <thead><tr style="color:#94a3b8;text-align:left;">
                <th style="padding:8px;">Resource</th><th style="padding:8px;">Type</th><th style="padding:8px;">Status</th><th style="padding:8px;">Issue</th>
            </tr></thead>
            <tbody>${regressionRows}</tbody>
        </table>` : ''}

        ${newIssueRows ? `
        <h3 style="color:#f59e0b;margin-top:1.5rem;">🆕 New Issues</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.85rem;">
            <thead><tr style="color:#94a3b8;text-align:left;">
                <th style="padding:8px;">Resource</th><th style="padding:8px;">Type</th><th style="padding:8px;">Status</th><th style="padding:8px;">Issue</th>
            </tr></thead>
            <tbody>${newIssueRows}</tbody>
        </table>` : ''}

        ${resolvedRows ? `
        <h3 style="color:#10b981;margin-top:1.5rem;">✓ Resolved Since Last Scan</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.85rem;">
            <thead><tr style="color:#94a3b8;text-align:left;">
                <th style="padding:8px;">Resource</th><th style="padding:8px;">Type</th><th style="padding:8px;">Status</th><th style="padding:8px;">Issue</th>
            </tr></thead>
            <tbody>${resolvedRows}</tbody>
        </table>` : ''}

        <div style="margin-top:2rem;padding-top:1rem;border-top:1px solid #333;font-size:0.75rem;color:#64748b;">
            ComplianceFlow AI-Native Governance Engine — Continuous Monitoring Service<br>
            Posture: ${snapshot.passing}/${snapshot.totalResources} passing | ${snapshot.critical} critical | ${snapshot.warnings} warnings
        </div>
    </div>`;
}
