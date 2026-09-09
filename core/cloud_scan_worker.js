import crypto from 'crypto';
import { runScan } from './scanner.js';
import { runRemediation } from './remediator.js';
import { evaluateWithGemini } from './gemini.js';
import { getClientCredentials } from './credentials.js';
import { generateReport, sendReport } from './reporter.js';
import { Logger } from './logger.js';
import { saveAuditLog } from './audit.js';
import { updateJobProgress, completeJob } from './jobs.js';
import { defaultSecretStore as SecretStore } from './secret_store.js';
import { recordAuditEvent } from './audit_events.js';
import { persistScanGraph } from './execution_worker_hooks.js';
import pool from './db.js';

async function markScanRunning(scanId) {
    if (!scanId) return;
    await pool.query(`UPDATE scans SET status='RUNNING', started_at=COALESCE(started_at,CURRENT_TIMESTAMP), updated_at=CURRENT_TIMESTAMP WHERE id=$1`, [scanId]);
}

async function persistScanResults({ scanId, organizationId, connectionId, executionId, resources }) {
    if (!scanId) return { findingsCount: 0, evidenceCount: 0 };
    const findings = [];
    for (const resource of resources || []) {
        const severity = String(resource?.severity || resource?.status || '').toUpperCase();
        if (severity === 'PASS' || severity === 'OK' || severity === 'HEALTHY') continue;
        const controls = resource?.controls && typeof resource.controls === 'object' ? resource.controls : {};
        for (const controlIds of Object.values(controls)) {
            if (!Array.isArray(controlIds)) continue;
            for (const controlId of controlIds) {
                const resourceId = resource.id || resource.name || 'unknown-resource';
                const stableKey = `${scanId}:${resourceId}:${controlId}:${resource.technicalId || resource.code || resource.type || 'CLOUD_FINDING'}`;
                const findingId = `finding_${crypto.createHash('sha256').update(stableKey).digest('hex').slice(0, 32)}`;
                findings.push({ id: findingId, organizationId, scanId, resourceId, controlId, severity: String(resource.severity || 'unknown').toUpperCase(), status: 'FAIL', code: resource.technicalId || resource.code || resource.type || 'CLOUD_FINDING' });
            }
        }
    }
    for (const finding of findings) {
        await pool.query(`INSERT INTO findings (id,organization_id,scan_id,resource_id,control_id,severity,status,code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET severity=EXCLUDED.severity, status=EXCLUDED.status, code=EXCLUDED.code`, [finding.id, finding.organizationId, finding.scanId, finding.resourceId, finding.controlId, finding.severity, finding.status, finding.code]);
    }

    // Evidence is persisted by persistScanGraph under the execution context. The
    // durable worker's executionId is normally the jobId, not the scanId.
    const evidenceRes = await pool.query(`SELECT COUNT(*)::int AS count FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 AND connection_id=$3`, [organizationId, executionId, connectionId]);
    const evidenceCount = evidenceRes.rows[0]?.count || 0;
    await pool.query(`UPDATE scans SET status=$1, resources_discovered=$2, findings_count=$3, evidence_count=$4, completed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP, error_code=NULL, error_message=NULL WHERE id=$5`, ['COMPLETED', Array.isArray(resources) ? resources.length : 0, findings.length, evidenceCount, scanId]);
    await pool.query(`UPDATE cloud_connections SET last_scan_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND organization_id=$2`, [connectionId, organizationId]);
    return { findingsCount: findings.length, evidenceCount };
}

async function markScanFailed(scanId, error) {
    if (!scanId) return;
    await pool.query(`UPDATE scans SET status='FAILED', error_code=$1, error_message=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3`, [error?.code || 'SCAN_FAILED', String(error?.message || 'Cloud scan failed').slice(0, 1000), scanId]).catch(() => {});
}

export async function processCloudScanJob(jobData = {}) {
    const { jobId, ...client } = jobData;
    const clientId = client.id || client.clientId || 'adhoc_user';
    const clientName = client.name || clientId;
    const provider = client.provider || 'aws';
    const orgId = client.orgId || client.organizationId || 'org_default';
    const connectionId = client.connectionId || client.id || clientId;
    const scanId = client.scanId || null;
    const executionId = jobId || client.executionId || scanId || `exec-${Date.now()}`;
    const log = new Logger({ clientId, executionId });
    const trackProgress = async (status, progress, level, message) => { if (jobId) await updateJobProgress(jobId, status, progress, level, message); };

    try {
        if (scanId) await markScanRunning(scanId);
        await trackProgress('in_progress', 5, 'SYSTEM', `Worker started for ${clientName}`);
        await recordAuditEvent(orgId, 'system', 'scan_started', 'job', jobId || executionId, { provider, tenant: clientName, scanId }).catch(() => {});

        let credentials = {};
        if (connectionId) {
            try {
                const stored = await SecretStore.getSecret(orgId, connectionId, 'scan', 'worker_daemon');
                if (stored) credentials = stored;
            } catch (err) {
                log.warn(`[CREDENTIALS] SecretStore lookup failed for ${connectionId}: ${err.message}`);
                if (process.env.NODE_ENV === 'production') throw err;
            }
        }
        if (!credentials || Object.keys(credentials).length === 0) {
            if (provider === 'aws' && client.roleArn) {
                await trackProgress('in_progress', 10, 'AGENT', `Assuming AWS role ${client.roleArn}...`);
                credentials = await getClientCredentials(client.roleArn, clientId, client.externalId);
            } else if (provider === 'gcp' && client.serviceAccountJson) credentials = { serviceAccountJson: client.serviceAccountJson };
            else if (provider === 'azure' && client.tenantId) credentials = { tenantId: client.tenantId, clientId: client.clientId, clientSecret: client.clientSecret, subscriptionId: client.subscriptionId };
            else if (client.apiToken) credentials = { apiToken: client.apiToken };
            else if (client.credentials && process.env.NODE_ENV !== 'production') credentials = client.credentials;
        }
        await trackProgress('in_progress', 15, 'AGENT', `${provider.toUpperCase()} credentials loaded.`);
        await trackProgress('in_progress', 25, 'SYSTEM', `Executing deep ${provider.toUpperCase()} scan...`);
        const { resources } = await runScan(provider, credentials);
        const anomalies = (resources || []).filter(resource => resource.severity !== 'pass');
        if (scanId) await persistScanResults({ scanId, organizationId: orgId, connectionId, executionId, resources: resources || [] });
        else await persistScanGraph({ organizationId: orgId, executionId, provider, connectionId, resources: resources || [] });

        const hasErrors = (resources || []).some(resource => resource.severity === 'error' || resource.status === 'ERROR');
        const scanStatus = hasErrors ? 'partial' : 'completed';
        if (scanId && hasErrors) await pool.query(`UPDATE scans SET status='PARTIAL', resources_discovered=$1, updated_at=CURRENT_TIMESTAMP WHERE id=$2`, [resources?.length || 0, scanId]);
        await trackProgress('in_progress', 50, 'OUTPUT', `Scan ${scanStatus}: ${(resources || []).length} resources, ${anomalies.length} anomalies.`);
        for (const resource of anomalies.slice(0, 10)) await trackProgress('in_progress', 52, 'INSIGHT', `${resource.severity?.toUpperCase()}: ${resource.type} "${resource.name}" — ${resource.issue}`);

        let resolvedCount = 0; let escalatedCount = 0; const remediationDetails = []; const totalAnomalies = anomalies.length;
        for (let i = 0; i < anomalies.length; i++) {
            const anomaly = anomalies[i]; const progress = 55 + Math.round((i / Math.max(totalAnomalies, 1)) * 25);
            await trackProgress('in_progress', progress, 'AGENT', `Evaluating ${anomaly.name} with AI reasoning...`);
            const llmDecision = await evaluateWithGemini(anomaly);
            if (llmDecision.action === 'AUTO_FIX' && client.autoRemediate) {
                await trackProgress('in_progress', progress, 'ACTION', `Auto-fixing: ${anomaly.name}`);
                try {
                    const result = await runRemediation(provider, credentials, anomaly.type, anomaly.name, anomaly.issue);
                    if (result.advisory) { escalatedCount++; remediationDetails.push({ name: anomaly.name, status: 'escalated' }); }
                    else { resolvedCount++; remediationDetails.push({ name: anomaly.name, status: 'fixed' }); }
                } catch (error) { escalatedCount++; remediationDetails.push({ name: anomaly.name, status: 'failed' }); log.error(`[AGENT] Fix failed for ${anomaly.name}:`, error); }
            } else {
                escalatedCount++; remediationDetails.push({ name: anomaly.name, status: 'escalated' });
                await trackProgress('in_progress', progress, 'AGENT', `Escalated: ${anomaly.name} (${llmDecision.reason?.slice(0, 80) || 'requires review'})`);
            }
        }
        await trackProgress('in_progress', 85, 'SYSTEM', 'Persisting results to audit trail...');
        await saveAuditLog(clientId, 'SCAN_COMPLETE', `Scan completed for ${clientName}`, { resources, executionId, jobId, scanId, scanStatus, summary: { resolved: resolvedCount, escalated: escalatedCount, details: remediationDetails } });
        await recordAuditEvent(orgId, 'system', 'scan_completed', 'job', jobId || executionId, { provider, scanId, resourcesCount: resources?.length || 0, status: scanStatus, result: 'success' }).catch(() => {});
        if (client.email) { await trackProgress('in_progress', 90, 'SYSTEM', 'Generating compliance report...'); const summary = { resolved: resolvedCount, escalated: escalatedCount, details: remediationDetails }; const reportHtml = generateReport(clientName, resources, summary); await trackProgress('in_progress', 95, 'SYSTEM', `Sending report to ${client.email}...`); await sendReport(client.email, clientName, reportHtml); }
        if (jobId) await completeJob(jobId, scanStatus, resources);
        return { success: true, clientId, jobId, scanId, status: scanStatus };
    } catch (error) {
        log.error(`Worker failed for ${clientName}:`, error);
        await markScanFailed(scanId, error);
        if (jobId) await completeJob(jobId, 'failed', [], error.message);
        const message = String(error?.message || '');
        const isNonRetryable = message.includes('Authentication Failed') || message.includes('Verification Failed') || message.includes('Missing cloud credentials') || message.includes('invalid') || message.includes('Unauthorized') || error?.isNonRetryable;
        if (isNonRetryable) return { success: false, clientId, jobId, scanId, error: message };
        throw error;
    }
}