import { runScan } from './core/scanner.js';
import { runRemediation } from './core/remediator.js';
import { evaluateWithGemini } from './core/gemini.js';
import { getClientCredentials } from './core/credentials.js';
import { generateReport, sendReport } from './core/reporter.js';
import { Logger } from './core/logger.js';
import { saveAuditLog } from './core/audit.js';
import { updateJobProgress, completeJob } from './core/jobs.js';
import { defaultSecretStore as SecretStore } from './core/secret_store.js';
import { recordAuditEvent } from './core/audit_events.js';
import { persistScanGraph } from './core/execution_worker_hooks.js';

/**
 * Worker Handler
 * Triggered by BullMQ (or legacy SQS event) to process a SINGLE tenant scan and remediation.
 * Writes progressive updates to PostgreSQL jobs table and emits SSE events.
 */
export const handler = async (payload) => {
    // Standardize job payload format
    let jobData = payload;
    if (payload?.Records?.[0]?.body) {
        jobData = typeof payload.Records[0].body === 'string'
            ? JSON.parse(payload.Records[0].body)
            : payload.Records[0].body;
    }

    const { jobId, ...client } = jobData;
    const clientId = client.id || client.clientId || 'adhoc_user';
    const clientName = client.name || clientId;
    const provider = client.provider || 'aws';
    const orgId = client.orgId || client.organizationId || 'org_default';
    const connectionId = client.connectionId || client.id || clientId;

    const executionId = jobId || `exec-${Date.now()}`;

    // Initialize context-aware logger
    const log = new Logger({ clientId, executionId });

    log.info(`➤ WORKER START: Processing tenant ${clientName} (Job: ${jobId || 'untracked'})`);

    // Helper to update job progress if jobId exists
    const trackProgress = async (status, progress, level, message) => {
        if (jobId) await updateJobProgress(jobId, status, progress, level, message);
    };

    try {
        await trackProgress('in_progress', 5, 'SYSTEM', `Worker started for ${clientName}`);

        await recordAuditEvent(orgId, 'system', 'scan_started', 'job', jobId || executionId, {
            provider,
            tenant: clientName
        }).catch(() => {});

        let credentials = {};

        // Step 1: Resolve credentials securely via SecretStore (Amendment 7 & 8)
        if (connectionId) {
            try {
                const stored = await SecretStore.getSecret(orgId, connectionId, 'scan', 'worker_daemon');
                if (stored) {
                    credentials = stored;
                    log.info(`[CREDENTIALS] Retrieved encrypted credentials for connection ${connectionId}`);
                }
            } catch (err) {
                log.warn(`[CREDENTIALS] SecretStore lookup failed for ${connectionId}: ${err.message}`);
                if (process.env.NODE_ENV === 'production') throw err;
            }
        }

        // Fallback for IAM AssumeRole or dev mode
        if (!credentials || Object.keys(credentials).length === 0) {
            if (provider === 'aws' && client.roleArn) {
                log.info(`[CREDENTIALS] Assuming AWS role ${client.roleArn}...`);
                await trackProgress('in_progress', 10, 'AGENT', `Assuming AWS role ${client.roleArn}...`);
                credentials = await getClientCredentials(client.roleArn, clientId, client.externalId);
                log.info(`[CREDENTIALS] ✓ AWS session established.`);
                await trackProgress('in_progress', 15, 'AGENT', '✓ AWS session established.');
            } else if (provider === 'gcp' && client.serviceAccountJson) {
                log.info(`[CREDENTIALS] Loading GCP Service Account...`);
                credentials = { serviceAccountJson: client.serviceAccountJson };
                await trackProgress('in_progress', 15, 'AGENT', 'GCP credentials loaded.');
            } else if (provider === 'azure' && client.tenantId) {
                log.info(`[CREDENTIALS] Loading Azure Service Principal...`);
                credentials = {
                    tenantId: client.tenantId,
                    clientId: client.clientId,
                    clientSecret: client.clientSecret,
                    subscriptionId: client.subscriptionId
                };
                await trackProgress('in_progress', 15, 'AGENT', 'Azure credentials loaded.');
            } else if (client.apiToken) {
                log.info(`[CREDENTIALS] Using ${provider.toUpperCase()} API Token...`);
                credentials = { apiToken: client.apiToken };
                await trackProgress('in_progress', 15, 'AGENT', `${provider.toUpperCase()} credentials loaded.`);
            } else if (client.credentials && process.env.NODE_ENV !== 'production') {
                credentials = client.credentials;
            }
        }

        await trackProgress('in_progress', 15, 'AGENT', `${provider.toUpperCase()} credentials loaded.`);

        // Step 2: Scan
        log.info(`[SCANNER] Executing deep ${provider.toUpperCase()} scan...`);
        await trackProgress('in_progress', 25, 'SYSTEM', `Executing deep ${provider.toUpperCase()} scan...`);

        const { resources } = await runScan(provider, credentials);
        const anomalies = (resources || []).filter(r => r.severity !== 'pass');

        // Persist the actual scan result as durable execution graph state.
        // This is intentionally fail-closed in production: a scan without durable
        // execution evidence must not be reported as successfully completed.
        try {
            await persistScanGraph({
                organizationId: orgId,
                executionId,
                provider,
                resources: resources || []
            });
        } catch (graphError) {
            log.error(`[EXECUTION] Durable graph persistence failed: ${graphError.message}`);
            if (process.env.NODE_ENV === 'production') throw graphError;
        }

        // Support partial success (Amendment 11): if any resource encountered an error, mark as PARTIAL
        const hasErrors = (resources || []).some(r => r.severity === 'error' || r.status === 'ERROR');
        const scanStatus = hasErrors ? 'partial' : 'completed';

        log.info(`[SCANNER] Found ${anomalies.length} anomalies. Status: ${scanStatus}`);
        await trackProgress('in_progress', 50, 'OUTPUT', `Scan ${scanStatus}: ${(resources || []).length} resources, ${anomalies.length} anomalies.`);

        // Log critical findings
        for (const r of anomalies.slice(0, 10)) {
            await trackProgress('in_progress', 52, 'INSIGHT',
                `${r.severity?.toUpperCase()}: ${r.type} "${r.name}" — ${r.issue}`
            );
        }

        // Step 3: Reason & Remediate
        let resolvedCount = 0;
        let escalatedCount = 0;
        const remediationDetails = [];
        const totalAnomalies = anomalies.length;

        for (let i = 0; i < anomalies.length; i++) {
            const anomaly = anomalies[i];
            const progress = 55 + Math.round((i / Math.max(totalAnomalies, 1)) * 25); // 55-80%

            log.info(`[AGENT] Consulting Gemini for ${anomaly.name} (${anomaly.type})...`);
            await trackProgress('in_progress', progress, 'AGENT', `Evaluating ${anomaly.name} with AI reasoning...`);

            const llmDecision = await evaluateWithGemini(anomaly);

            if (llmDecision.action === 'AUTO_FIX' && client.autoRemediate) {
                log.info(`[AGENT] ⚡ EXECUTING AUTO-FIX: ${anomaly.name}`);
                await trackProgress('in_progress', progress, 'ACTION', `⚡ Auto-fixing: ${anomaly.name}`);

                try {
                    const result = await runRemediation(provider, credentials, anomaly.type, anomaly.name, anomaly.issue);
                    if (result.advisory) {
                        log.warn(`[AGENT] Advisory: ${result.message}`);
                        escalatedCount++;
                        remediationDetails.push({ name: anomaly.name, status: 'escalated' });
                        await trackProgress('in_progress', progress, 'INSIGHT', `Advisory for ${anomaly.name}: ${result.message}`);
                    } else {
                        log.audit('REMEDIATE', anomaly.name, 'SUCCESS');
                        resolvedCount++;
                        remediationDetails.push({ name: anomaly.name, status: 'fixed' });
                        await trackProgress('in_progress', progress, 'ACTION', `✓ Fixed: ${anomaly.name}`);
                    }
                } catch (e) {
                    log.error(`[AGENT] Fix failed for ${anomaly.name}:`, e);
                    escalatedCount++;
                    remediationDetails.push({ name: anomaly.name, status: 'failed' });
                    await trackProgress('in_progress', progress, 'INSIGHT', `Fix failed for ${anomaly.name}: ${e.message}`);
                }
            } else {
                log.info(`[AGENT] ⏸ Escalating: ${anomaly.name}`);
                escalatedCount++;
                remediationDetails.push({ name: anomaly.name, status: 'escalated' });
                await trackProgress('in_progress', progress, 'AGENT', `⏸ Escalated: ${anomaly.name} (${llmDecision.reason?.slice(0, 80)})`);
            }
        }

        // Step 4: Save audit log — Fail-closed on evidence persistence failure (Amendment 9)
        log.info(`[REPORTER] Generating results for audit log...`);
        await trackProgress('in_progress', 85, 'SYSTEM', 'Persisting results to audit trail...');

        try {
            await saveAuditLog(clientId, 'SCAN_COMPLETE', `Scan completed for ${clientName}`, {
                resources,
                executionId,
                jobId,
                scanStatus,
                summary: { resolved: resolvedCount, escalated: escalatedCount, details: remediationDetails }
            });
        } catch (auditErr) {
            log.error(`[EVIDENCE] Evidence persistence failed: ${auditErr.message}`);
            if (process.env.NODE_ENV === 'production') {
                throw new Error(`Evidence persistence failure: ${auditErr.message}`);
            }
        }

        await recordAuditEvent(orgId, 'system', 'scan_completed', 'job', jobId || executionId, {
            provider,
            resourcesCount: resources?.length || 0,
            status: scanStatus,
            result: 'success'
        }).catch(() => {});

        // Step 5: Generate & Send Report
        if (client.email) {
            log.info(`[REPORTER] Generating email report for ${client.email}...`);
            await trackProgress('in_progress', 90, 'SYSTEM', 'Generating compliance report...');

            const summary = { resolved: resolvedCount, escalated: escalatedCount, details: remediationDetails };
            const reportHtml = generateReport(clientName, resources, summary);

            await trackProgress('in_progress', 95, 'SYSTEM', `Sending report to ${client.email}...`);
            await sendReport(client.email, clientName, reportHtml);
            log.info(`[REPORTER] ✓ Report delivered to ${client.email}`);
        }

        // Step 6: Complete the job
        if (jobId) {
            await completeJob(jobId, scanStatus, resources);
        }
        log.info(`✨ WORKER COMPLETE for ${clientName}. Status: ${scanStatus}`);
        return { success: true, clientId, jobId, status: scanStatus };

    } catch (e) {
        log.error(`❌ WORKER CRASHED for ${clientName}:`, e);
        if (jobId) await completeJob(jobId, 'failed', [], e.message);

        // Non-retryable errors (e.g. Auth failures, invalid credentials, missing configuration)
        const isNonRetryable = e.message.includes('Authentication Failed') ||
                               e.message.includes('Verification Failed') ||
                               e.message.includes('Missing cloud credentials') ||
                               e.message.includes('invalid') ||
                               e.message.includes('Unauthorized') ||
                               e.isNonRetryable;

        if (isNonRetryable) {
            log.warn(`[WORKER] Non-retryable authentication error detected for ${clientName}. Skipping queue retries.`);
            return { success: false, clientId, jobId, error: e.message };
        }

        throw e;
    }
};
