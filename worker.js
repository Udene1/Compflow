import { runScan } from './core/scanner.js';
import { runRemediation } from './core/remediator.js';
import { evaluateWithGemini } from './core/gemini.js';
import { getClientCredentials } from './core/credentials.js';
import { generateReport, sendReport } from './core/reporter.js';
import { Logger } from './core/logger.js';
import { saveAuditLog } from './core/audit.js';
import { updateJobProgress, completeJob } from './core/jobs.js';

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

        let credentials = client.credentials || {};
        
        // Step 1: Resolve Credentials based on Provider if not pre-provided
        if (!client.credentials || Object.keys(client.credentials).length === 0) {
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
            }
        } else {
            await trackProgress('in_progress', 15, 'AGENT', `${provider.toUpperCase()} credentials loaded.`);
        }

        // Step 2: Scan
        log.info(`[SCANNER] Executing deep ${provider.toUpperCase()} scan...`);
        await trackProgress('in_progress', 25, 'SYSTEM', `Executing deep ${provider.toUpperCase()} scan...`);

        const { resources } = await runScan(provider, credentials);
        const anomalies = (resources || []).filter(r => r.severity !== 'pass');
        log.info(`[SCANNER] Found ${anomalies.length} anomalies.`);
        await trackProgress('in_progress', 50, 'OUTPUT', `Scan complete: ${(resources || []).length} resources, ${anomalies.length} anomalies.`);

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

        // Step 4: Save audit log
        log.info(`[REPORTER] Generating results for audit log...`);
        await trackProgress('in_progress', 85, 'SYSTEM', 'Persisting results to audit trail...');

        await saveAuditLog(clientId, 'SCAN_COMPLETE', `Scan completed for ${clientName}`, { 
            resources, 
            executionId,
            jobId,
            summary: { resolved: resolvedCount, escalated: escalatedCount, details: remediationDetails }
        });

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
            await completeJob(jobId, 'completed', resources);
        }
        log.info(`✨ WORKER COMPLETE for ${clientName}.`);
        return { success: true, clientId, jobId };

    } catch (e) {
        log.error(`❌ WORKER CRASHED for ${clientName}:`, e);
        if (jobId) await completeJob(jobId, 'failed', [], e.message);
        throw e;
    }
};
