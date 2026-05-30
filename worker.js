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
 * Triggered by SQS to process a SINGLE tenant scan and remediation.
 * Writes progressive updates to the Jobs table.
 */
export const handler = async (event) => {
    // 1. Parse SQS Message (BatchSize is 1)
    const messageBody = JSON.parse(event.Records[0].body);
    const { jobId, ...client } = messageBody;
    const executionId = event.Records[0].messageId;
    
    // Initialize context-aware logger
    const log = new Logger({ clientId: client.id, executionId });

    log.info(`➤ WORKER START: Processing tenant ${client.name} (Job: ${jobId || 'untracked'})`);

    // Helper to update job if jobId exists
    const trackProgress = async (status, progress, level, message) => {
        if (jobId) await updateJobProgress(jobId, status, progress, level, message);
    };

    try {
        await trackProgress('in_progress', 5, 'SYSTEM', `Worker started for ${client.name}`);

        let credentials = {};
        
        // Step 1: Resolve Credentials based on Provider
        if (client.provider === 'aws') {
            log.info(`[CREDENTIALS] Assuming AWS role ${client.roleArn}...`);
            await trackProgress('in_progress', 10, 'AGENT', `Assuming AWS role ${client.roleArn}...`);
            credentials = await getClientCredentials(client.roleArn, client.id);
            log.info(`[CREDENTIALS] ✓ AWS session established.`);
            await trackProgress('in_progress', 15, 'AGENT', '✓ AWS session established.');
        } else if (client.provider === 'gcp') {
            log.info(`[CREDENTIALS] Loading GCP Service Account...`);
            credentials = { serviceAccountJson: client.serviceAccountJson };
            await trackProgress('in_progress', 15, 'AGENT', 'GCP credentials loaded.');
        } else if (client.provider === 'azure') {
            log.info(`[CREDENTIALS] Loading Azure Service Principal...`);
            credentials = { 
                tenantId: client.tenantId, 
                clientId: client.clientId, 
                clientSecret: client.clientSecret, 
                subscriptionId: client.subscriptionId 
            };
            await trackProgress('in_progress', 15, 'AGENT', 'Azure credentials loaded.');
        } else {
            log.info(`[CREDENTIALS] Using ${client.provider.toUpperCase()} API Token...`);
            credentials = { apiToken: client.apiToken };
            await trackProgress('in_progress', 15, 'AGENT', `${client.provider.toUpperCase()} credentials loaded.`);
        }

        // Step 2: Scan
        log.info(`[SCANNER] Executing deep ${client.provider.toUpperCase()} scan...`);
        await trackProgress('in_progress', 25, 'SYSTEM', `Executing deep ${client.provider.toUpperCase()} scan...`);

        const { resources } = await runScan(client.provider, credentials);
        const anomalies = resources.filter(r => r.severity !== 'pass');
        log.info(`[SCANNER] Found ${anomalies.length} anomalies.`);
        await trackProgress('in_progress', 50, 'OUTPUT', `Scan complete: ${resources.length} resources, ${anomalies.length} anomalies.`);

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
                    const result = await runRemediation(client.provider, credentials, anomaly.type, anomaly.name, anomaly.issue);
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

        // Step 4: Save results for frontend polling
        log.info(`[REPORTER] Generating results for polling...`);
        await trackProgress('in_progress', 85, 'SYSTEM', 'Persisting results to audit trail...');

        await saveAuditLog(client.id, 'SCAN_COMPLETE', `Scan completed for ${client.name}`, { 
            resources, 
            executionId,
            jobId,
            summary: { resolved: resolvedCount, escalated: escalatedCount, details: remediationDetails }
        });

        // Step 5: Generate & Send Report
        log.info(`[REPORTER] Generating email report...`);
        await trackProgress('in_progress', 90, 'SYSTEM', 'Generating compliance report...');

        const summary = { resolved: resolvedCount, escalated: escalatedCount, details: remediationDetails };
        const reportHtml = generateReport(client.name, resources, summary);

        if (client.email) {
            await trackProgress('in_progress', 95, 'SYSTEM', `Sending report to ${client.email}...`);
            await sendReport(client.email, client.name, reportHtml);
            log.info(`[REPORTER] ✓ Report delivered to ${client.email}`);
        }

        // Step 6: Complete the job
        await completeJob(jobId, 'completed', resources);
        log.info(`✨ WORKER COMPLETE for ${client.name}.`);
        return { success: true, clientId: client.id, jobId };

    } catch (e) {
        log.error(`❌ WORKER CRASHED for ${client.name}:`, e);
        if (jobId) await completeJob(jobId, 'failed', [], e.message);
        throw e;
    }
};
