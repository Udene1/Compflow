import { runScan } from './core/scanner.js';
import { runRemediation } from './core/remediator.js';
import { evaluateWithGemini } from './core/gemini.js';
import { getClientCredentials } from './core/credentials.js';
import { generateReport, sendReport } from './core/reporter.js';
import { Logger } from './core/logger.js';

/**
 * Worker Handler
 * Triggered by SQS to process a SINGLE tenant scan and remediation.
 */
export const handler = async (event) => {
    // 1. Parse SQS Message (BatchSize is 1)
    const client = JSON.parse(event.Records[0].body);
    const executionId = event.Records[0].messageId;
    
    // Initialize context-aware logger
    const log = new Logger({ clientId: client.id, executionId });

    log.info(`➤ WORKER START: Processing tenant ${client.name}`);

    try {
        // Step 1: Assume client's IAM role
        log.info(`[CREDENTIALS] Assuming role ${client.roleArn}...`);
        const credentials = await getClientCredentials(client.roleArn, client.id);
        log.info(`[CREDENTIALS] ✓ Temporary session established.`);

        // Step 2: Scan
        log.info(`[SCANNER] Executing deep cloud scan...`);
        const { resources } = await runScan('aws', credentials);
        const anomalies = resources.filter(r => r.severity !== 'pass');
        log.info(`[SCANNER] Found ${anomalies.length} anomalies.`);

        // Step 3: Reason & Remediate
        let resolvedCount = 0;
        let escalatedCount = 0;
        const remediationDetails = [];

        for (const anomaly of anomalies) {
            log.info(`[AGENT] Consulting Gemini for ${anomaly.name}...`);
            const llmDecision = await evaluateWithGemini(anomaly);

            if (llmDecision.action === 'AUTO_FIX' && client.autoRemediate) {
                log.info(`[AGENT] ⚡ EXECUTING AUTO-FIX: ${anomaly.name}`);
                
                try {
                    const result = await runRemediation('aws', credentials, anomaly.type, anomaly.name, anomaly.issue);
                    if (result.advisory) {
                        log.warn(`[AGENT] Advisory: ${result.message}`);
                        escalatedCount++;
                        remediationDetails.push({ name: anomaly.name, status: 'escalated' });
                    } else {
                        log.audit('REMEDIATE', anomaly.name, 'SUCCESS');
                        resolvedCount++;
                        remediationDetails.push({ name: anomaly.name, status: 'fixed' });
                    }
                } catch (e) {
                    log.error(`[AGENT] Fix failed for ${anomaly.name}:`, e);
                    escalatedCount++;
                    remediationDetails.push({ name: anomaly.name, status: 'failed' });
                }
            } else {
                log.info(`[AGENT] ⏸ Escalating: ${anomaly.name}`);
                escalatedCount++;
                remediationDetails.push({ name: anomaly.name, status: 'escalated' });
            }
        }

        // Step 4: Generate & Send Report
        log.info(`[REPORTER] Generating report...`);
        const summary = { resolved: resolvedCount, escalated: escalatedCount, details: remediationDetails };
        const reportHtml = generateReport(client.name, resources, summary);

        if (client.email) {
            await sendReport(client.email, client.name, reportHtml);
            log.info(`[REPORTER] ✓ Report delivered to ${client.email}`);
        }

        log.info(`✨ WORKER COMPLETE for ${client.name}.`);
        return { success: true, clientId: client.id };

    } catch (e) {
        log.error(`❌ WORKER CRASHED for ${client.name}:`, e);
        throw e;
    }
};
