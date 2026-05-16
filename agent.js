import { runScan } from './core/scanner.js';
import { runRemediation } from './core/remediator.js';
import { evaluateWithGemini } from './core/gemini.js';
import { getClientCredentials, validatePlatformEnv } from './core/credentials.js';
import { loadClients } from './core/registry.js';
import { saveAuditLog } from './core/audit.js';
import { generateReport, generatePdfReport, sendReport } from './core/reporter.js';

// Validate platform environment on startup
validatePlatformEnv();

async function orchestratorLoop() {
    console.log(`\n========================================`);
    console.log(`🤖 COMPLIANCEFLOW AGENT INITIALIZING...`);
    console.log(`========================================`);

    const clients = await loadClients();

    if (clients.length === 0) {
        console.warn('[AGENT] No clients found in vault. Nothing to process.');
        return;
    }

    for (const client of clients) {
        console.log(`\n➤ Processing Client: ${client.name} (${client.id})`);
        
        try {
            // Step 1: Assume client's IAM role for temporary credentials
            console.log(`[CREDENTIALS] Assuming role ${client.roleArn}...`);
            let credentials;
            try {
                // Mandatory ExternalId to prevent Confused Deputy attacks
                credentials = await getClientCredentials(client.roleArn, client.id, client.externalId);
                console.log(`[CREDENTIALS] ✓ Temporary session established (1h TTL).`);
            } catch (e) {
                console.error(`[CREDENTIALS] ❌ Failed to assume role for ${client.name}: ${e.message}`);
                console.log(`[AGENT] Skipping client ${client.name} due to credential failure.`);
                continue;
            }

            // Step 2: Scan with temporary credentials
            console.log(`[SCANNER] Executing deep cloud scan...`);
            const { resources } = await runScan('aws', credentials);
            const anomalies = resources.filter(r => r.severity !== 'pass');
            console.log(`[SCANNER] Found ${anomalies.length} compliance anomalies out of ${resources.length} controls.`);

            // Step 3: Reason & Remediate
            let resolvedCount = 0;
            let escalatedCount = 0;
            const remediationDetails = [];

            for (const anomaly of anomalies) {
                console.log(`[AGENT] Consulting Gemini for ${anomaly.name}...`);
                const llmDecision = await evaluateWithGemini(anomaly);

                // Respect client's autoRemediate preference
                if (llmDecision.action === 'AUTO_FIX' && client.autoRemediate) {
                    console.log(`[AGENT] ⚡ Executing auto-fix for ${anomaly.name} (${llmDecision.reason})`);
                    
                    try {
                        const result = await runRemediation(
                            'aws', 
                            credentials, 
                            anomaly.type, 
                            anomaly.name, 
                            anomaly.issue
                        );

                        // --- PERSIST AUDIT LOG ---
                        await saveAuditLog(client.id, 'INFO', `REMEDIATED: ${anomaly.name}`, {
                            resource: anomaly.name,
                            type: anomaly.type,
                            issue: anomaly.issue,
                            decision: llmDecision.action,
                            reason: llmDecision.reason,
                            status: 'fixed'
                        });

                        if (result.advisory) {
                            console.log(`[AGENT] ⚠️ Advisory: ${result.message}`);
                            escalatedCount++;
                            remediationDetails.push({ name: anomaly.name, issue: anomaly.issue, status: 'escalated' });
                        } else {
                            console.log(`[AGENT] ✓ Remediated: ${anomaly.name}.`);
                            resolvedCount++;
                            remediationDetails.push({ name: anomaly.name, issue: anomaly.issue, status: 'fixed' });
                        }
                    } catch (e) {
                        console.error(`[AGENT] ❌ Fix failed: ${e.message}`);
                        escalatedCount++;
                        remediationDetails.push({ name: anomaly.name, issue: anomaly.issue, status: 'failed' });
                        
                        await saveAuditLog(client.id, 'ERROR', `FIX_FAILED: ${anomaly.name}`, {
                            resource: anomaly.name,
                            issue: anomaly.issue,
                            error: e.message,
                            status: 'failed'
                        });
                    }
                } else {
                    const reason = !client.autoRemediate 
                        ? 'Auto-remediation disabled for this client' 
                        : llmDecision.reason;
                    console.log(`[AGENT] ⏸ Escalating: ${anomaly.name} (${reason})`);
                    escalatedCount++;
                    remediationDetails.push({ name: anomaly.name, issue: anomaly.issue, status: 'escalated' });

                    // --- PERSIST AUDIT LOG ---
                    await saveAuditLog(client.id, 'WARN', `ESCALATED: ${anomaly.name}`, {
                        resource: anomaly.name,
                        type: anomaly.type,
                        issue: anomaly.issue,
                        decision: llmDecision.action,
                        reason,
                        status: 'escalated'
                    });
                }
            }

            // Step 4: Generate & Send Report
            console.log(`\n[REPORTER] Generating compliance posture report...`);
            const remediationSummary = {
                resolved: resolvedCount,
                escalated: escalatedCount,
                details: remediationDetails,
            };
            
            const reportHtml = generateReport(client.name, resources, remediationSummary);
            const pdfBuffer = await generatePdfReport(client.name, resources);
            
            console.log(`[REPORTER] Report & PDF generated. Summary: ${resolvedCount} resolved | ${escalatedCount} escalated.`);

            if (client.email) {
                await sendReport(client.email, client.name, reportHtml, pdfBuffer);
            } else {
                console.warn(`[REPORTER] No email configured for ${client.name} — skipping delivery.`);
            }
            
        } catch (e) {
            console.error(`❌ Critical error processing client ${client.id}:`, e);
        }
    }
    
    console.log(`\n========================================`);
    console.log(`💤 ORCHESTRATOR SLEEPING UNTIL NEXT RUN.`);
    console.log(`========================================`);
}

// Support running locally via `node agent.js`
if (process.argv[1] && process.argv[1].endsWith('agent.js')) {
    orchestratorLoop();
}

// AWS Lambda Handler
export const handler = async (event, context) => {
    console.log("[LAMBDA] Invoked by EventBridge:", JSON.stringify(event));
    try {
        await orchestratorLoop();
        return { statusCode: 200, body: 'Run complete.' };
    } catch (e) {
        console.error('[LAMBDA] Execution failed:', e);
        throw e;
    }
};

export { orchestratorLoop };
