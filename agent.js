import { runScan } from './core/scanner.js';
import { runRemediation } from './core/remediator.js';

// Mock DB of clients
const CLIENT_DB = [
    {
        id: 'client_001',
        name: 'Acme Corp',
        provider: 'aws',
        // In a real app, this is an IAM AssumeRole ARN or Encrypted Secret.
        credentials: {
            accessKeyId: 'AKI...MOCK',
            secretAccessKey: 'V2tN...MOCK',
            sessionToken: ''
        }
    }
];

// Mock LLM Reasoning Engine (The "AI" in AINS)
async function evaluateFinding(finding) {
    console.log(`[LLM SUPERVISOR] Analyzing: ${finding.type} - ${finding.issue}...`);
    
    // Simulate LLM latency
    await new Promise(resolve => setTimeout(resolve, 800));

    // Hardcode some safe versus dangerous fixes exactly how an LLM would structure it
    const safeToFix = [
        'Public access enabled',
        'PITR (Continuous Backups) disabled',
        'Root MFA disabled',
        'Default execute-api endpoint enabled',
        'X-Ray Tracing disabled',
        'Log Retention < 365 days',
        'Automated Data Discovery disabled'
    ];

    const isSafe = safeToFix.some(i => finding.issue.includes(i));

    if (isSafe) {
        return { action: 'AUTO_FIX', confidence: 0.98, reason: 'Low blast radius structural fix.' };
    } else {
        return { action: 'ESCALATE', confidence: 0.85, reason: 'High risk of workload disruption.' };
    }
}

async function orchestratorLoop() {
    console.log(`\n========================================`);
    console.log(`🤖 COMPLIANCEFLOW AGENT INITIALIZING...`);
    console.log(`========================================`);

    for (const client of CLIENT_DB) {
        console.log(`\n➤ Processing Client: ${client.name} (${client.id})`);
        
        try {
            // Step 1: Scan
            console.log(`[SCANNER] Executing deep cloud scan...`);
            const { resources } = await runScan(client.provider, client.credentials);
            const anomalies = resources.filter(r => r.severity !== 'pass');
            console.log(`[SCANNER] Found ${anomalies.length} compliance anomalies.`);

            // Step 2: Reason & Remediate
            let resolvedCount = 0;
            let escalatedCount = 0;

            for (const anomaly of anomalies) {
                const llmDecision = await evaluateFinding(anomaly);
                
                if (llmDecision.action === 'AUTO_FIX') {
                    console.log(`[AGENT] ⚡ Executing auto-fix for ${anomaly.name} (${llmDecision.reason})`);
                    
                    try {
                        const result = await runRemediation(
                            client.provider, 
                            client.credentials, 
                            anomaly.type, 
                            anomaly.name, 
                            anomaly.issue
                        );
                        if (result.advisory) {
                            console.log(`[AGENT] ⚠️ Fix resulted in purely advisory message: ${result.message}`);
                            escalatedCount++;
                        } else {
                            console.log(`[AGENT] ✓ Successfully remediated: ${anomaly.name}.`);
                            resolvedCount++;
                        }
                    } catch (e) {
                        console.error(`[AGENT] ❌ Fix failed: ${e.message}`);
                        escalatedCount++;
                    }
                } else {
                    console.log(`[AGENT] ⏸ Escalating to client Jira/CISO: ${anomaly.name} (${llmDecision.reason})`);
                    escalatedCount++;
                }
            }

            // Step 3: Reporting (Mock)
            console.log(`\n[REPORTER] Generating Weekly Posture Report...`);
            console.log(`Summary: ${resolvedCount} autonomously resolved | ${escalatedCount} escalated for review.`);
            console.log(`[REPORTER] Email sent to ${client.name} Leadership.`);
            
        } catch (e) {
            console.error(`❌ Critical error processing client ${client.id}:`, e);
        }
    }
    
    console.log(`\n========================================`);
    console.log(`💤 ORCHESTRATOR SLEEPING UNTIL NEXT CRON.`);
    console.log(`========================================`);
}

// Start daemon
orchestratorLoop();

export { orchestratorLoop };
