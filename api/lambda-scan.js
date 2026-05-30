import { runScan } from '../core/scanner.js';
import { log } from '../core/logger.js';
import { saveAuditLog } from '../core/audit.js';
import { updateJobProgress, completeJob } from '../core/jobs.js';

/**
 * Lambda Scan Handler
 * Runs the full cloud resource scan with progressive job updates.
 */
export const handler = async (event) => {
    // Determine if this is an API Gateway event or a direct invocation
    const isApiGateway = !!event.httpMethod;
    const body = isApiGateway ? JSON.parse(event.body || '{}') : event;
    const { credentials, provider, clientId = 'adhoc_user', jobId } = body;

    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };

    if (isApiGateway && event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        if (!provider || !credentials) {
            const err = 'Missing provider or credentials';
            if (jobId) await completeJob(jobId, 'failed', [], err);
            return isApiGateway 
                ? { statusCode: 400, headers, body: JSON.stringify({ error: err }) }
                : { error: err };
        }

        // ── Step 1: Mark in_progress ──
        if (jobId) {
            await updateJobProgress(jobId, 'in_progress', 10, 'SYSTEM', `Scan started for ${provider.toUpperCase()}`);
        }

        console.log(`[LAMBDA-SCAN] Deep scan started for ${provider.toUpperCase()} (Client: ${clientId}, Job: ${jobId || 'none'})`);

        // ── Step 2: Validate credentials ──
        if (jobId) {
            await updateJobProgress(jobId, 'in_progress', 20, 'AGENT', 'Validating cloud credentials...');
        }

        // ── Step 3: Run the scan ──
        if (jobId) {
            await updateJobProgress(jobId, 'in_progress', 30, 'AGENT', `Executing ${provider.toUpperCase()} resource enumeration...`);
        }

        const result = await runScan(provider, credentials);

        if (jobId) {
            const resourceCount = result.resources?.length || 0;
            const anomalies = (result.resources || []).filter(r => r.severity !== 'pass');
            await updateJobProgress(jobId, 'in_progress', 60, 'OUTPUT', 
                `Scan complete: ${resourceCount} resources found, ${anomalies.length} anomalies detected.`
            );
        }

        // ── Step 4: Log resource details ──
        if (jobId && result.resources) {
            for (const r of result.resources.filter(r => r.severity !== 'pass').slice(0, 10)) {
                await updateJobProgress(jobId, 'in_progress', 65, 'INSIGHT', 
                    `${r.severity?.toUpperCase()}: ${r.type} "${r.name}" — ${r.issue}`
                );
            }
        }

        // ── Step 5: Save to Audit Table (backward compatible) ──
        if (jobId) {
            await updateJobProgress(jobId, 'in_progress', 85, 'SYSTEM', 'Persisting results to audit trail...');
        }

        await saveAuditLog(clientId, 'SCAN_COMPLETE', `Manual scan completed for ${provider.toUpperCase()}`, {
            resources: result.resources,
            jobId,
            timestamp: new Date().toISOString()
        });

        // ── Step 6: Complete the job ──
        if (jobId) {
            await completeJob(jobId, 'completed', result.resources || []);
        }

        console.log(`[LAMBDA-SCAN] Scan complete. ${result.resources?.length || 0} resources recorded.`);

        return isApiGateway 
            ? { statusCode: 200, headers, body: JSON.stringify(result) }
            : result;

    } catch (e) {
        console.error('[LAMBDA-SCAN] Fatal scan error:', e);
        if (jobId) await completeJob(jobId, 'failed', [], e.message);
        return isApiGateway 
            ? { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) }
            : { error: e.message };
    }
};
