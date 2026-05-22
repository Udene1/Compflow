import { runScan } from '../core/scanner.js';
import { log } from '../core/logger.js';
import { saveAuditLog } from '../core/audit.js';

/**
 * Lambda Scan Handler
 * Runs the full cloud resource scan and persists results to the Audit Table.
 */
export const handler = async (event) => {
    // Determine if this is an API Gateway event or a direct invocation
    const isApiGateway = !!event.httpMethod;
    const body = isApiGateway ? JSON.parse(event.body || '{}') : event;
    const { credentials, provider, clientId = 'adhoc_user' } = body;

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
            return isApiGateway 
                ? { statusCode: 400, headers, body: JSON.stringify({ error: err }) }
                : { error: err };
        }

        console.log(`[LAMBDA-SCAN] Deep scan started for ${provider.toUpperCase()} (Client: ${clientId})`);
        const result = await runScan(provider, credentials);

        // Save to Audit Table for frontend polling
        await saveAuditLog(clientId, 'SCAN_COMPLETE', `Manual scan completed for ${provider.toUpperCase()}`, {
            resources: result.resources,
            timestamp: new Date().toISOString()
        });

        console.log(`[LAMBDA-SCAN] Scan complete. ${result.resources?.length || 0} resources recorded.`);

        return isApiGateway 
            ? { statusCode: 200, headers, body: JSON.stringify(result) }
            : result;

    } catch (e) {
        console.error('[LAMBDA-SCAN] Fatal scan error:', e);
        return isApiGateway 
            ? { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) }
            : { error: e.message };
    }
};
    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };

    // Handle CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method Not Allowed' }) };
    }

    try {
        const body = JSON.parse(event.body || '{}');
        const { credentials, provider } = body;

        if (!provider || !credentials) {
            return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing provider or credentials' }) };
        }

        log.info(`[LAMBDA-SCAN] Dispatching scan for ${provider.toUpperCase()}`);
        const result = await runScan(provider, credentials);

        log.info(`[LAMBDA-SCAN] Scan complete. ${result.resources?.length || 0} resources found.`);
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(result)
        };
    } catch (e) {
        console.error('[LAMBDA-SCAN] Fatal error:', e);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: e.message || 'Internal scan error' })
        };
    }
};
