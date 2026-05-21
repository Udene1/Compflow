import { runScan } from '../core/scanner.js';
import { log } from '../core/logger.js';

/**
 * Lambda HTTP Scan Handler
 * Runs the full cloud resource scan with a 15-minute timeout.
 * Called by the Vercel /api/scan proxy or directly via API Gateway.
 */
export const handler = async (event) => {
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
