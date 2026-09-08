import { analyzeExecutionSecurity } from '../core/ai_analyst.js';

/**
 * Legacy chat entry point. Security analysis is now performed only from the
 * authenticated execution context and deterministic Compflow evidence.
 * No placeholder credentials or synthetic scan context are permitted.
 */
export const handler = async (event) => {
    const isApiGateway = !!event.httpMethod;
    const body = isApiGateway ? JSON.parse(event.body || '{}') : event;
    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };
    if (isApiGateway && event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
    const organizationId = body.organizationId || body.orgId;
    const executionId = body.executionId;
    const actorId = body.actorId || null;
    const idempotencyKey = body.idempotencyKey || null;
    if (!organizationId || !executionId) {
        return isApiGateway
            ? { statusCode: 400, headers, body: JSON.stringify({ error: 'ORGANIZATION_AND_EXECUTION_REQUIRED' }) }
            : { error: 'ORGANIZATION_AND_EXECUTION_REQUIRED' };
    }
    if (!process.env.GEMINI_API_KEY) {
        return isApiGateway
            ? { statusCode: 503, headers, body: JSON.stringify({ error: 'AI_ANALYST_UNAVAILABLE' }) }
            : { error: 'AI_ANALYST_UNAVAILABLE' };
    }
    try {
        const result = await analyzeExecutionSecurity({ organizationId, executionId, actorId, idempotencyKey });
        return isApiGateway
            ? { statusCode: 200, headers, body: JSON.stringify(result) }
            : result;
    } catch (error) {
        const status = error?.message === 'AI_ANALYST_UNAVAILABLE' ? 503 : 500;
        return isApiGateway
            ? { statusCode: status, headers, body: JSON.stringify({ error: error.message || 'AI_ANALYST_FAILED' }) }
            : { error: error.message || 'AI_ANALYST_FAILED' };
    }
};
