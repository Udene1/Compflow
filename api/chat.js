import { analyzeExecutionSecurity } from '../core/ai_analyst.js';

/**
 * Security analyst API. Analysis is grounded only in the authenticated
 * execution context and deterministic Compflow evidence.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    const organizationId = req.user?.orgId;
    const executionId = req.body?.executionId;
    const actorId = req.user?.userId || req.body?.actorId || null;
    const idempotencyKey = req.body?.idempotencyKey || null;

    if (!organizationId || !executionId) {
        return res.status(400).json({ error: 'ORGANIZATION_AND_EXECUTION_REQUIRED' });
    }

    if (!process.env.GEMINI_API_KEY) {
        return res.status(503).json({ error: 'AI_ANALYST_UNAVAILABLE' });
    }

    try {
        const result = await analyzeExecutionSecurity({
            organizationId,
            executionId,
            actorId,
            idempotencyKey
        });
        return res.status(200).json(result);
    } catch (error) {
        const status = error?.message === 'AI_ANALYST_UNAVAILABLE' ? 503 : 500;
        console.error('[CHAT-API] Analyst error:', error?.message || error);
        return res.status(status).json({ error: error?.message || 'AI_ANALYST_FAILED' });
    }
}
