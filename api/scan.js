import { createJob } from '../core/jobs.js';
import { enqueueJob } from '../core/queue.js';

/**
 * Scan Endpoint
 * Creates a job record, enqueues to BullMQ Redis Queue, returns jobId immediately.
 */
export default async function handler(req, res) {
    try {
        if (req.method === 'OPTIONS') return res.status(200).end();
        if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

        const clientId = req.body?.clientId || 'adhoc_user';
        const provider = req.body?.provider;
        const credentials = req.body?.credentials;
        const email = req.body?.email;

        if (!provider || !credentials) {
            return res.status(400).json({ error: "Missing provider or credentials." });
        }

        // 1. Create job record in PostgreSQL
        const jobId = await createJob(clientId, 'on_demand');

        // 2. Enqueue job into BullMQ scan-queue
        const payload = {
            jobId,
            provider,
            credentials,
            clientId,
            id: clientId,
            name: clientId,
            email
        };

        console.log(`[SCAN-API] Job ${jobId} created for client '${clientId}' (${provider.toUpperCase()}) → Enqueuing to BullMQ`);

        await enqueueJob(payload);

        // 3. Return jobId immediately
        return res.status(202).json({ 
            success: true, 
            status: 'queued', 
            jobId,
            clientId
        });

    } catch (err) {
        console.error('[SCAN-API] Fatal Error:', err);
        return res.status(500).json({ 
            error: "Internal server error triggering scan: " + err.message 
        });
    }
}
