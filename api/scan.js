import { createJob, completeJob } from '../core/jobs.js';
import { enqueueJob } from '../core/queue.js';

/**
 * Scan Endpoint
 * Creates a durable job, stores credential references, and enqueues only
 * non-secret identifiers into BullMQ.
 */
export default async function handler(req, res) {
    try {
        if (req.method === 'OPTIONS') return res.status(200).end();
        if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

        const clientId = req.body?.clientId || 'adhoc_user';
        const provider = req.body?.provider;
        const credentials = req.body?.credentials;
        const email = req.body?.email || null;
        const orgId = req.user?.orgId || req.authContext?.orgId;

        if (!orgId) return res.status(403).json({ error: 'Organization context required' });
        if (!provider) return res.status(400).json({ error: 'Missing provider.' });
        if (!credentials && !req.body?.connectionId) {
            return res.status(400).json({ error: 'Missing cloud connection credentials.' });
        }

        const jobId = await createJob(clientId, 'on_demand', orgId);
        let connectionId = req.body?.connectionId || null;

        if (credentials && !connectionId) {
            connectionId = 'scan_conn_' + jobId;
            const { defaultSecretStore } = await import('../core/secret_store.js');
            await defaultSecretStore.saveSecret(orgId, connectionId, credentials, req.user?.userId || 'api_user');
        }

        if (!connectionId) {
            await completeJob(jobId, 'failed', [], 'Cloud connection is unavailable.');
            return res.status(400).json({ error: 'Cloud connection is unavailable.' });
        }

        const payload = {
            jobId,
            provider,
            organizationId: orgId,
            connectionId,
            clientId,
            scanType: 'on_demand',
            enqueuedAt: new Date().toISOString()
        };

        console.log(`[SCAN-API] Job ${jobId} created for organization ${orgId} (${provider.toUpperCase()}) → enqueuing`);

        try {
            await enqueueJob(payload);
        } catch (queueError) {
            await completeJob(jobId, 'failed', [], 'Scan could not be queued.');
            const status = queueError?.code === 'QUEUE_UNAVAILABLE' ? 503 : 500;
            return res.status(status).json({
                error: status === 503 ? 'Scan queue unavailable.' : 'Scan could not be queued.'
            });
        }

        return res.status(202).json({ success: true, status: 'queued', jobId, clientId });
    } catch (err) {
        console.error('[SCAN-API] Fatal Error:', err?.message || err);
        return res.status(500).json({ error: 'Internal server error triggering scan.' });
    }
}
