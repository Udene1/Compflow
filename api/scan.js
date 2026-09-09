import { createJob, completeJob } from '../core/jobs.js';
import { enqueueJob } from '../core/queue.js';

function apiError(res, status, code, message, extra = {}) {
    return res.status(status).json({ error: code, code, message, ...extra });
}

/**
 * Scan Endpoint
 * Creates a durable job, stores credential references, and enqueues only
 * non-secret identifiers into BullMQ.
 */
export default async function handler(req, res) {
    try {
        if (req.method === 'OPTIONS') return res.status(200).end();
        if (req.method !== 'POST') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed.');

        const clientId = req.body?.clientId || 'adhoc_user';
        const provider = req.body?.provider;
        const credentials = req.body?.credentials;
        const email = req.body?.email || null;
        const orgId = req.user?.orgId || req.authContext?.orgId;

        if (!orgId) return apiError(res, 403, 'ORGANIZATION_CONTEXT_REQUIRED', 'Organization context required.');
        if (!provider) return apiError(res, 400, 'PROVIDER_REQUIRED', 'Cloud provider is required.');
        if (!credentials && !req.body?.connectionId) {
            return apiError(res, 400, 'CLOUD_CONNECTION_REQUIRED', 'A verified cloud connection is required.');
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
            return apiError(res, 400, 'CLOUD_CONNECTION_UNAVAILABLE', 'Cloud connection is unavailable.');
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
            return apiError(
                res,
                status,
                status === 503 ? 'QUEUE_UNAVAILABLE' : 'QUEUE_ENQUEUE_FAILED',
                status === 503 ? 'Scan queue unavailable. Please try again when the service is ready.' : 'Scan could not be queued. Please try again.'
            );
        }

        return res.status(202).json({ success: true, status: 'queued', jobId, clientId });
    } catch (err) {
        console.error('[SCAN-API] Fatal Error:', err?.message || err);
        return apiError(res, 500, 'SCAN_REQUEST_FAILED', 'The scan request could not be completed.');
    }
}
