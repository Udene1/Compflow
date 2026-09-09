import { createJob, completeJob } from '../core/jobs.js';
import { enqueueJob } from '../core/queue.js';
import pool from '../core/db.js';

function apiError(res, status, code, message, extra = {}) {
    return res.status(status).json({ error: code, code, message, ...extra });
}

/**
 * Scan Endpoint
 * Creates a durable scan job and enqueues only non-secret references into BullMQ.
 * Cloud credentials are accepted only by the onboarding connection flow, where
 * they are stored in SecretStore and verified against the real provider first.
 */
export default async function handler(req, res) {
    try {
        if (req.method === 'OPTIONS') return res.status(200).end();
        if (req.method !== 'POST') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed.');

        const clientId = req.body?.clientId || 'adhoc_user';
        const provider = String(req.body?.provider || '').toLowerCase();
        const connectionId = req.body?.connectionId || null;
        const orgId = req.user?.orgId || req.authContext?.orgId;

        if (!orgId) return apiError(res, 403, 'ORGANIZATION_CONTEXT_REQUIRED', 'Organization context required.');
        if (!provider) return apiError(res, 400, 'PROVIDER_REQUIRED', 'Cloud provider is required.');
        if (!connectionId) return apiError(res, 400, 'CLOUD_CONNECTION_REQUIRED', 'A verified cloud connection is required.');

        const connection = await pool.query(
            `SELECT id, provider, status
             FROM cloud_connections
             WHERE id = $1 AND organization_id = $2`,
            [connectionId, orgId]
        );

        if (connection.rows.length === 0) {
            return apiError(res, 404, 'CLOUD_CONNECTION_NOT_FOUND', 'Cloud connection not found.');
        }

        const cloudConnection = connection.rows[0];
        if (cloudConnection.provider !== provider) {
            return apiError(res, 409, 'CLOUD_PROVIDER_MISMATCH', 'The selected provider does not match the cloud connection.');
        }
        if (cloudConnection.status !== 'VERIFIED') {
            return apiError(res, 409, 'CLOUD_CONNECTION_NOT_VERIFIED', 'Cloud connection must pass real provider verification before scanning.');
        }

        const jobId = await createJob(clientId, 'on_demand', orgId);
        const scanId = 'scan_' + crypto.randomUUID().replace(/-/g, '').substring(0, 16);

        await pool.query(
            `INSERT INTO scans (id, organization_id, connection_id, job_id, scan_type, status)
             VALUES ($1, $2, $3, $4, 'manual', 'QUEUED')`,
            [scanId, orgId, connectionId, jobId]
        );

        const payload = {
            jobId,
            scanId,
            provider,
            organizationId: orgId,
            connectionId,
            clientId,
            scanType: 'manual',
            enqueuedAt: new Date().toISOString()
        };

        console.log(`[SCAN-API] Scan ${scanId} / Job ${jobId} created for organization ${orgId} (${provider.toUpperCase()}) → enqueuing`);

        try {
            await enqueueJob(payload);
        } catch (queueError) {
            await completeJob(jobId, 'failed', [], 'Scan could not be queued.');
            await pool.query(
                `UPDATE scans SET status='FAILED', error_code=$1, error_message=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3`,
                [queueError?.code || 'QUEUE_ENQUEUE_FAILED', 'Scan could not be queued.', scanId]
            ).catch(() => {});
            const status = queueError?.code === 'QUEUE_UNAVAILABLE' ? 503 : 500;
            return apiError(
                res,
                status,
                status === 503 ? 'QUEUE_UNAVAILABLE' : 'QUEUE_ENQUEUE_FAILED',
                status === 503 ? 'Scan queue unavailable. Please try again when the service is ready.' : 'Scan could not be queued. Please try again.'
            );
        }

        return res.status(202).json({ success: true, status: 'queued', scanId, jobId, clientId });
    } catch (err) {
        console.error('[SCAN-API] Fatal Error:', err?.message || err);
        return apiError(res, 500, 'SCAN_REQUEST_FAILED', 'The scan request could not be completed.');
    }
}