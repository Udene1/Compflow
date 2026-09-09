import { getJob } from '../core/jobs.js';

function apiError(res, status, code, message) {
    return res.status(status).json({ error: code, code, message });
}

/**
 * Durable job status endpoint. A job is readable only inside the authenticated
 * organization's durable job namespace.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed.');

    const { jobId } = req.query;
    const organizationId = req.user?.orgId;
    if (!organizationId) return apiError(res, 403, 'ORGANIZATION_CONTEXT_REQUIRED', 'Organization context required.');
    if (!jobId) return apiError(res, 400, 'JOB_ID_REQUIRED', 'A job ID is required.');

    try {
        const job = await getJob(jobId, organizationId);
        if (!job) return apiError(res, 404, 'JOB_NOT_FOUND', 'Job not found.');
        return res.status(200).json(job);
    } catch (error) {
        console.error('[JOB-STATUS] Error:', error?.message || error);
        return apiError(res, 500, 'JOB_STATUS_FAILED', 'Job status could not be retrieved.');
    }
}
