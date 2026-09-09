import { getJob } from '../core/jobs.js';

/**
 * Durable job status endpoint. A job is readable only inside the authenticated
 * organization's durable job namespace.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method Not Allowed' });

    const { jobId } = req.query;
    const organizationId = req.user?.orgId;
    if (!organizationId) return res.status(403).json({ error: 'Organization context required' });
    if (!jobId) return res.status(400).json({ error: 'Missing jobId' });

    try {
        const job = await getJob(jobId, organizationId);
        if (!job) return res.status(404).json({ error: 'Job not found' });
        return res.status(200).json(job);
    } catch (error) {
        console.error('[JOB-STATUS] Error:', error?.message || error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
