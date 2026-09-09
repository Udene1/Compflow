import { getJobHistory, getJob } from '../core/jobs.js';

/**
 * Durable jobs API backed by PostgreSQL. Organization ownership comes from
 * the authenticated session and is enforced by the job manager.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    const organizationId = req.user?.orgId;
    if (!organizationId) return res.status(403).json({ error: 'Organization context required' });

    const { clientId, jobId, action } = req.body || {};

    try {
        if (action === 'history') {
            if (!clientId) return res.status(400).json({ error: 'Missing clientId' });
            const history = await getJobHistory(clientId, 5, organizationId);
            return res.status(200).json({ history });
        }

        if (action === 'details') {
            if (!jobId) return res.status(400).json({ error: 'Missing jobId' });
            const job = await getJob(jobId, organizationId);
            if (!job) return res.status(404).json({ error: 'Job not found' });
            return res.status(200).json({ job });
        }

        return res.status(400).json({ error: 'Invalid action' });
    } catch (error) {
        console.error('[JOBS-API] Error:', error?.message || error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
