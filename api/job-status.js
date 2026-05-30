import { getJob } from '../core/jobs.js';

/**
 * Job Status API — Lightweight polling endpoint
 * GET /api/job-status?jobId=xxx
 * Returns current job state for frontend terminal streaming.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method Not Allowed' });

    const { jobId } = req.query;
    if (!jobId) return res.status(400).json({ error: 'Missing jobId' });

    try {
        const job = await getJob(jobId);
        
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }

        return res.status(200).json({
            jobId: job.jobId,
            status: job.status,
            progress: job.progress,
            logs: job.logs || [],
            resources: job.resources || [],
            errorMessage: job.errorMessage || null,
            createdAt: job.createdAt,
            updatedAt: job.updatedAt,
            completedAt: job.completedAt || null
        });
    } catch (e) {
        console.error('[JOB-STATUS] Error:', e.message);
        return res.status(500).json({ error: e.message });
    }
}
