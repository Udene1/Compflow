import pool from '../core/db.js';

/**
 * Durable job status endpoint. A job is readable only when its authoritative
 * scan belongs to the authenticated organization.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method Not Allowed' });

    const { jobId } = req.query;
    const organizationId = req.user?.orgId;
    if (!organizationId) return res.status(403).json({ error: 'Organization context required' });
    if (!jobId) return res.status(400).json({ error: 'Missing jobId' });

    try {
        const result = await pool.query(`
            SELECT j.*
            FROM jobs j
            WHERE j.job_id = $1
              AND EXISTS (
                  SELECT 1 FROM scans s
                  WHERE s.job_id = j.job_id AND s.organization_id = $2
              )
            LIMIT 1
        `, [jobId, organizationId]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Job not found' });

        const job = result.rows[0];
        return res.status(200).json({
            jobId: job.job_id,
            status: job.status,
            progress: job.progress,
            logs: job.logs || [],
            resources: job.resources || [],
            errorMessage: job.error_message || null,
            createdAt: job.created_at,
            updatedAt: job.updated_at,
            completedAt: job.completed_at || null
        });
    } catch (error) {
        console.error('[JOB-STATUS] Error:', error?.message || error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
