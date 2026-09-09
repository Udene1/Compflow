import pool from '../core/db.js';

/**
 * Operational monitoring API backed by PostgreSQL.
 * Organization ownership is proven through the authoritative scans table;
 * Redis/BullMQ remains dispatch-only and is never used as monitoring truth.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    const organizationId = req.user?.orgId;
    if (!organizationId) return res.status(403).json({ error: 'Organization context required' });

    try {
        const result = await pool.query(`
            SELECT
                COUNT(DISTINCT j.job_id)::int AS total_jobs,
                COUNT(DISTINCT j.job_id) FILTER (WHERE j.status = 'FAILED')::int AS failed_count
            FROM jobs j
            INNER JOIN scans s ON s.job_id = j.job_id
            WHERE s.organization_id = $1
              AND j.created_at >= NOW() - INTERVAL '24 hours'
        `, [organizationId]);

        const recentFailures = await pool.query(`
            SELECT DISTINCT ON (j.job_id)
                j.job_id, j.client_id, j.scan_type, j.status,
                j.error_message, j.created_at AS started_at, j.updated_at
            FROM jobs j
            INNER JOIN scans s ON s.job_id = j.job_id
            WHERE s.organization_id = $1
              AND j.status = 'FAILED'
              AND j.created_at >= NOW() - INTERVAL '24 hours'
            ORDER BY j.job_id, j.updated_at DESC
        `, [organizationId]);

        const totalJobs = result.rows[0]?.total_jobs || 0;
        const failedCount = result.rows[0]?.failed_count || 0;
        const successRate = totalJobs > 0
            ? Math.round(((totalJobs - failedCount) / totalJobs) * 100)
            : 100;

        return res.status(200).json({
            window: '24h',
            totalJobs,
            successRate: `${successRate}%`,
            failedCount,
            failures: recentFailures.rows
                .sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at))
                .slice(0, 10)
                .map(row => ({
                    jobId: row.job_id,
                    clientId: row.client_id,
                    scanType: row.scan_type,
                    time: row.started_at,
                    updatedAt: row.updated_at,
                    error: row.error_message || 'Unknown error',
                    status: row.status
                }))
        });
    } catch (error) {
        console.error('[MONITORING-API] Error:', error?.message || error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
