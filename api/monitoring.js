import pool from '../core/db.js';

/**
 * Operational monitoring API backed by PostgreSQL.
 * Redis/BullMQ is dispatch-only; durable job state is the source of truth.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    const organizationId = req.user?.orgId;
    if (!organizationId) return res.status(403).json({ error: 'Organization context required' });

    try {
        const result = await pool.query(`
            SELECT COUNT(*)::int AS total_jobs,
                   COUNT(*) FILTER (WHERE status = 'FAILED')::int AS failed_count
            FROM jobs
            WHERE org_id = $1
              AND created_at >= NOW() - INTERVAL '24 hours'
        `, [organizationId]);

        const recentFailures = await pool.query(`
            SELECT job_id, client_id, scan_type, status, error_message,
                   created_at AS started_at, updated_at
            FROM jobs
            WHERE org_id = $1
              AND status = 'FAILED'
              AND created_at >= NOW() - INTERVAL '24 hours'
            ORDER BY updated_at DESC
            LIMIT 10
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
            failures: recentFailures.rows.map(row => ({
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
