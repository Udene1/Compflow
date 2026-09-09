import pool from '../core/db.js';

function mapJob(row) {
    return {
        jobId: row.job_id,
        clientId: row.client_id,
        scanType: row.scan_type,
        status: row.status,
        progress: row.progress,
        logs: row.logs || [],
        resources: row.resources || [],
        errorMessage: row.error_message || null,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        completedAt: row.completed_at
    };
}

/**
 * Durable jobs API backed by PostgreSQL.
 * Ownership is proven through the authoritative scan/tenant relationship;
 * the request cannot supply an organization identifier of its own.
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
            const result = await pool.query(`
                SELECT j.*
                FROM jobs j
                WHERE j.client_id = $1
                  AND (
                    EXISTS (
                        SELECT 1 FROM scans s
                        WHERE s.job_id = j.job_id AND s.organization_id = $2
                    )
                    OR EXISTS (
                        SELECT 1 FROM tenants t
                        WHERE t.id = j.client_id AND t.org_id = $2
                    )
                  )
                ORDER BY j.created_at DESC
                LIMIT 5
            `, [clientId, organizationId]);
            return res.status(200).json({ history: result.rows.map(mapJob) });
        }

        if (action === 'details') {
            if (!jobId) return res.status(400).json({ error: 'Missing jobId' });
            const result = await pool.query(`
                SELECT j.*
                FROM jobs j
                WHERE j.job_id = $1
                  AND (
                    EXISTS (
                        SELECT 1 FROM scans s
                        WHERE s.job_id = j.job_id AND s.organization_id = $2
                    )
                    OR EXISTS (
                        SELECT 1 FROM tenants t
                        WHERE t.id = j.client_id AND t.org_id = $2
                    )
                  )
                LIMIT 1
            `, [jobId, organizationId]);
            if (result.rows.length === 0) return res.status(404).json({ error: 'Job not found' });
            return res.status(200).json({ job: mapJob(result.rows[0]) });
        }

        return res.status(400).json({ error: 'Invalid action' });
    } catch (error) {
        console.error('[JOBS-API] Error:', error?.message || error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
