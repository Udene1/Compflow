import pool from '../core/db.js';
import { jobEvents } from '../core/jobs.js';

/**
 * SSE Job Stream Endpoint.
 * The stream is opened only after the job's organization ownership is proven
 * from durable PostgreSQL state.
 */
export default async function jobStreamHandler(req, res) {
    const jobId = req.query.jobId || req.query.job_id;
    const organizationId = req.user?.orgId;

    if (!organizationId) return res.status(403).json({ error: 'Organization context required' });
    if (!jobId) return res.status(400).json({ error: 'Missing jobId parameter' });

    let job;
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
        job = result.rows[0] || null;
    } catch (error) {
        console.error('[JOB-STREAM] Ownership lookup failed:', error?.message || error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (!job) return res.status(404).json({ error: 'Job not found' });

    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });
    res.flushHeaders?.();

    const sendSSE = (eventName, data) => {
        if (!res.writableEnded) res.write(`event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    sendSSE('initial', {
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

    const onJobUpdate = (targetJobId, updateData) => {
        if (targetJobId !== jobId || res.writableEnded) return;
        if (updateData.status === 'completed') sendSSE('complete', updateData);
        else if (updateData.status === 'failed') sendSSE('error', updateData);
        else sendSSE('update', updateData);
    };

    jobEvents.on('update', onJobUpdate);
    const heartbeatTimer = setInterval(() => {
        if (!res.writableEnded) res.write(': ping\n\n');
    }, 15000);

    req.on('close', () => {
        clearInterval(heartbeatTimer);
        jobEvents.removeListener('update', onJobUpdate);
        if (!res.writableEnded) res.end();
    });
}
