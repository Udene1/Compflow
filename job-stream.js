// ─── ComplianceFlow AI: Server-Sent Events (SSE) Endpoint ───
import { getJob, jobEvents } from './core/jobs.js';

/**
 * Handles SSE live streaming for job status and progress.
 * GET /api/job-stream?jobId=xxx
 */
export async function jobStreamHandler(req, res) {
    const jobId = req.query.jobId || req.query.job_id;

    if (!jobId) {
        return res.status(400).json({ error: 'Missing jobId query parameter' });
    }

    // Set SSE Headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // Disable proxy buffering (Nginx/Azure)
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Send initial comment to establish connection
    res.write(`: SSE stream connected for job ${jobId}\n\n`);

    // Fetch and send current initial state
    try {
        const currentJob = await getJob(jobId);
        if (currentJob) {
            res.write(`data: ${JSON.stringify(currentJob)}\n\n`);

            if (currentJob.status === 'completed' || currentJob.status === 'failed') {
                res.write(`data: ${JSON.stringify({ ...currentJob, eventType: 'job:finished' })}\n\n`);
                return res.end();
            }
        }
    } catch (err) {
        console.error(`[SSE] Error fetching initial job ${jobId}:`, err.message);
    }

    // Subscribe to EventEmitter for real-time updates
    const onJobUpdate = (updatePayload) => {
        if (updatePayload.jobId === jobId) {
            try {
                res.write(`data: ${JSON.stringify(updatePayload)}\n\n`);

                if (updatePayload.status === 'completed' || updatePayload.status === 'failed') {
                    cleanup();
                    res.end();
                }
            } catch (err) {
                console.error(`[SSE] Error writing event to client for job ${jobId}:`, err.message);
            }
        }
    };

    jobEvents.on('job:update', onJobUpdate);

    // Periodic 15s keep-alive ping to prevent timeouts
    const pingInterval = setInterval(() => {
        try {
            res.write(': ping\n\n');
        } catch (e) {
            cleanup();
        }
    }, 15000);

    function cleanup() {
        clearInterval(pingInterval);
        jobEvents.removeListener('job:update', onJobUpdate);
    }

    // Clean up when client disconnects
    req.on('close', () => {
        cleanup();
    });
}

export default jobStreamHandler;
