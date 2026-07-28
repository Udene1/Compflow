import { getJob, jobEvents } from '../core/jobs.js';

/**
 * SSE Job Stream Endpoint
 * GET /api/job-stream?jobId=xxx
 * Streams real-time terminal logs and progress updates to EventSource clients.
 */
export default async function jobStreamHandler(req, res) {
    const jobId = req.query.jobId || req.query.job_id;

    if (!jobId) {
        return res.status(400).json({ error: 'Missing jobId parameter' });
    }

    // Set Server-Sent Events HTTP Headers
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
    });

    // Flush headers immediately
    res.flushHeaders?.();

    // Helper to send typed SSE event
    const sendSSE = (eventName, data) => {
        res.write(`event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    // 1. Send initial snapshot of job state
    try {
        const job = await getJob(jobId);
        if (job) {
            sendSSE('initial', job);
        } else {
            sendSSE('error', { message: 'Job not found' });
        }
    } catch (err) {
        sendSSE('error', { message: err.message });
    }

    // 2. Subscribe to real-time jobEvents for this jobId
    const onJobUpdate = (targetJobId, updateData) => {
        if (targetJobId !== jobId) return;

        if (updateData.status === 'completed') {
            sendSSE('complete', updateData);
        } else if (updateData.status === 'failed') {
            sendSSE('error', updateData);
        } else {
            sendSSE('update', updateData);
        }
    };

    jobEvents.on('update', onJobUpdate);

    // 3. Keep connection alive with 15s heartbeats
    const heartbeatTimer = setInterval(() => {
        res.write(': ping\n\n');
    }, 15000);

    // 4. Cleanup listener on client disconnect
    req.on('close', () => {
        clearInterval(heartbeatTimer);
        jobEvents.removeListener('update', onJobUpdate);
        res.end();
    });
}
