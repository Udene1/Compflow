import { getJob, jobEvents } from '../core/jobs.js';

function apiError(res, status, code, message) {
    return res.status(status).json({ error: code, code, message });
}

/**
 * SSE job stream. Authorization is established before opening the stream and
 * every initial snapshot is read from the organization-scoped durable store.
 */
export default async function jobStreamHandler(req, res) {
    const jobId = req.query.jobId || req.query.job_id;
    const organizationId = req.user?.orgId;

    if (!organizationId) return apiError(res, 403, 'ORGANIZATION_CONTEXT_REQUIRED', 'Organization context required.');
    if (!jobId) return apiError(res, 400, 'JOB_ID_REQUIRED', 'A job ID is required.');

    let job;
    try {
        job = await getJob(jobId, organizationId);
    } catch (error) {
        console.error('[JOB-STREAM] Lookup error:', error?.message || error);
        return apiError(res, 500, 'JOB_STREAM_LOOKUP_FAILED', 'The job stream could not be opened.');
    }
    if (!job) return apiError(res, 404, 'JOB_NOT_FOUND', 'Job not found.');

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
    sendSSE('initial', job);

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
