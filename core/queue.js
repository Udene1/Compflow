const redisHost = process.env.REDIS_HOST || 'localhost';
const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);
const QUEUE_NAME = 'scan_jobs';
let scanQueue = null;
let queueInitPromise = null;

async function getQueue() {
    if (scanQueue) return scanQueue;
    if (queueInitPromise) return queueInitPromise;
    queueInitPromise = (async () => {
        try {
            const { Queue } = await import('bullmq');
            const { default: Redis } = await import('ioredis');
            const connection = new Redis({ host: redisHost, port: redisPort, maxRetriesPerRequest: null, lazyConnect: true });
            await connection.connect();
            await connection.ping();
            scanQueue = new Queue(QUEUE_NAME, { connection });
            await scanQueue.waitUntilReady();
            return scanQueue;
        } catch (e) {
            queueInitPromise = null;
            throw Object.assign(new Error('QUEUE_UNAVAILABLE'), { code: 'QUEUE_UNAVAILABLE' });
        }
    })();
    return queueInitPromise;
}

const ALLOWED_PAYLOAD_KEYS = new Set([
    'jobId', 'scanId', 'executionId', 'organizationId', 'connectionId', 'provider', 'scanType', 'enqueuedAt', 'resumeNodeIds'
]);

export function sanitizeJobPayload(jobData) {
    if (!jobData || typeof jobData !== 'object' || Array.isArray(jobData)) return {};
    const clean = {};
    for (const [k, v] of Object.entries(jobData)) {
        if (!ALLOWED_PAYLOAD_KEYS.has(k)) continue;
        if (k === 'resumeNodeIds') {
            if (Array.isArray(v) && v.length <= 100 && v.every(id => typeof id === 'string' && id.length <= 128)) {
                clean[k] = [...new Set(v)];
            }
            continue;
        }
        clean[k] = v;
    }
    return clean;
}

export async function enqueueJob(jobData) {
    const cleanPayload = sanitizeJobPayload(jobData);
    if (!cleanPayload.jobId || !cleanPayload.scanId || !cleanPayload.organizationId || !cleanPayload.connectionId) {
        throw Object.assign(new Error('INVALID_QUEUE_PAYLOAD'), { code: 'INVALID_QUEUE_PAYLOAD' });
    }
    const queue = await getQueue();
    try {
        const job = await queue.add('scan', cleanPayload, {
            jobId: cleanPayload.jobId,
            attempts: 3,
            backoff: { type: 'exponential', delay: 1000 },
            removeOnComplete: false,
            removeOnFail: false
        });
        return job;
    } catch (e) {
        if (scanQueue === queue) scanQueue = null;
        queueInitPromise = null;
        throw Object.assign(new Error(e?.code || 'QUEUE_ENQUEUE_FAILED'), { code: e?.code || 'QUEUE_ENQUEUE_FAILED' });
    }
}

export function resetQueueForTests() {
    scanQueue = null;
    queueInitPromise = null;
}

export async function listenWorkerQueue(processorFn) {
    const { Worker } = await import('bullmq');
    const { default: Redis } = await import('ioredis');
    const connection = new Redis({ host: redisHost, port: redisPort, maxRetriesPerRequest: null });
    await connection.ping();
    const worker = new Worker(QUEUE_NAME, async (job) => processorFn(job.data), { connection, concurrency: 5 });
    worker.on('failed', (job, err) => console.error(`[BULLMQ WORKER] Job ${job?.id} failed:`, err?.message || 'unknown error'));
    return worker;
}
