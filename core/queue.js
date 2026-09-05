const redisHost = process.env.REDIS_HOST || 'localhost';
const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);
const QUEUE_NAME = 'scan_jobs';

let scanQueue = null;

async function getQueue() {
    if (scanQueue) return scanQueue;
    try {
        const { Queue } = await import('bullmq');
        const { default: Redis } = await import('ioredis');
        const connection = new Redis({
            host: redisHost,
            port: redisPort,
            maxRetriesPerRequest: null,
            lazyConnect: true
        });
        scanQueue = new Queue(QUEUE_NAME, { connection });
        return scanQueue;
    } catch (e) {
        return null;
    }
}

const SENSITIVE_PAYLOAD_KEYS = [
    'credentials', 'clientSecret', 'accessKey', 'accessKeyId', 
    'secretKey', 'secretAccessKey', 'privateKey', 'token', 
    'apiToken', 'serviceAccountJson', 'password', 'client_secret'
];

export function sanitizeJobPayload(jobData) {
    if (!jobData || typeof jobData !== 'object') return jobData;
    const clean = {};
    for (const [k, v] of Object.entries(jobData)) {
        if (SENSITIVE_PAYLOAD_KEYS.includes(k)) {
            continue; // Strictly omit raw credentials from queue payload
        }
        clean[k] = v;
    }
    return clean;
}

/**
 * Enqueue a job into BullMQ
 * @param {Object} jobData - Payload containing jobId, clientId, provider, connectionId, email (NO credentials)
 */
export async function enqueueJob(jobData) {
    const cleanPayload = sanitizeJobPayload(jobData);
    try {
        const queue = await getQueue();
        if (!queue) {
            console.log(`[QUEUE-FALLBACK] BullMQ queue unavailable. Processing in direct mode for job: ${cleanPayload.jobId}`);
            return { id: cleanPayload.jobId || 'fallback-id', data: cleanPayload };
        }

        const addPromise = queue.add('scan', cleanPayload, {
            attempts: 3,
            backoff: {
                type: 'exponential',
                delay: 1000
            },
            removeOnComplete: true,
            removeOnFail: false
        });

        // Timeout race so execution never hangs if Redis daemon is unreachable
        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Redis connection timeout')), 500)
        );

        const job = await Promise.race([addPromise, timeoutPromise]);
        console.log(`[BULLMQ] Enqueued job ${job.id} (jobId: ${cleanPayload.jobId}) without credentials`);
        return job;
    } catch (err) {
        console.log(`[QUEUE-FALLBACK] BullMQ direct fallback (${err.message}) for job: ${cleanPayload.jobId}`);
        return { id: cleanPayload.jobId || 'fallback-id', data: cleanPayload };
    }
}

/**
 * Listen and process jobs from BullMQ
 * @param {Function} processorFn - Async function (job) => void
 */
export async function listenWorkerQueue(processorFn) {
    try {
        const { Worker } = await import('bullmq');
        const { default: Redis } = await import('ioredis');
        const connection = new Redis({
            host: redisHost,
            port: redisPort,
            maxRetriesPerRequest: null
        });

        console.log(`[BULLMQ] Starting Worker on queue '${QUEUE_NAME}' connected to ${redisHost}:${redisPort}...`);

        const worker = new Worker(
            QUEUE_NAME,
            async (job) => {
                console.log(`[BULLMQ WORKER] Processing job ${job.id} (jobId: ${job.data.jobId})...`);
                await processorFn(job.data);
            },
            { connection, concurrency: 5 }
        );

        worker.on('completed', (job) => {
            console.log(`[BULLMQ WORKER] Job ${job.id} completed.`);
        });

        worker.on('failed', (job, err) => {
            console.error(`[BULLMQ WORKER] Job ${job?.id} failed:`, err.message);
        });

        return worker;
    } catch (e) {
        console.warn('[BULLMQ] Failed to initialize worker listener:', e.message);
        return null;
    }
}
