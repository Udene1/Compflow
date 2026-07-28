import { Queue, Worker } from 'bullmq';
import Redis from 'ioredis';

const redisHost = process.env.REDIS_HOST || 'localhost';
const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);

const connection = new Redis({
    host: redisHost,
    port: redisPort,
    maxRetriesPerRequest: null
});

const QUEUE_NAME = 'scan_jobs';

export const scanQueue = new Queue(QUEUE_NAME, { connection });

/**
 * Enqueue a job into BullMQ
 * @param {Object} jobData - Payload containing jobId, clientId, provider, credentials, email
 */
export async function enqueueJob(jobData) {
    const job = await scanQueue.add('scan', jobData, {
        attempts: 3,
        backoff: {
            type: 'exponential',
            delay: 1000
        },
        removeOnComplete: true,
        removeOnFail: false
    });

    console.log(`[BULLMQ] Enqueued job ${job.id} (jobId: ${jobData.jobId})`);
    return job;
}

/**
 * Listen and process jobs from BullMQ
 * @param {Function} processorFn - Async function (job) => void
 */
export function listenWorkerQueue(processorFn) {
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
}
