const redisHost = process.env.REDIS_HOST || 'localhost';
const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);
const QUEUE_NAME = 'scan_jobs';
let scanQueue = null;
let queueConnection = null;
let queueInitPromise = null;
let workerConnections = new Set();

function queueJobId(organizationId, jobId) { return `org-${organizationId}-job-${jobId}`; }

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
            queueConnection = connection;
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
    'jobId', 'scanId', 'executionId', 'clientId', 'organizationId', 'connectionId', 'provider', 'scanType', 'roleArn', 'enqueuedAt', 'resumeNodeIds', 'normalMetadata',
    'executionNodeType', 'executionNodeId', 'executionAttemptId', 'planHash'
]);
const PROVIDERS = new Set(['aws', 'azure', 'gcp', 'digitalocean', 'hetzner']);
const SCAN_TYPES = new Set(['initial', 'initial_onboarding_scan', 'manual', 'scheduled', 'resume', 'adhoc', 'execution_node']);

function boundedString(value, max = 128) { return typeof value === 'string' && value.length > 0 && value.length <= max ? value : null; }

export function sanitizeJobPayload(jobData) {
    if (!jobData || typeof jobData !== 'object' || Array.isArray(jobData)) return {};
    const clean = {};
    for (const [k, v] of Object.entries(jobData)) {
        if (!ALLOWED_PAYLOAD_KEYS.has(k)) continue;
        if (k === 'resumeNodeIds') {
            if (Array.isArray(v) && v.length <= 100 && v.every(id => boundedString(id, 128))) clean[k] = [...new Set(v)];
            continue;
        }
        if (k === 'normalMetadata') { if (typeof v === 'string' && v.length <= 2000) clean[k] = v; continue; }
        clean[k] = v;
    }
    return clean;
}

export async function enqueueJob(jobData) {
    const cleanPayload = sanitizeJobPayload(jobData);
    const isExecutionNode = cleanPayload.scanType === 'execution_node' || Boolean(cleanPayload.executionNodeType);
    if (!boundedString(cleanPayload.jobId) || !boundedString(cleanPayload.organizationId) || !boundedString(cleanPayload.executionId)) {
        throw Object.assign(new Error('INVALID_QUEUE_PAYLOAD'), { code: 'INVALID_QUEUE_PAYLOAD' });
    }
    if (!isExecutionNode && (!boundedString(cleanPayload.scanId) || !boundedString(cleanPayload.connectionId))) {
        throw Object.assign(new Error('INVALID_QUEUE_PAYLOAD'), { code: 'INVALID_QUEUE_PAYLOAD' });
    }
    if (!PROVIDERS.has(cleanPayload.provider) || !SCAN_TYPES.has(cleanPayload.scanType)) {
        throw Object.assign(new Error('INVALID_QUEUE_PAYLOAD'), { code: 'INVALID_QUEUE_PAYLOAD' });
    }
    if (!cleanPayload.enqueuedAt || Number.isNaN(Date.parse(cleanPayload.enqueuedAt))) {
        throw Object.assign(new Error('INVALID_QUEUE_PAYLOAD'), { code: 'INVALID_QUEUE_PAYLOAD' });
    }
    if (isExecutionNode && (!boundedString(cleanPayload.executionNodeType) || !boundedString(cleanPayload.executionNodeId) || !boundedString(cleanPayload.executionAttemptId) || !boundedString(cleanPayload.planHash, 128))) {
        throw Object.assign(new Error('INVALID_QUEUE_PAYLOAD'), { code: 'INVALID_QUEUE_PAYLOAD' });
    }
    const queue = await getQueue();
    try {
        const job = await queue.add(isExecutionNode ? 'execution_node' : 'scan', cleanPayload, {
            jobId: queueJobId(cleanPayload.organizationId, cleanPayload.jobId),
            attempts: 3,
            backoff: { type: 'exponential', delay: 1000 },
            removeOnComplete: false,
            removeOnFail: false
        });
        return job;
    } catch (e) {
        if (scanQueue === queue) { scanQueue = null; queueConnection = null; }
        queueInitPromise = null;
        throw Object.assign(new Error(e?.code || 'QUEUE_ENQUEUE_FAILED'), { code: e?.code || 'QUEUE_ENQUEUE_FAILED' });
    }
}

export function resetQueueForTests() { scanQueue = null; queueConnection = null; queueInitPromise = null; workerConnections.clear(); }

export async function closeQueue() {
    const queue = scanQueue; const connection = queueConnection;
    scanQueue = null; queueConnection = null; queueInitPromise = null;
    if (queue) await queue.close();
    if (connection) await connection.quit().catch(() => {});
    const connections = [...workerConnections]; workerConnections.clear();
    await Promise.all(connections.map(connection => connection.quit().catch(() => {})));
}

export async function listenWorkerQueue(processorFn) {
    const { Worker } = await import('bullmq');
    const { default: Redis } = await import('ioredis');
    const connection = new Redis({ host: redisHost, port: redisPort, maxRetriesPerRequest: null });
    await connection.ping(); workerConnections.add(connection);
    const worker = new Worker(QUEUE_NAME, async (job) => processorFn(job.data, job), { connection, concurrency: 5 });
    worker.on('failed', (job, err) => console.error(`[BULLMQ WORKER] Job ${job?.id} failed:`, err?.message || 'unknown error'));
    worker.on('closed', () => workerConnections.delete(connection));
    return worker;
}
