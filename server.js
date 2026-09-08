import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

import { handler as schedulerHandler } from './scheduler.js';
import tenantsHandler from './api/tenants.js';
import scanHandler from './api/scan.js';
import validateHandler from './api/validate.js';
import { handler as monitoringHandler } from './api/lambda-monitoring.js';
import { handler as jobsHandler } from './api/lambda-jobs.js';
import { handler as chatHandler } from './api/chat.js';
import jobStatusHandler from './api/job-status.js';
import jobStreamHandler from './api/job-stream.js';
import auditorHandler from './api/auditor.js';
import remediateHandler from './api/remediate.js';
import executionGraphHandler from './api/execution-graph.js';
import authRouter from './api/auth.js';
import onboardingRouter from './api/onboarding.js';
import { durableWorkerHandler } from './core/durable_worker.js';
import { listenWorkerQueue } from './core/queue.js';
import { initDb } from './core/db.js';
import { startExecutionRecovery } from './core/execution_recovery.js';
import { requireAuth } from './core/auth_guard.js';
import { ROLES } from './core/auth.js';

const app = express();
app.set('trust proxy', 1);

const ALLOWED_ORIGINS = new Set([
    'https://compflow.icu', 'https://www.compflow.icu', 'https://api.compflow.icu',
    'http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'
]);
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.has(origin)) return callback(null, true);
        return callback(new Error('CORS origin blocked'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Idempotency-Key']
}));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
    if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
app.use(express.json({ limit: process.env.COMPFLOW_JSON_LIMIT || '2mb' }));

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'API rate limit exceeded. Please try again later.' },
    skip: (req) => req.path === '/health'
});
const heavyActionLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'Heavy operation rate limit exceeded. Please wait 5 minutes before retrying.' }
});
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 50, standardHeaders: 'draft-7', legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'Authentication rate limit exceeded. Please wait before trying again.' }
});
app.use('/api/', generalLimiter);
const PORT = process.env.PORT || 3000;

function lambdaAdapter(handler) {
    return async (req, res) => {
        try {
            const event = {
                httpMethod: req.method, path: req.path, headers: req.headers,
                queryStringParameters: req.query || null, body: JSON.stringify(req.body || {}),
                requestContext: {}, authContext: req.user || null
            };
            const result = await handler(event);
            if (result.headers) for (const [key, val] of Object.entries(result.headers)) res.setHeader(key, val);
            res.status(result.statusCode || 200);
            if (typeof result.body === 'string') {
                try { res.json(JSON.parse(result.body)); } catch { res.send(result.body); }
            } else if (result.body) res.json(result.body); else res.end();
        } catch (err) {
            console.error('Adapter crash:', err?.message || 'unknown error');
            res.status(500).json({ error: 'Internal Server Error' });
        }
    };
}

app.get('/health', (req, res) => res.json({ status: 'OK', timestamp: new Date().toISOString() }));
app.get('/health/ready', async (req, res) => {
    try {
        const { default: pool } = await import('./core/db.js');
        await pool.query('SELECT 1');
        const { default: Redis } = await import('ioredis');
        const redis = new Redis({ host: process.env.REDIS_HOST || 'localhost', port: Number(process.env.REDIS_PORT) || 6379, lazyConnect: true, maxRetriesPerRequest: 1 });
        try { await redis.connect(); await redis.ping(); } finally { await redis.quit().catch(() => {}); }
        return res.status(200).json({ status: 'READY', timestamp: new Date().toISOString() });
    } catch (error) {
        console.error('[READINESS] check failed:', error?.message || 'unknown error');
        return res.status(503).json({ status: 'NOT_READY' });
    }
});
app.use('/api/auth', authLimiter, authRouter);
app.use('/api/onboarding', requireAuth(), onboardingRouter);
app.post('/api/scan', heavyActionLimiter, requireAuth([ROLES.ENGINEER]), scanHandler);
app.post('/api/trigger', heavyActionLimiter, requireAuth([ROLES.ADMIN]), lambdaAdapter(schedulerHandler));
app.get('/api/tenants', requireAuth([ROLES.VIEWER]), tenantsHandler);
app.post('/api/tenants', requireAuth([ROLES.ADMIN]), tenantsHandler);
app.patch('/api/tenants', requireAuth([ROLES.ADMIN]), tenantsHandler);
app.all('/api/tenants/toggle', requireAuth([ROLES.ADMIN]), tenantsHandler);
app.post('/api/validate', requireAuth([ROLES.ENGINEER]), validateHandler);
app.get('/api/job-status', requireAuth([ROLES.VIEWER]), jobStatusHandler);
app.get('/api/job-stream', requireAuth([ROLES.VIEWER]), jobStreamHandler);
app.get('/api/execution-graph', requireAuth([ROLES.VIEWER]), executionGraphHandler);
app.post('/api/execution-graph', requireAuth([ROLES.ENGINEER]), executionGraphHandler);
app.post('/api/monitoring', requireAuth([ROLES.ADMIN]), lambdaAdapter(monitoringHandler));
app.post('/api/jobs', requireAuth([ROLES.ADMIN]), lambdaAdapter(jobsHandler));
app.post('/api/chat', heavyActionLimiter, requireAuth([ROLES.ENGINEER]), lambdaAdapter(chatHandler));
app.all(['/api/remediate', '/api/remediation'], heavyActionLimiter, requireAuth([ROLES.ENGINEER]), remediateHandler);
app.all('/api/auditor*', requireAuth([ROLES.AUDITOR]), auditorHandler);
app.all('/api/*', (req, res) => res.status(404).json({ error: 'Not Found', message: `API endpoint ${req.method} ${req.path} does not exist.` }));
app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error?.type === 'entity.too.large' || error?.status === 413) return res.status(413).json({ error: 'REQUEST_TOO_LARGE', message: 'Request body exceeds the permitted limit.' });
    if (error?.type === 'entity.parse.failed' || error instanceof SyntaxError) return res.status(400).json({ error: 'INVALID_JSON', message: 'Request body must contain valid JSON.' });
    if (error?.message === 'CORS origin blocked') return res.status(403).json({ error: 'CORS_ORIGIN_BLOCKED' });
    console.error('[HTTP] Unhandled request error:', error?.message || error);
    return res.status(500).json({ error: 'Internal Server Error' });
});

let httpServer;
let stopRecovery;
let worker;
let shuttingDown = false;

async function startApp() {
    await initDb();
    stopRecovery = startExecutionRecovery({
        intervalMs: Number(process.env.COMPFLOW_RECOVERY_INTERVAL_MS) || 15000,
        staleAfterSeconds: Number(process.env.COMPFLOW_STALE_ATTEMPT_SECONDS) || 90
    });
    worker = await listenWorkerQueue(durableWorkerHandler);
    httpServer = app.listen(PORT, () => {
        console.log(`[HTTP SERVER] ComplianceFlow API server listening on port ${PORT}`);
        console.log('[AUTH] Route protection: ENABLED — all /api/* routes require authentication');
        console.log('[EXECUTION] Durable graph worker: ENABLED');
        console.log('[EXECUTION] Heartbeat + stale recovery: ENABLED');
        console.log('[EXECUTION] Live graph stream + controls: ENABLED');
        console.log('[RBAC] Role hierarchy: OWNER > ADMIN > ENGINEER > AUDITOR > VIEWER');
    });
}

async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[SHUTDOWN] Received ${signal}; stopping new work and draining services.`);
    stopRecovery?.();
    const forceTimer = setTimeout(() => { console.error('[SHUTDOWN] Graceful shutdown timed out.'); process.exit(1); }, 15000);
    forceTimer.unref?.();
    try {
        if (httpServer) await new Promise(resolve => httpServer.close(resolve));
        if (worker) await worker.close();
        const { default: pool } = await import('./core/db.js');
        await pool.end();
        clearTimeout(forceTimer);
        process.exit(0);
    } catch (error) {
        clearTimeout(forceTimer);
        console.error('[SHUTDOWN] Failed:', error?.message || error);
        process.exit(1);
    }
}
process.once('SIGTERM', () => void shutdown('SIGTERM'));
process.once('SIGINT', () => void shutdown('SIGINT'));

startApp().catch(err => {
    console.error('Failed to initialize server:', err?.message || err);
    process.exit(1);
});
