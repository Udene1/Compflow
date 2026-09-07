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
import { requireAuth } from './core/auth_guard.js';
import { ROLES } from './core/auth.js';

const app = express();
app.set('trust proxy', 1);

const ALLOWED_ORIGINS = [
    'https://compflow.icu', 'https://www.compflow.icu', 'https://api.compflow.icu',
    'http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin) || origin.endsWith('.compflow.icu')) return callback(null, true);
        return callback(new Error('CORS origin blocked'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.use(express.json({ limit: '10mb' }));

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'API rate limit exceeded. Please try again later.' },
    skip: (req) => req.path === '/health' || req.path === '/api/job-stream'
});
const heavyActionLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'Heavy operation rate limit exceeded. Please wait 5 minutes before retrying.' }
});
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 50, standardHeaders: 'draft-7', legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'Authentication rate limit exceeded. Please wait before retrying.' }
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
            console.error('Adapter crash:', err);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    };
}

app.get('/health', (req, res) => res.json({ status: 'OK', timestamp: new Date().toISOString() }));
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

// Durable execution graph: read for viewers, resume requires an authenticated engineer.
app.get('/api/execution-graph', requireAuth([ROLES.VIEWER]), executionGraphHandler);
app.post('/api/execution-graph', requireAuth([ROLES.ENGINEER]), executionGraphHandler);

app.post('/api/monitoring', requireAuth([ROLES.ADMIN]), lambdaAdapter(monitoringHandler));
app.post('/api/jobs', requireAuth([ROLES.ADMIN]), lambdaAdapter(jobsHandler));
app.post('/api/chat', heavyActionLimiter, requireAuth([ROLES.ENGINEER]), lambdaAdapter(chatHandler));
app.all(['/api/remediate', '/api/remediation'], heavyActionLimiter, requireAuth([ROLES.ENGINEER]), remediateHandler);
app.all('/api/auditor*', requireAuth([ROLES.AUDITOR]), auditorHandler);

app.all('/api/*', (req, res) => res.status(404).json({ error: 'Not Found', message: `API endpoint ${req.method} ${req.path} does not exist.` }));

async function startApp() {
    await initDb();
    await listenWorkerQueue(durableWorkerHandler);
    app.listen(PORT, () => {
        console.log(`[HTTP SERVER] ComplianceFlow API server listening on port ${PORT}`);
        console.log('[AUTH] Route protection: ENABLED — all /api/* routes require authentication');
        console.log('[EXECUTION] Durable graph worker: ENABLED');
        console.log('[RBAC] Role hierarchy: OWNER > ADMIN > ENGINEER > AUDITOR > VIEWER');
    });
}

startApp().catch(err => {
    console.error('Failed to initialize server:', err);
    process.exit(1);
});
