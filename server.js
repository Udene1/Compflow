import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

// Import handlers & core modules
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
import { handler as workerHandler } from './worker.js';
import { listenWorkerQueue } from './core/queue.js';
import { initDb } from './core/db.js';

const app = express();

// Trust reverse proxies (Cloudflare, Nginx, Azure ALB)
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ── Rate Limiting & DoS Defense ──
// General API Rate Limiter (300 requests per 15 minutes per IP)
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'API rate limit exceeded. Please try again later.' },
    skip: (req) => req.path === '/health' || req.path === '/api/job-stream'
});

// Stricter Rate Limiter for compute-heavy actions (Scans, AI Chat, Auditor Token generation)
const heavyActionLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    limit: 30,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'Heavy operation rate limit exceeded. Please wait 5 minutes before retrying.' }
});

app.use('/api/', generalLimiter);

const PORT = process.env.PORT || 3000;

// Lambda Adapter to run lambda handlers natively in Express
function lambdaAdapter(handler) {
    return async (req, res) => {
        try {
            const event = {
                httpMethod: req.method,
                path: req.path,
                headers: req.headers,
                queryStringParameters: req.query || null,
                body: JSON.stringify(req.body || {}),
                requestContext: {}
            };

            const result = await handler(event);

            if (result.headers) {
                for (const [key, val] of Object.entries(result.headers)) {
                    res.setHeader(key, val);
                }
            }

            const statusCode = result.statusCode || 200;
            res.status(statusCode);

            if (typeof result.body === 'string') {
                try {
                    const parsed = JSON.parse(result.body);
                    res.json(parsed);
                } catch {
                    res.send(result.body);
                }
            } else if (result.body) {
                res.json(result.body);
            } else {
                res.end();
            }
        } catch (err) {
            console.error('Adapter crash:', err);
            res.status(500).json({ error: 'Internal Server Error', message: err.message });
        }
    };
}

// Map HTTP Routes to Handlers
app.post('/api/trigger', heavyActionLimiter, lambdaAdapter(schedulerHandler));
app.all('/api/tenants', tenantsHandler);
app.all('/api/tenants/toggle', tenantsHandler);
app.post('/api/scan', heavyActionLimiter, scanHandler);
app.all('/api/validate', validateHandler);
app.post('/api/monitoring', lambdaAdapter(monitoringHandler));
app.post('/api/jobs', lambdaAdapter(jobsHandler));
app.get('/api/job-status', jobStatusHandler);
app.get('/api/job-stream', jobStreamHandler);
app.post('/api/chat', heavyActionLimiter, lambdaAdapter(chatHandler));
app.all('/api/auditor*', auditorHandler);

// Health Check Route
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Initialize Database & Start Worker Daemon
async function startApp() {
    await initDb();
    
    // Start BullMQ Redis Queue Listener
    listenWorkerQueue(workerHandler);

    app.listen(PORT, () => {
        console.log(`[HTTP SERVER] ComplianceFlow API server listening on port ${PORT}`);
    });
}

startApp().catch(err => {
    console.error('Failed to initialize server:', err);
});
