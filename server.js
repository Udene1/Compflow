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
import remediateHandler from './api/remediate.js';
import authRouter from './api/auth.js';
import { handler as workerHandler } from './worker.js';
import { listenWorkerQueue } from './core/queue.js';
import { initDb } from './core/db.js';

// Auth & RBAC Middleware
import { requireAuth, optionalAuth } from './core/auth_guard.js';
import { ROLES } from './core/auth.js';

const app = express();

// Trust reverse proxies (Cloudflare, Nginx, Azure ALB)
app.set('trust proxy', 1);

// ── Production CORS Configuration with Origin Whitelist ──
const ALLOWED_ORIGINS = [
    'https://compflow.icu',
    'https://www.compflow.icu',
    'https://api.compflow.icu',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173',
    'http://127.0.0.1:5173'
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (curl, server-to-server, mobile probes)
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin) || origin.endsWith('.compflow.icu')) {
            return callback(null, true);
        }
        return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

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

// Auth endpoint rate limiter (prevents brute-force on login/dev-login)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too Many Requests', message: 'Authentication rate limit exceeded. Please wait before retrying.' }
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
                requestContext: {},
                // Pass authenticated user context to lambda handlers
                authContext: req.user || null
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

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC ROUTES — No authentication required
// ─────────────────────────────────────────────────────────────────────────────

// Health Check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Authentication Routes (login/logout/callback/providers)
app.use('/api/auth', authLimiter, authRouter);

// ─────────────────────────────────────────────────────────────────────────────
// PROTECTED ROUTES — Require valid session + RBAC enforcement
// ─────────────────────────────────────────────────────────────────────────────

// ── Scan Operations (ENGINEER+ can initiate scans) ──
app.post('/api/scan',
    heavyActionLimiter,
    requireAuth([ROLES.ENGINEER]),
    scanHandler
);

// ── Autonomous Sweep Trigger (ADMIN+ can trigger org-wide sweeps) ──
app.post('/api/trigger',
    heavyActionLimiter,
    requireAuth([ROLES.ADMIN]),
    lambdaAdapter(schedulerHandler)
);

// ── Tenant / Cloud Connection Management ──
// GET: Any authenticated user can list tenants (filtered by org)
// POST/PATCH: Only ADMIN+ can create or modify tenants
app.get('/api/tenants',
    requireAuth([ROLES.VIEWER]),
    tenantsHandler
);
app.post('/api/tenants',
    requireAuth([ROLES.ADMIN]),
    tenantsHandler
);
app.patch('/api/tenants',
    requireAuth([ROLES.ADMIN]),
    tenantsHandler
);
app.all('/api/tenants/toggle',
    requireAuth([ROLES.ADMIN]),
    tenantsHandler
);

// ── Credential Validation (ENGINEER+ can validate cloud credentials) ──
app.post('/api/validate',
    requireAuth([ROLES.ENGINEER]),
    validateHandler
);

// ── Job Monitoring & Streaming ──
// Job status polling: any authenticated user can check their jobs
app.get('/api/job-status',
    requireAuth([ROLES.VIEWER]),
    jobStatusHandler
);
// SSE job stream: any authenticated user can stream results
app.get('/api/job-stream',
    requireAuth([ROLES.VIEWER]),
    jobStreamHandler
);

// ── Infrastructure Monitoring (ADMIN+) ──
app.post('/api/monitoring',
    requireAuth([ROLES.ADMIN]),
    lambdaAdapter(monitoringHandler)
);

// ── Job Management (ADMIN+ can manage job queue) ──
app.post('/api/jobs',
    requireAuth([ROLES.ADMIN]),
    lambdaAdapter(jobsHandler)
);

// ── AI Chat (ENGINEER+ can interact with compliance AI) ──
app.post('/api/chat',
    heavyActionLimiter,
    requireAuth([ROLES.ENGINEER]),
    lambdaAdapter(chatHandler)
);

// ── Remediation Engine (ENGINEER+ can trigger dry-run & live auto-fixes) ──
app.all(['/api/remediate', '/api/remediation'],
    heavyActionLimiter,
    requireAuth([ROLES.ENGINEER]),
    remediateHandler
);

// ── Auditor Portal ──
// Token generation: ADMIN+ can issue auditor tokens
// Export: AUDITOR+ can download evidence packages (also verified via auditor token)
// Verify: Any authenticated user can verify package integrity
app.all('/api/auditor*',
    requireAuth([ROLES.AUDITOR]),
    auditorHandler
);

// ─────────────────────────────────────────────────────────────────────────────
// Catch-all for undefined API routes
// ─────────────────────────────────────────────────────────────────────────────
app.all('/api/*', (req, res) => {
    res.status(404).json({ error: 'Not Found', message: `API endpoint ${req.method} ${req.path} does not exist.` });
});

// Initialize Database & Start Worker Daemon
async function startApp() {
    await initDb();
    
    // Start BullMQ Redis Queue Listener
    listenWorkerQueue(workerHandler);

    app.listen(PORT, () => {
        console.log(`[HTTP SERVER] ComplianceFlow API server listening on port ${PORT}`);
        console.log(`[AUTH] Route protection: ENABLED — all /api/* routes require authentication`);
        console.log(`[RBAC] Role hierarchy: OWNER > ADMIN > ENGINEER > AUDITOR > VIEWER`);
    });
}

startApp().catch(err => {
    console.error('Failed to initialize server:', err);
});
