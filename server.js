import express from 'express';
import cors from 'cors';

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
import { handler as workerHandler } from './worker.js';
import { listenWorkerQueue } from './core/queue.js';
import { initDb } from './core/db.js';

const app = express();
app.use(cors());
app.use(express.json());

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
app.post('/api/trigger', lambdaAdapter(schedulerHandler));
app.all('/api/tenants', tenantsHandler);
app.all('/api/tenants/toggle', tenantsHandler);
app.post('/api/scan', scanHandler);
app.all('/api/validate', validateHandler);
app.post('/api/monitoring', lambdaAdapter(monitoringHandler));
app.post('/api/jobs', lambdaAdapter(jobsHandler));
app.get('/api/job-status', jobStatusHandler);
app.get('/api/job-stream', jobStreamHandler);
app.post('/api/chat', lambdaAdapter(chatHandler));

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
