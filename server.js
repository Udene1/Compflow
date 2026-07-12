import express from 'express';
import cors from 'cors';
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';

// Import handlers
import { handler as schedulerHandler } from './scheduler.js';
import tenantsHandler from './api/tenants.js';
import { handler as scanHandler } from './api/lambda-scan.js';
import validateHandler from './api/validate.js';
import { handler as monitoringHandler } from './api/lambda-monitoring.js';
import { handler as jobsHandler } from './api/lambda-jobs.js';
import { handler as chatHandler } from './api/chat.js';
import { handler as workerHandler } from './worker.js';

const app = express();
app.use(cors());
app.use(express.json());

// Express port and environment configuration
const PORT = process.env.PORT || 3000;
const QUEUE_URL = process.env.SCAN_QUEUE_URL;
const REGION = process.env.AWS_REGION || 'us-east-1';

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
app.post('/api/scan', lambdaAdapter(scanHandler));
app.all('/api/validate', validateHandler);
app.post('/api/monitoring', lambdaAdapter(monitoringHandler));
app.post('/api/jobs', lambdaAdapter(jobsHandler));
app.post('/api/chat', lambdaAdapter(chatHandler));

// Health Check Route
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// SQS Worker Background Loop
const sqs = new SQSClient({ region: REGION });

async function startWorkerPoll() {
    if (!QUEUE_URL) {
        console.warn('[SQS WORKER] SCAN_QUEUE_URL environment variable is not defined. SQS polling is disabled.');
        return;
    }

    console.log(`[SQS WORKER] Starting polling loop on ${QUEUE_URL} in region ${REGION}...`);

    while (true) {
        try {
            const response = await sqs.send(new ReceiveMessageCommand({
                QueueUrl: QUEUE_URL,
                MaxNumberOfMessages: 1,
                WaitTimeSeconds: 20, // Long polling
                VisibilityTimeout: 900 // match 15 min handler timeout
            }));

            if (response.Messages && response.Messages.length > 0) {
                const message = response.Messages[0];
                console.log(`[SQS WORKER] Received message ID: ${message.MessageId}`);

                // Construct mock SQS Lambda trigger event
                const sqsEvent = {
                    Records: [
                        {
                            body: message.Body,
                            messageId: message.MessageId
                        }
                    ]
                };

                try {
                    // Execute the worker scan and remediation
                    await workerHandler(sqsEvent);
                    
                    // Successfully processed, delete from queue
                    await sqs.send(new DeleteMessageCommand({
                        QueueUrl: QUEUE_URL,
                        ReceiptHandle: message.ReceiptHandle
                    }));
                    console.log(`[SQS WORKER] Successfully processed and deleted message ID: ${message.MessageId}`);
                } catch (workerErr) {
                    console.error(`[SQS WORKER] Processing failed for message ID: ${message.MessageId}:`, workerErr);
                    // On failure, let VisibilityTimeout expire so message will be retried (or sent to DLQ by SQS policy)
                }
            }
        } catch (pollErr) {
            console.error('[SQS WORKER] Error polling from SQS:', pollErr);
            // Brief backoff on SQS network errors
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
}

// Start API Server
app.listen(PORT, () => {
    console.log(`[HTTP SERVER] ComplianceFlow API wrapper listening on port ${PORT}`);
    // Start SQS worker daemon
    startWorkerPoll();
});
