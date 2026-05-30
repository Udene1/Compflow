import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { loadClients } from './core/registry.js';
import { log } from './core/logger.js';
import { createJob } from './core/jobs.js';

const sqs = new SQSClient({ region: process.env.AWS_REGION || "us-east-1" });
const QUEUE_URL = process.env.SCAN_QUEUE_URL;

/**
 * Scheduler Handler
 * Triggered by EventBridge cron or HTTP POST to dispatch scans to workers.
 * Creates a job record per tenant before dispatching to SQS.
 */
export async function handler(event) {
    log.info("🚀 SCHEDULER: Triggering automated compliance scans...");

    try {
        // 1. Load all tenants from DynamoDB
        const clients = await loadClients();
        log.info(`[REGISTRY] Found ${clients.length} tenants active.`);

        // 2. Create a job and dispatch one message per tenant to SQS
        for (const client of clients) {
            // Create a tracked job for this scheduled scan
            const jobId = await createJob(client.id, 'scheduled');
            log.info(`➤ Dispatching worker for tenant: ${client.name} (${client.id}) — Job: ${jobId}`);
            
            await sqs.send(new SendMessageCommand({
                QueueUrl: QUEUE_URL,
                MessageBody: JSON.stringify({ ...client, jobId })
            }));
        }

        log.info("✨ All scans dispatched successfully.");
        return { statusCode: 200, body: `Dispatched ${clients.length} scans.` };

    } catch (e) {
        log.error("❌ SCHEDULER FAILED:", e);
        throw e;
    }
}
