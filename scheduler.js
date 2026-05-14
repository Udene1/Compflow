import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { loadClients } from './core/registry.js';
import { log } from './core/logger.js';

const sqs = new SQSClient({ region: process.env.AWS_REGION || "us-east-1" });
const QUEUE_URL = process.env.SCAN_QUEUE_URL;

/**
 * Scheduler Handler
 * Triggered by EventBridge or HTTP to dispatch scans to workers.
 */
export async function handler(event) {
    log.info("🚀 SCHEDULER: Triggering automated compliance scans...");

    try {
        // 1. Load all tenants from DynamoDB
        const clients = await loadClients();
        log.info(`[REGISTRY] Found ${clients.length} tenants active.`);

        // 2. Dispatch one message per tenant to SQS
        for (const client of clients) {
            log.info(`➤ Dispatching worker for tenant: ${client.name} (${client.id})`);
            
            await sqs.send(new SendMessageCommand({
                QueueUrl: QUEUE_URL,
                MessageBody: JSON.stringify(client)
            }));
        }

        log.info("✨ All scans dispatched successfully.");
        return { statusCode: 200, body: `Dispatched ${clients.length} scans.` };

    } catch (e) {
        log.error("❌ SCHEDULER FAILED:", e);
        throw e;
    }
}
