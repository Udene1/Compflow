import { loadClients } from './core/registry.js';
import { log } from './core/logger.js';
import { createJob } from './core/jobs.js';
import { enqueueJob } from './core/queue.js';

/**
 * Scheduler Handler
 * Triggered by cron or HTTP POST to dispatch automated scans to workers.
 * Creates a job record per tenant before dispatching to BullMQ Redis Queue.
 */
export async function handler(event) {
    log.info("🚀 SCHEDULER: Triggering automated compliance scans...");

    try {
        // 1. Load all tenants
        const clients = await loadClients();
        log.info(`[REGISTRY] Found ${clients.length} tenants active.`);

        // 2. Create a job and dispatch one message per tenant to BullMQ
        for (const client of clients) {
            // Create a tracked job for this scheduled scan
            const jobId = await createJob(client.id, 'scheduled');
            log.info(`➤ Dispatching worker for tenant: ${client.name} (${client.id}) — Job: ${jobId}`);
            
            await enqueueJob({
                ...client,
                jobId
            });
        }

        log.info("✨ All scans dispatched successfully.");
        return { statusCode: 200, body: `Dispatched ${clients.length} scans.` };

    } catch (e) {
        log.error("❌ SCHEDULER FAILED:", e);
        throw e;
    }
}
