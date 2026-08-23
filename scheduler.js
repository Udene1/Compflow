import { loadClients } from './core/registry.js';
import { log } from './core/logger.js';
import { createJob } from './core/jobs.js';
import { enqueueJob } from './core/queue.js';
import { runScan } from './core/scanner.js';
import { generatePdfReport, generateReport, sendReport } from './core/reporter.js';

/**
 * Autonomous Scheduled Compliance Sweeps Engine
 * Triggered by cron, serverless timer, or HTTP dispatch to execute recurring scans.
 * 
 * Supports:
 * - Tenant filtering by schedule frequency (daily, weekly, continuous)
 * - Custom governance policy evaluation
 * - Automated PDF/HTML compliance report compilation and email distribution
 */
export async function handler(event = {}) {
    const frequency = event.frequency || 'daily';
    log.info(`🚀 AUTONOMOUS SCHEDULER: Triggering ${frequency.toUpperCase()} compliance sweeps...`);

    const resultsSummary = {
        dispatchedCount: 0,
        directCompletedCount: 0,
        tenants: []
    };

    try {
        // 1. Load active tenants from registry
        const clients = await loadClients();
        const activeClients = clients.filter(c => c.status !== 'paused' && c.status !== 'disabled');
        log.info(`[REGISTRY] Found ${activeClients.length} active tenants eligible for scheduled sweep.`);

        for (const client of activeClients) {
            // Check if tenant schedule matches current sweep frequency
            const clientFreq = client.scheduleFrequency || 'daily';
            if (frequency !== 'all' && clientFreq !== frequency) {
                continue;
            }

            const jobId = await createJob(client.id, 'scheduled');
            log.info(`➤ Dispatching scheduled governance sweep for tenant: ${client.name} (${client.id}) — Job: ${jobId}`);

            // If queue service is available, dispatch to worker queue
            if (process.env.USE_QUEUE === 'true') {
                await enqueueJob({
                    ...client,
                    jobId,
                    frequency
                });
                resultsSummary.dispatchedCount++;
                resultsSummary.tenants.push({ id: client.id, name: client.name, mode: 'queued', jobId });
            } else {
                // Direct Autonomous Sweep Execution
                try {
                    const { resources } = await runScan(client.provider, client.credentials || {}, client.customPolicies || null);
                    const anomalies = (resources || []).filter(r => r.severity !== 'pass');
                    
                    // Generate Compliance Reports
                    const summary = { resolved: 0, escalated: anomalies.length, details: anomalies.map(a => ({ name: a.name, status: 'escalated', issue: a.issue })) };
                    const reportHtml = generateReport(client.name, resources, summary);

                    if (client.email) {
                        log.info(`[SCHEDULER] Delivering automated ${frequency} executive report to ${client.email}...`);
                        await sendReport(client.email, client.name, reportHtml);
                    }

                    resultsSummary.directCompletedCount++;
                    resultsSummary.tenants.push({
                        id: client.id,
                        name: client.name,
                        mode: 'direct',
                        jobId,
                        resourcesCount: resources.length,
                        anomaliesCount: anomalies.length
                    });
                } catch (err) {
                    log.warn(`[SCHEDULER] Sweep failed for tenant ${client.name}:`, err.message);
                    resultsSummary.tenants.push({ id: client.id, name: client.name, mode: 'failed', error: err.message });
                }
            }
        }

        log.info(`✨ Autonomous scheduled sweep complete. Dispatched: ${resultsSummary.dispatchedCount}, Completed: ${resultsSummary.directCompletedCount}`);
        return {
            statusCode: 200,
            body: resultsSummary
        };

    } catch (e) {
        log.error("❌ SCHEDULER EXECUTION FAILED:", e);
        throw e;
    }
}
