import { loadClients } from './core/registry.js';
import { log } from './core/logger.js';
import { createJob } from './core/jobs.js';
import { enqueueJob } from './core/queue.js';
import { runScan } from './core/scanner.js';
import { generateReport, sendReport } from './core/reporter.js';

/**
 * Autonomous scheduled compliance sweep engine.
 * Runs inside the current application runtime; BullMQ is used for durable
 * dispatch and PostgreSQL remains authoritative for job state.
 */
export async function handler(event = {}) {
    const frequency = event.frequency || 'daily';
    log.info(`AUTONOMOUS SCHEDULER: Triggering ${frequency.toUpperCase()} compliance sweeps...`);

    const resultsSummary = { dispatchedCount: 0, directCompletedCount: 0, tenants: [] };

    try {
        const clients = await loadClients();
        const activeClients = clients.filter(c => c.status !== 'paused' && c.status !== 'disabled');
        log.info(`[REGISTRY] Found ${activeClients.length} active tenants eligible for scheduled sweep.`);

        for (const client of activeClients) {
            const clientFreq = client.scheduleFrequency || 'daily';
            if (frequency !== 'all' && clientFreq !== frequency) continue;

            const organizationId = client.orgId || client.organizationId || null;
            const jobId = await createJob(client.id, 'scheduled', organizationId);
            log.info(`Dispatching scheduled governance sweep for tenant: ${client.name} (${client.id}) — Job: ${jobId}`);

            if (process.env.USE_QUEUE === 'true') {
                const { credentials, apiToken, clientSecret, serviceAccountJson, ...safeClient } = client;
                await enqueueJob({
                    ...safeClient,
                    jobId,
                    organizationId,
                    frequency,
                    scanType: 'scheduled',
                    enqueuedAt: new Date().toISOString()
                });
                resultsSummary.dispatchedCount++;
                resultsSummary.tenants.push({ id: client.id, name: client.name, mode: 'queued', jobId });
            } else {
                try {
                    const { resources } = await runScan(client.provider, client.credentials || {}, client.customPolicies || null);
                    const anomalies = (resources || []).filter(r => r.severity !== 'pass');
                    const summary = {
                        resolved: 0,
                        escalated: anomalies.length,
                        details: anomalies.map(a => ({ name: a.name, status: 'escalated', issue: a.issue }))
                    };
                    const reportHtml = generateReport(client.name, resources, summary);
                    if (client.email) await sendReport(client.email, client.name, reportHtml);
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

        log.info(`Autonomous scheduled sweep complete. Dispatched: ${resultsSummary.dispatchedCount}, Completed: ${resultsSummary.directCompletedCount}`);
        return { statusCode: 200, body: resultsSummary };
    } catch (error) {
        log.error('SCHEDULER EXECUTION FAILED:', error);
        throw error;
    }
}
