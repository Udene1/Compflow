import { getJob } from '../core/jobs.js';
import { getExecutionGraph, getResumableNodes } from '../core/execution_engine.js';

/**
 * Job Status API — polling endpoint with durable execution state.
 * GET /api/job-status?jobId=xxx
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method Not Allowed' });

    const { jobId } = req.query;
    if (!jobId) return res.status(400).json({ error: 'Missing jobId' });

    try {
        const job = await getJob(jobId);
        if (!job) return res.status(404).json({ error: 'Job not found' });

        let execution = null;
        try {
            const graph = await getExecutionGraph(job.clientId || 'org_default', jobId);
            const resumable = await getResumableNodes(job.clientId || 'org_default', jobId);
            execution = {
                ...graph,
                resumableNodeIds: resumable.map(node => node.id)
            };
        } catch (graphError) {
            // Older jobs may predate the execution graph. Do not make status unavailable.
            console.warn('[JOB-STATUS] Execution graph unavailable:', graphError.message);
        }

        return res.status(200).json({
            jobId: job.jobId,
            status: job.status,
            progress: job.progress,
            logs: job.logs || [],
            resources: job.resources || [],
            errorMessage: job.errorMessage || null,
            createdAt: job.createdAt,
            updatedAt: job.updatedAt,
            completedAt: job.completedAt || null,
            execution
        });
    } catch (e) {
        console.error('[JOB-STATUS] Error:', e.message);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
