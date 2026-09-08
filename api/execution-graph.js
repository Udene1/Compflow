import { getExecutionGraph, getResumableNodes } from '../core/execution_engine.js';
import { recoverExpiredExecutionLeases } from '../core/execution_lifecycle.js';
import { recoverStaleNodeAttempts } from '../core/execution_engine.js';
import { getExecutionRun } from '../core/execution_lifecycle.js';
import { enqueueJob } from '../core/queue.js';

function organizationIdFromRequest(req) {
  return req.user?.orgId || req.authContext?.orgId || null;
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!['GET', 'POST'].includes(req.method)) return res.status(405).json({ error: 'Method Not Allowed' });

  const organizationId = organizationIdFromRequest(req);
  const executionId = req.query?.executionId || req.body?.executionId;
  if (!organizationId) return res.status(403).json({ error: 'Organization context required' });
  if (!executionId) return res.status(400).json({ error: 'Missing executionId' });

  try {
    if (req.method === 'GET') {
      const recoveredExecutions = await recoverExpiredExecutionLeases({ organizationId, executionId });
      const recoveredAttempts = await recoverStaleNodeAttempts({ organizationId, executionId });
      const graph = await getExecutionGraph(organizationId, executionId);
      if (!graph.nodes.length) return res.status(404).json({ error: 'Execution not found' });
      const execution = await getExecutionRun(organizationId, executionId);
      const resumableNodeIds = (await getResumableNodes(organizationId, executionId)).map(node => node.id);
      return res.status(200).json({
        ...graph,
        execution,
        live: true,
        observedAt: new Date().toISOString(),
        recovery: {
          executionsRecovered: recoveredExecutions.map(run => run.id),
          attemptsRecovered: recoveredAttempts.map(attempt => attempt.id)
        },
        resumableNodeIds
      });
    }

    const graph = await getExecutionGraph(organizationId, executionId);
    if (!graph.nodes.length) return res.status(404).json({ error: 'Execution not found' });

    const resumable = await getResumableNodes(organizationId, executionId);
    if (!resumable.length) return res.status(409).json({ error: 'No dependency-ready nodes to resume' });

    const executionNode = graph.nodes.find(node => node.node_type === 'EXECUTION');
    const metadata = executionNode?.metadata || {};
    const connectionId = metadata.connectionId;
    const scanId = metadata.scanId;
    const provider = metadata.provider;
    if (!connectionId || !scanId || !provider) return res.status(409).json({ error: 'Execution is missing resumable cloud connection metadata' });

    const resumableNodeIds = resumable.map(node => node.id);
    const jobId = `resume-${executionId}-${Date.now()}`;
    await enqueueJob({
      jobId,
      scanId,
      executionId,
      organizationId,
      connectionId,
      provider,
      scanType: 'resume',
      resumeNodeIds: resumableNodeIds,
      enqueuedAt: new Date().toISOString()
    });
    return res.status(202).json({ success: true, status: 'queued', executionId, jobId, resumableNodeIds });
  } catch (error) {
    console.error('[EXECUTION-GRAPH] Request failed:', error?.message || error);
    const code = error?.code === 'QUEUE_UNAVAILABLE' ? 'QUEUE_UNAVAILABLE' : 'EXECUTION_GRAPH_FAILED';
    return res.status(code === 'QUEUE_UNAVAILABLE' ? 503 : 500).json({ error: code });
  }
}
