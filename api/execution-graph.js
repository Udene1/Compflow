import { getExecutionGraph, getResumableNodes } from '../core/execution_engine.js';
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
    const graph = await getExecutionGraph(organizationId, executionId);
    if (!graph.nodes.length) return res.status(404).json({ error: 'Execution not found' });
    if (req.method === 'GET') return res.status(200).json(graph);

    const resumable = await getResumableNodes(organizationId, executionId);
    if (!resumable.length) return res.status(409).json({ error: 'No dependency-ready nodes to resume' });

    const executionNode = graph.nodes.find(node => node.node_type === 'EXECUTION');
    const metadata = executionNode?.metadata || {};
    const connectionId = metadata.connectionId;
    const scanId = metadata.scanId;
    const provider = metadata.provider;
    if (!connectionId || !scanId || !provider) return res.status(409).json({ error: 'Execution is missing resumable cloud connection metadata' });

    const jobId = `resume-${executionId}-${Date.now()}`;
    await enqueueJob({ jobId, scanId, executionId, organizationId, connectionId, provider, scanType: 'resume', enqueuedAt: new Date().toISOString() });
    return res.status(202).json({ success: true, status: 'queued', executionId, jobId, resumableNodeIds: resumable.map(node => node.id) });
  } catch (error) {
    console.error('[EXECUTION-GRAPH] Request failed:', error?.message || error);
    const code = error?.code === 'QUEUE_UNAVAILABLE' ? 'QUEUE_UNAVAILABLE' : 'EXECUTION_GRAPH_FAILED';
    return res.status(code === 'QUEUE_UNAVAILABLE' ? 503 : 500).json({ error: code });
  }
}
