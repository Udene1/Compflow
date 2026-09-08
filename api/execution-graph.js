import crypto from 'crypto';
import { getExecutionGraph, getResumableNodes, recoverStaleNodeAttempts } from '../core/execution_engine.js';
import { recoverExpiredExecutionLeases, getExecutionRun, cancelExecutionRun } from '../core/execution_lifecycle.js';
import { enqueueJob } from '../core/queue.js';

function organizationIdFromRequest(req) {
  return req.user?.orgId || req.authContext?.orgId || null;
}

function snapshot(graph, execution, resumableNodeIds, recovery = {}) {
  const body = {
    ...graph,
    execution,
    live: true,
    observedAt: new Date().toISOString(),
    recovery,
    resumableNodeIds
  };
  return { body, hash: crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex') };
}

async function readState(organizationId, executionId) {
  const recoveredExecutions = await recoverExpiredExecutionLeases({ organizationId, executionId });
  const recoveredAttempts = await recoverStaleNodeAttempts({ organizationId, executionId });
  const execution = await getExecutionRun(organizationId, executionId);
  const graph = await getExecutionGraph(organizationId, executionId);
  if (!execution && !graph.nodes.length) throw new Error('EXECUTION_NOT_FOUND');
  const resumableNodeIds = (await getResumableNodes(organizationId, executionId)).map(node => node.id);
  return snapshot(graph, execution, resumableNodeIds, {
    executionsRecovered: recoveredExecutions.map(run => run.id),
    attemptsRecovered: recoveredAttempts.map(attempt => attempt.id)
  });
}

function writeSse(res, event, data, id = null) {
  if (id) res.write(`id: ${id}\n`);
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

async function streamExecution(res, organizationId, executionId, req) {
  res.status(200);
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  let stopped = false;
  let lastHash = req.headers['last-event-id'] || null;
  let timer;
  const intervalMs = Math.max(1000, Math.min(Number(process.env.COMPFLOW_GRAPH_STREAM_INTERVAL_MS) || 2000, 30000));

  const close = () => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    if (!res.writableEnded) res.end();
  };
  req.on('close', close);

  const tick = async () => {
    if (stopped || res.writableEnded) return;
    try {
      const state = await readState(organizationId, executionId);
      if (state.hash !== lastHash) {
        lastHash = state.hash;
        writeSse(res, 'execution', state.body, state.hash);
      } else {
        writeSse(res, 'heartbeat', { observedAt: new Date().toISOString() });
      }
      if (['SUCCEEDED', 'CANCELLED'].includes(state.body.execution?.status)) close();
    } catch (error) {
      writeSse(res, 'error', { error: error?.message === 'EXECUTION_NOT_FOUND' ? 'EXECUTION_NOT_FOUND' : 'EXECUTION_GRAPH_STREAM_FAILED' });
      close();
    }
  };

  writeSse(res, 'ready', { executionId, intervalMs });
  await tick();
  if (!stopped) timer = setInterval(() => { void tick(); }, intervalMs);
}

async function queueResume({ organizationId, executionId, nodeIds = null, action = 'resume' }) {
  const execution = await getExecutionRun(organizationId, executionId);
  if (!execution) throw new Error('EXECUTION_NOT_FOUND');
  if (execution.status === 'SUCCEEDED') throw new Error('EXECUTION_ALREADY_SUCCEEDED');
  if (execution.status === 'CANCELLED') throw new Error('EXECUTION_CANCELLED');

  const resumable = await getResumableNodes(organizationId, executionId);
  const requested = nodeIds ? resumable.filter(node => nodeIds.includes(node.id)) : resumable;
  if (!requested.length) throw new Error('NO_DEPENDENCY_READY_NODES');

  const graph = await getExecutionGraph(organizationId, executionId);
  const executionNode = graph.nodes.find(node => node.node_type === 'EXECUTION');
  const metadata = executionNode?.metadata || execution.metadata || {};
  const { connectionId, scanId, provider } = metadata;
  if (!connectionId || !scanId || !provider) throw new Error('EXECUTION_MISSING_CONNECTION_METADATA');

  const jobId = `${action}-${executionId}-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  await enqueueJob({
    jobId,
    scanId,
    executionId,
    organizationId,
    connectionId,
    provider,
    scanType: 'resume',
    resumeNodeIds: requested.map(node => node.id),
    enqueuedAt: new Date().toISOString(),
    normalMetadata: JSON.stringify({ control: action })
  });
  return { success: true, status: 'queued', executionId, jobId, action, resumableNodeIds: requested.map(node => node.id) };
}

function controlAction(req) {
  return req.body?.action || req.query?.action || null;
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!['GET', 'POST'].includes(req.method)) return res.status(405).json({ error: 'Method Not Allowed' });

  const organizationId = organizationIdFromRequest(req);
  const executionId = req.query?.executionId || req.body?.executionId;
  if (!organizationId) return res.status(403).json({ error: 'Organization context required' });
  if (!executionId) return res.status(400).json({ error: 'Missing executionId' });

  try {
    if (req.method === 'GET' && req.query?.stream === '1') return streamExecution(res, organizationId, executionId, req);

    if (req.method === 'POST') {
      const action = controlAction(req);
      if (action === 'cancel') {
        const execution = await cancelExecutionRun({ organizationId, executionId, reason: req.body?.reason });
        return res.status(200).json({ success: true, status: execution.status, executionId, action });
      }
      if (action === 'resume' || action === 'retry') {
        const nodeIds = Array.isArray(req.body?.nodeIds) ? req.body.nodeIds.slice(0, 100) : null;
        const result = await queueResume({ organizationId, executionId, nodeIds, action });
        return res.status(202).json(result);
      }
      return res.status(400).json({ error: 'Unsupported execution action' });
    }

    const state = await readState(organizationId, executionId);
    return res.status(200).json(state.body);
  } catch (error) {
    console.error('[EXECUTION-GRAPH] Request failed:', error?.message || error);
    const known = new Map([
      ['EXECUTION_NOT_FOUND', 404], ['EXECUTION_ALREADY_SUCCEEDED', 409], ['EXECUTION_CANCELLED', 409],
      ['EXECUTION_ALREADY_TERMINAL', 409], ['EXECUTION_CANCEL_CONFLICT', 409], ['NO_DEPENDENCY_READY_NODES', 409],
      ['EXECUTION_MISSING_CONNECTION_METADATA', 409], ['QUEUE_UNAVAILABLE', 503]
    ]);
    const status = known.get(error?.message) || (error?.code === 'QUEUE_UNAVAILABLE' ? 503 : 500);
    return res.status(status).json({ error: known.has(error?.message) ? error.message : error?.code === 'QUEUE_UNAVAILABLE' ? 'QUEUE_UNAVAILABLE' : 'EXECUTION_GRAPH_FAILED' });
  }
}
