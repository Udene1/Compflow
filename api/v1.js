import express from 'express';
import { startComplianceExecution, finalizeComplianceDecision } from '../core/compliance_pipeline.js';
import { getExecutionGraph } from '../core/execution_engine.js';
import { getExecutionRun, cancelExecutionRun } from '../core/execution_lifecycle.js';
import { listExecutionEvents, appendExecutionEvent, getExecutionEventByIdempotencyKey } from '../core/execution_events.js';
import { approveExecutionNode, dispatchReadyPlanNodes, startPersistedPlanExecution } from '../core/plan_executor.js';
import { getDependencyAwareResumePlan } from '../core/execution_resume.js';
import { enqueueJob } from '../core/queue.js';
import { getEvidenceFreshness, verifyEvidenceIntegrity } from '../core/evidence.js';
import pool from '../core/db.js';
import { listProviders } from '../core/provider_registry.js';
import executionGraphHandler from './execution-graph.js';

const router = express.Router();
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const KEY = /^[A-Za-z0-9._:-]{1,128}$/;
const LIMIT = 100;

function org(req) { return req.user?.orgId || req.authContext?.orgId || null; }
function actor(req) { return req.user?.userId || req.user?.id || req.authContext?.userId || null; }
function executionId(value) { if (!ID.test(String(value || ''))) throw new Error('EXECUTION_ID_INVALID'); return String(value); }
function idempotency(req) { const value = req.get('Idempotency-Key'); if (value == null) return null; if (!KEY.test(value)) throw new Error('IDEMPOTENCY_KEY_INVALID'); return value; }
function page(value, fallback = 100) { const n = Number(value); return Number.isSafeInteger(n) ? Math.max(1, Math.min(n, LIMIT)) : fallback; }

router.get('/providers', (req, res) => res.json({ providers: listProviders() }));

router.post('/executions', async (req, res, next) => {
  try {
    const organizationId = org(req); if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
    const key = idempotency(req); const id = executionId(req.body?.executionId);
    if (!req.body?.intent || typeof req.body.intent !== 'object' || Array.isArray(req.body.intent)) return res.status(400).json({ error: 'INTENT_REQUIRED' });
    if (key) {
      const existingEvent = await getExecutionEventByIdempotencyKey({ organizationId, executionId: id, eventType: 'EXECUTION_CREATED', idempotencyKey: `create:${key}` });
      if (existingEvent) return res.status(200).json({ ...(existingEvent.payload?.result || {}), idempotencyKey: key, idempotentReplay: true });
    }
    const existing = await pool.query('SELECT * FROM execution_runs WHERE id=$1 AND organization_id=$2', [id, organizationId]);
    if (existing.rows[0]) { if (key) throw new Error('EXECUTION_ID_CONFLICT'); return res.status(200).json({ execution: existing.rows[0], idempotentReplay: true }); }
    const result = await startComplianceExecution({ organizationId, executionId: id, intent: req.body.intent });
    if (key) await appendExecutionEvent({ organizationId, executionId: id, eventType: 'EXECUTION_CREATED', actorType: 'USER', actorId: actor(req), result: 'created', payload: { result: { intent: result.intent, plan: result.plan, execution: result.execution } }, idempotencyKey: `create:${key}` });
    return res.status(202).json({ ...result, idempotencyKey: key });
  } catch (error) { next(error); }
});

router.get('/executions/:executionId/stream', async (req, res, next) => {
  try { const id = executionId(req.params.executionId); req.query.executionId = id; req.query.stream = '1'; return executionGraphHandler(req, res); }
  catch (error) { next(error); }
});

router.get('/executions/:executionId', async (req, res, next) => {
  try {
    const organizationId = org(req); if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
    const id = executionId(req.params.executionId); const execution = await getExecutionRun(organizationId, id); const graph = await getExecutionGraph(organizationId, id);
    if (!execution && !graph.nodes.length) return res.status(404).json({ error: 'EXECUTION_NOT_FOUND' });
    const events = await listExecutionEvents({ organizationId, executionId: id, afterSequence: Number(req.query.afterSequence || 0), limit: page(req.query.limit) });
    return res.json({ execution, graph, events, providers: listProviders() });
  } catch (error) { next(error); }
});

router.get('/executions/:executionId/evidence', async (req, res, next) => {
  try {
    const organizationId = org(req); if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
    const id = executionId(req.params.executionId); const result = await pool.query(`SELECT id,node_id,attempt_id,control_id,provider,connection_id,resource_id,source_type,source_ref,collected_at,evidence,evidence_hash,evidence_kind,observed_at,freshness_expires_at,lineage,created_at FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 ORDER BY collected_at DESC LIMIT $3`, [organizationId, id, page(req.query.limit)]);
    return res.json({ executionId: id, evidence: result.rows.map(row => ({ ...row, integrityValid: verifyEvidenceIntegrity(row), freshness: getEvidenceFreshness(row) })) });
  } catch (error) { next(error); }
});

router.get('/executions/:executionId/decisions', async (req, res, next) => {
  try {
    const organizationId = org(req); if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
    const id = executionId(req.params.executionId); const controls = await pool.query('SELECT * FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2 ORDER BY control_id,scope_key LIMIT $3', [organizationId, id, page(req.query.limit)]); const history = await pool.query('SELECT * FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2 ORDER BY decided_at ASC LIMIT $3', [organizationId, id, page(req.query.limit)]); const final = await pool.query('SELECT * FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]);
    return res.json({ executionId: id, controls: controls.rows, history: history.rows, final: final.rows[0] || null });
  } catch (error) { next(error); }
});

router.post('/executions/:executionId/actions', async (req, res, next) => {
  try {
    const organizationId = org(req); if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
    const id = executionId(req.params.executionId); const action = req.body?.action; const key = idempotency(req);
    if (!['start','resume','retry','approve','cancel','finalize'].includes(action)) return res.status(400).json({ error: 'ACTION_INVALID' });
    if (action === 'start') return res.status(202).json(await startPersistedPlanExecution({ organizationId, executionId: id }));
    if (action === 'finalize') return res.status(200).json(await finalizeComplianceDecision({ organizationId, executionId: id }));
    if (action === 'approve') return res.status(200).json(await approveExecutionNode({ organizationId, executionId: id, nodeId: req.body?.nodeId, actorId: actor(req) }));
    if (action === 'cancel') return res.status(200).json(await cancelExecutionRun({ organizationId, executionId: id, reason: String(req.body?.reason || 'Cancelled by operator').slice(0,500), actorId: actor(req), idempotencyKey: key ? `v1:cancel:${key}` : null }));
    const eventKey = key ? `control:${action}:${key}` : null;
    if (eventKey) { const existingEvent = await getExecutionEventByIdempotencyKey({ organizationId, executionId: id, eventType: 'EXECUTION_CONTROL_QUEUED', idempotencyKey: eventKey }); if (existingEvent) return res.status(202).json({ success:true,status:'queued',executionId:id,action,jobId:existingEvent.payload?.jobId||null,resumableNodeIds:existingEvent.payload?.nodeIds||[],idempotencyKey:key,idempotentReplay:true }); }
    const plan = await getDependencyAwareResumePlan(organizationId, id); const requested = Array.isArray(req.body?.nodeIds) ? req.body.nodeIds : plan.nodes.map(node => node.id); if (requested.length > LIMIT || requested.some(nodeId => !ID.test(nodeId))) throw new Error('NODE_IDS_INVALID'); const execution = plan.execution; const graph = await getExecutionGraph(organizationId, id); const executionNode = graph.nodes.find(node => node.node_type === 'EXECUTION'); const metadata = executionNode?.metadata || execution.metadata || {}; if (!metadata.connectionId || !metadata.scanId || !metadata.provider) throw new Error('EXECUTION_MISSING_CONNECTION_METADATA'); const jobId = `v1-${id}-${action}-${key || Date.now()}`; await enqueueJob({ jobId, scanId: metadata.scanId, executionId:id, organizationId, connectionId:metadata.connectionId, provider:metadata.provider, scanType:'resume', resumeNodeIds:requested, enqueuedAt:new Date().toISOString(), normalMetadata:JSON.stringify({ control:action, idempotencyKey:key }) }); await appendExecutionEvent({ organizationId, executionId:id, eventType:'EXECUTION_CONTROL_QUEUED', actorType:'USER', actorId:actor(req), result:'success', payload:{action,jobId,nodeIds:requested}, idempotencyKey:eventKey }); return res.status(202).json({ success:true,status:'queued',executionId:id,action,jobId,resumableNodeIds:requested,idempotencyKey:key });
  } catch (error) { next(error); }
});

export default router;
