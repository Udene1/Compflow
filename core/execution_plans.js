import crypto from 'crypto';
import pool from './db.js';
import { ensureExecutionGraph } from './execution_engine.js';
import { validatePolicyPlan } from './policy_planner.js';

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS execution_plans (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL,
  policy_id TEXT NOT NULL, policy_version TEXT NOT NULL, plan_version INTEGER NOT NULL,
  plan_hash TEXT NOT NULL, plan JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, execution_id), UNIQUE (organization_id, plan_hash)
);
CREATE INDEX IF NOT EXISTS execution_plans_policy_idx ON execution_plans (organization_id, policy_id, policy_version, created_at DESC);
`;
let schemaPromise;
async function ensureSchema() { if (!schemaPromise) schemaPromise = pool.query(SCHEMA_SQL).catch(error => { schemaPromise = null; throw error; }); return schemaPromise; }
function assertId(value, code) { if (typeof value !== 'string' || value.length < 1 || value.length > 128) throw new Error(code); return value; }
function canonicalPlan(plan) { validatePolicyPlan(plan); return JSON.stringify(plan); }
export async function ensureExecutionPlansSchema() { await ensureSchema(); }
export async function persistExecutionPlan({ organizationId, executionId, plan, client = null } = {}) {
  await ensureSchema(); assertId(organizationId, 'PLAN_ORGANIZATION_REQUIRED'); assertId(executionId, 'PLAN_EXECUTION_REQUIRED'); validatePolicyPlan(plan);
  const db = client || pool; const id = `plan_${crypto.createHash('sha256').update(`${organizationId}:${executionId}`).digest('hex').slice(0, 32)}`;
  const result = await db.query(`INSERT INTO execution_plans (id,organization_id,execution_id,policy_id,policy_version,plan_version,plan_hash,plan) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT (organization_id,execution_id) DO UPDATE SET policy_id=EXCLUDED.policy_id, policy_version=EXCLUDED.policy_version, plan_version=EXCLUDED.plan_version, plan_hash=EXCLUDED.plan_hash, plan=EXCLUDED.plan RETURNING *`, [id, organizationId, executionId, plan.policy.id, plan.policy.version, plan.planVersion, plan.planHash, canonicalPlan(plan)]);
  return result.rows[0];
}
export async function getExecutionPlan({ organizationId, executionId, client = null } = {}) {
  await ensureSchema(); assertId(organizationId, 'PLAN_ORGANIZATION_REQUIRED'); assertId(executionId, 'PLAN_EXECUTION_REQUIRED');
  const db = client || pool; const result = await db.query('SELECT * FROM execution_plans WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]); return result.rows[0] || null;
}
export async function materializeExecutionPlan({ organizationId, executionId, plan, client = null } = {}) {
  validatePolicyPlan(plan); await ensureExecutionGraph();
  const ownTransaction = !client; const tx = client || await pool.connect();
  try {
    if (ownTransaction) await tx.query('BEGIN');
    const stored = await persistExecutionPlan({ organizationId, executionId, plan, client: tx });
    for (const node of plan.nodes) await tx.query(`INSERT INTO execution_graph_nodes (id,organization_id,execution_id,node_type,logical_key,status,label,metadata) VALUES ($1,$2,$3,$4,$5,'PENDING',$6,$7::jsonb) ON CONFLICT (organization_id,execution_id,node_type,logical_key) DO UPDATE SET label=COALESCE(EXCLUDED.label,execution_graph_nodes.label), metadata=execution_graph_nodes.metadata||EXCLUDED.metadata`, [node.id, organizationId, executionId, node.nodeType, node.logicalKey, node.label || null, JSON.stringify(node.metadata || {})]);
    for (const edge of plan.edges) await tx.query(`INSERT INTO execution_graph_edges (id,organization_id,execution_id,from_node_id,to_node_id,edge_type,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT (execution_id,from_node_id,to_node_id,edge_type) DO UPDATE SET metadata=execution_graph_edges.metadata||EXCLUDED.metadata`, [edge.id, organizationId, executionId, edge.fromNodeId, edge.toNodeId, edge.edgeType, JSON.stringify(edge.metadata || {})]);
    if (ownTransaction) await tx.query('COMMIT'); return stored;
  } catch (error) { if (ownTransaction) await tx.query('ROLLBACK').catch(() => {}); throw error; }
  finally { if (ownTransaction) tx.release(); }
}
