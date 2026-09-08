import crypto from 'crypto';
import pool from './db.js';

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS execution_graph_nodes (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL,
  node_type TEXT NOT NULL, logical_key TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING',
  label TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, execution_id, node_type, logical_key)
);
CREATE INDEX IF NOT EXISTS execution_graph_nodes_execution_idx ON execution_graph_nodes (organization_id, execution_id);
CREATE TABLE IF NOT EXISTS execution_graph_edges (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL,
  from_node_id TEXT NOT NULL REFERENCES execution_graph_nodes(id) ON DELETE CASCADE,
  to_node_id TEXT NOT NULL REFERENCES execution_graph_nodes(id) ON DELETE CASCADE,
  edge_type TEXT NOT NULL DEFAULT 'DEPENDS_ON', metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (execution_id, from_node_id, to_node_id, edge_type)
);
CREATE INDEX IF NOT EXISTS execution_graph_edges_execution_idx ON execution_graph_edges (organization_id, execution_id);
CREATE TABLE IF NOT EXISTS execution_attempts (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL,
  node_id TEXT NOT NULL REFERENCES execution_graph_nodes(id) ON DELETE CASCADE,
  attempt_number INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'RUNNING', started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), finished_at TIMESTAMPTZ,
  heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), error_code TEXT, error_message TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, UNIQUE (node_id, attempt_number)
);
ALTER TABLE execution_attempts ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE INDEX IF NOT EXISTS execution_attempts_execution_idx ON execution_attempts (organization_id, execution_id, started_at);
CREATE INDEX IF NOT EXISTS execution_attempts_running_heartbeat_idx ON execution_attempts (organization_id, status, heartbeat_at) WHERE status = 'RUNNING';
CREATE UNIQUE INDEX IF NOT EXISTS execution_attempts_one_running_node_idx ON execution_attempts (node_id) WHERE status = 'RUNNING';
`;
let schemaPromise;
const NODE_STATUS = new Set(['PENDING', 'RUNNING', 'FAILED', 'CANCELLED', 'SUCCEEDED', 'SKIPPED']);
const ATTEMPT_STATUS = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED', 'SKIPPED']);
const LEGAL_NODE_TRANSITIONS = { PENDING: new Set(['PENDING', 'RUNNING', 'CANCELLED', 'SKIPPED']), RUNNING: new Set(['RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'SKIPPED']), FAILED: new Set(['FAILED', 'RUNNING', 'CANCELLED', 'SKIPPED']), CANCELLED: new Set(['CANCELLED', 'RUNNING', 'SKIPPED']), SUCCEEDED: new Set(['SUCCEEDED']), SKIPPED: new Set(['SKIPPED']) };
async function ensureSchema() {
  if (!schemaPromise) schemaPromise = (async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('compflow.execution_graph_schema'))");
      await client.query(SCHEMA_SQL);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally { client.release(); }
  })().catch(error => { schemaPromise = null; throw error; });
  return schemaPromise;
}
function cleanErrorMessage(value) { if (!value) return null; return String(value).replace(/(authorization|token|secret|password|client_secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]').slice(0, 500); }
function assertNodeTransition(current, next) { if (!NODE_STATUS.has(next)) throw new Error('NODE_STATUS_INVALID'); if (!LEGAL_NODE_TRANSITIONS[current]?.has(next)) throw new Error(`NODE_TRANSITION_INVALID:${current}->${next}`); }
export function stableUsageId(organizationId, executionId, nodeType, logicalKey) { return `node_${crypto.createHash('sha256').update([organizationId, executionId, nodeType, logicalKey].map(v => String(v ?? '').trim()).join(':')).digest('hex').slice(0, 32)}`; }
export function stableEdgeId(executionId, fromNodeId, toNodeId, edgeType = 'DEPENDS_ON') { return `edge_${crypto.createHash('sha256').update([executionId, fromNodeId, toNodeId, edgeType].join(':')).digest('hex').slice(0, 32)}`; }
export async function ensureExecutionGraph() { await ensureSchema(); }
export async function upsertGraphNode({ organizationId, executionId, nodeType, logicalKey, status = 'PENDING', label = null, metadata = {} }) { await ensureSchema(); if (!organizationId || !executionId || !nodeType || !logicalKey) throw new Error('GRAPH_NODE_INPUT_INVALID'); if (!NODE_STATUS.has(status)) throw new Error('NODE_STATUS_INVALID'); const id = stableUsageId(organizationId, executionId, nodeType, logicalKey); const result = await pool.query(`INSERT INTO execution_graph_nodes (id,organization_id,execution_id,node_type,logical_key,status,label,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT (organization_id,execution_id,node_type,logical_key) DO UPDATE SET status=CASE WHEN $6 = execution_graph_nodes.status THEN execution_graph_nodes.status WHEN $6 = 'RUNNING' AND execution_graph_nodes.status IN ('SUCCEEDED','SKIPPED') THEN execution_graph_nodes.status WHEN execution_graph_nodes.status = 'SUCCEEDED' AND $6 IN ('PENDING','FAILED','CANCELLED') THEN execution_graph_nodes.status WHEN execution_graph_nodes.status = 'SKIPPED' AND $6 IN ('PENDING','FAILED','CANCELLED','RUNNING') THEN execution_graph_nodes.status ELSE $6 END, label=COALESCE(EXCLUDED.label,execution_graph_nodes.label), metadata=execution_graph_nodes.metadata||EXCLUDED.metadata, updated_at=NOW() RETURNING *`, [id, organizationId, executionId, nodeType, logicalKey, status, label, JSON.stringify(metadata)]); return result.rows[0]; }
export async function addDependencyEdge({ organizationId, executionId, fromNodeId, toNodeId, edgeType = 'DEPENDS_ON', metadata = {} }) { await ensureSchema(); if (!organizationId || !executionId || !fromNodeId || !toNodeId || fromNodeId === toNodeId) throw new Error('GRAPH_EDGE_INPUT_INVALID'); const id = stableEdgeId(executionId, fromNodeId, toNodeId, edgeType); const result = await pool.query(`INSERT INTO execution_graph_edges (id,organization_id,execution_id,from_node_id,to_node_id,edge_type,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT (execution_id,from_node_id,to_node_id,edge_type) DO UPDATE SET metadata=execution_graph_edges.metadata||EXCLUDED.metadata RETURNING *`, [id, organizationId, executionId, fromNodeId, toNodeId, edgeType, JSON.stringify(metadata)]); return result.rows[0]; }
