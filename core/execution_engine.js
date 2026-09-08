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
const LEGAL_NODE_TRANSITIONS = {
  PENDING: new Set(['PENDING', 'RUNNING', 'CANCELLED', 'SKIPPED']),
  RUNNING: new Set(['RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'SKIPPED']),
  FAILED: new Set(['FAILED', 'RUNNING', 'CANCELLED', 'SKIPPED']),
  CANCELLED: new Set(['CANCELLED', 'RUNNING', 'SKIPPED']),
  SUCCEEDED: new Set(['SUCCEEDED']), SKIPPED: new Set(['SKIPPED'])
};

async function ensureSchema() {
  if (!schemaPromise) schemaPromise = (async () => {
    const client = await pool.connect();
    try {
      // Use the same advisory lock namespace as the central DB DDL path.
      // This prevents concurrent test workers/requests from deadlocking on
      // graph DDL while another session is writing graph rows.
      await client.query("SELECT pg_advisory_lock(hashtextextended('compflow:schema',0))");
      try {
        await client.query('BEGIN');
        await client.query(SCHEMA_SQL);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        await client.query("SELECT pg_advisory_unlock(hashtextextended('compflow:schema',0))").catch(() => {});
      }
    } finally { client.release(); }
  })().catch(error => { schemaPromise = null; throw error; });
  return schemaPromise;
}

function cleanErrorMessage(value) { if (!value) return null; return String(value).replace(/(authorization|token|secret|password|client_secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]').slice(0, 500); }
function assertNodeTransition(current, next) { if (!NODE_STATUS.has(next)) throw new Error('NODE_STATUS_INVALID'); if (!LEGAL_NODE_TRANSITIONS[current]?.has(next)) throw new Error(`NODE_TRANSITION_INVALID:${current}->${next}`); }
export function stableUsageId(organizationId, executionId, nodeType, logicalKey) { return `node_${crypto.createHash('sha256').update([organizationId, executionId, nodeType, logicalKey].map(v => String(v ?? '').trim()).join(':')).digest('hex').slice(0, 32)}`; }
export function stableEdgeId(executionId, fromNodeId, toNodeId, edgeType = 'DEPENDS_ON') { return `edge_${crypto.createHash('sha256').update([executionId, fromNodeId, toNodeId, edgeType].join(':')).digest('hex').slice(0, 32)}`; }
export async function ensureExecutionGraph() { await ensureSchema(); }

export async function upsertGraphNode({ organizationId, executionId, nodeType, logicalKey, status = 'PENDING', label = null, metadata = {} }) {
  await ensureSchema();
  if (!organizationId || !executionId || !nodeType || !logicalKey) throw new Error('GRAPH_NODE_INPUT_INVALID');
  if (!NODE_STATUS.has(status)) throw new Error('NODE_STATUS_INVALID');
  const id = stableUsageId(organizationId, executionId, nodeType, logicalKey);
  const result = await pool.query(`INSERT INTO execution_graph_nodes (id,organization_id,execution_id,node_type,logical_key,status,label,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT (organization_id,execution_id,node_type,logical_key) DO UPDATE SET status=CASE WHEN $6 = execution_graph_nodes.status THEN execution_graph_nodes.status WHEN $6 = 'RUNNING' AND execution_graph_nodes.status IN ('SUCCEEDED','SKIPPED') THEN execution_graph_nodes.status ELSE $6 END,label=COALESCE($7,execution_graph_nodes.label),metadata=$8::jsonb,updated_at=NOW() RETURNING *`, [id,organizationId,executionId,nodeType,logicalKey,status,label,JSON.stringify(metadata)]);
  return result.rows[0];
}

export async function addDependencyEdge({ organizationId, executionId, fromNodeId, toNodeId, edgeType = 'DEPENDS_ON', metadata = {} }) { await ensureSchema(); const id=stableEdgeId(executionId,fromNodeId,toNodeId,edgeType); const result=await pool.query(`INSERT INTO execution_graph_edges (id,organization_id,execution_id,from_node_id,to_node_id,edge_type,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT (execution_id,from_node_id,to_node_id,edge_type) DO UPDATE SET metadata=$7::jsonb RETURNING *`,[id,organizationId,executionId,fromNodeId,toNodeId,edgeType,JSON.stringify(metadata)]); return result.rows[0]; }

export async function startNodeAttempt({ organizationId, executionId, nodeId, metadata = {} }) {
  await ensureSchema();
  const client=await pool.connect();
  try { await client.query('BEGIN'); const node=(await client.query('SELECT * FROM execution_graph_nodes WHERE id=$1 AND organization_id=$2 AND execution_id=$3 FOR UPDATE',[nodeId,organizationId,executionId])).rows[0]; if(!node) throw new Error('EXECUTION_NODE_NOT_FOUND'); assertNodeTransition(node.status,'RUNNING'); const number=(await client.query('SELECT COALESCE(MAX(attempt_number),0)+1 AS next FROM execution_attempts WHERE node_id=$1',[nodeId])).rows[0].next; const attemptId=crypto.randomUUID(); const attempt=(await client.query(`INSERT INTO execution_attempts (id,organization_id,execution_id,node_id,attempt_number,status,metadata) VALUES ($1,$2,$3,$4,$5,'RUNNING',$6::jsonb) RETURNING *`,[attemptId,organizationId,executionId,nodeId,number,JSON.stringify(metadata)])).rows[0]; await client.query(`UPDATE execution_graph_nodes SET status='RUNNING',updated_at=NOW() WHERE id=$1 AND organization_id=$2 AND execution_id=$3`,[nodeId,organizationId,executionId]); await client.query('COMMIT'); return attempt; } catch(error){await client.query('ROLLBACK').catch(()=>{}); throw error;} finally{client.release();}
}

export async function heartbeatNodeAttempt({ organizationId, executionId, nodeId, attemptId }) { await ensureSchema(); const result=await pool.query(`UPDATE execution_attempts SET heartbeat_at=NOW() WHERE id=$1 AND organization_id=$2 AND execution_id=$3 AND node_id=$4 AND status='RUNNING' RETURNING *`,[attemptId,organizationId,executionId,nodeId]); if(!result.rows[0]) throw new Error('EXECUTION_NODE_ATTEMPT_NOT_RUNNING'); return result.rows[0]; }
export async function finishNodeAttempt({ organizationId, executionId, nodeId, attemptId, status, errorCode=null, errorMessage=null, metadata=null }) { await ensureSchema(); if(!ATTEMPT_STATUS.has(status)) throw new Error('ATTEMPT_STATUS_INVALID'); const client=await pool.connect(); try{await client.query('BEGIN'); const attempt=(await client.query('SELECT * FROM execution_attempts WHERE id=$1 AND organization_id=$2 AND execution_id=$3 AND node_id=$4 FOR UPDATE',[attemptId,organizationId,executionId,nodeId])).rows[0]; if(!attempt) throw new Error('EXECUTION_ATTEMPT_NOT_FOUND'); if(attempt.status!=='RUNNING') throw new Error('EXECUTION_NODE_ATTEMPT_NOT_RUNNING'); const node=(await client.query('SELECT * FROM execution_graph_nodes WHERE id=$1 AND organization_id=$2 AND execution_id=$3 FOR UPDATE',[nodeId,organizationId,executionId])).rows[0]; if(!node) throw new Error('EXECUTION_NODE_NOT_FOUND'); assertNodeTransition(node.status,status); const updated=(await client.query(`UPDATE execution_attempts SET status=$1,finished_at=clock_timestamp(),error_code=$2,error_message=$3,metadata=COALESCE($4::jsonb,metadata) WHERE id=$5 RETURNING *`,[status,errorCode,cleanErrorMessage(errorMessage),metadata?JSON.stringify(metadata):null,attemptId])).rows[0]; await client.query(`UPDATE execution_graph_nodes SET status=$1,updated_at=clock_timestamp() WHERE id=$2 AND organization_id=$3 AND execution_id=$4`,[status,nodeId,organizationId,executionId]); await client.query('COMMIT'); return updated;}catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();} }

export async function getExecutionGraph(organizationId,executionId){await ensureSchema();const [nodes,edges]=await Promise.all([pool.query('SELECT * FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2 ORDER BY created_at,id',[organizationId,executionId]),pool.query('SELECT * FROM execution_graph_edges WHERE organization_id=$1 AND execution_id=$2 ORDER BY created_at,id',[organizationId,executionId])]);return {nodes:nodes.rows,edges:edges.rows};}
export async function getResumableNodes({organizationId,executionId}){await ensureSchema();const result=await pool.query(`SELECT n.* FROM execution_graph_nodes n WHERE n.organization_id=$1 AND n.execution_id=$2 AND n.status IN ('PENDING','FAILED','CANCELLED') AND NOT EXISTS (SELECT 1 FROM execution_graph_edges e JOIN execution_graph_nodes dep ON dep.id=e.from_node_id WHERE e.execution_id=n.execution_id AND e.to_node_id=n.id AND dep.status NOT IN ('SUCCEEDED','SKIPPED')) ORDER BY n.created_at,n.id`,[organizationId,executionId]);return result.rows;}
export async function claimResumableNode({organizationId,executionId,nodeId}){return startNodeAttempt({organizationId,executionId,nodeId,metadata:{resumed:true}});}
export async function recoverStaleNodeAttempts({organizationId,executionId,staleAfterSeconds=300}){await ensureSchema();const result=await pool.query(`UPDATE execution_attempts SET status='FAILED',finished_at=clock_timestamp(),error_code='STALE_ATTEMPT',error_message='Execution node attempt became stale' WHERE organization_id=$1 AND execution_id=$2 AND status='RUNNING' AND heartbeat_at <= clock_timestamp() - ($3 * INTERVAL '1 second') RETURNING *`,[organizationId,executionId,staleAfterSeconds]);for(const attempt of result.rows) await pool.query(`UPDATE execution_graph_nodes SET status='FAILED',updated_at=clock_timestamp() WHERE id=$1 AND organization_id=$2 AND execution_id=$3 AND status='RUNNING'`,[attempt.node_id,organizationId,executionId]);return result.rows;}
export async function resumeExecution({organizationId,executionId,nodeIds=[]}){const resumable=await getResumableNodes({organizationId,executionId});const allowed=new Set(nodeIds.length?nodeIds:resumable.map(n=>n.id));const claimed=[];for(const node of resumable)if(allowed.has(node.id))claimed.push(await claimResumableNode({organizationId,executionId,nodeId:node.id}));return claimed;}
