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
  error_code TEXT, error_message TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, UNIQUE (node_id, attempt_number)
);
CREATE INDEX IF NOT EXISTS execution_attempts_execution_idx ON execution_attempts (organization_id, execution_id, started_at);
`;
let schemaPromise;
async function ensureSchema() {
  if (!schemaPromise) schemaPromise = pool.query(SCHEMA_SQL).catch(error => { schemaPromise = null; throw error; });
  return schemaPromise;
}
export function stableUsageId(organizationId, executionId, nodeType, logicalKey) {
  return `node_${crypto.createHash('sha256').update([organizationId,executionId,nodeType,logicalKey].map(v=>String(v??'').trim()).join(':')).digest('hex').slice(0,32)}`;
}
export function stableEdgeId(executionId, fromNodeId, toNodeId, edgeType='DEPENDS_ON') {
  return `edge_${crypto.createHash('sha256').update([executionId,fromNodeId,toNodeId,edgeType].join(':')).digest('hex').slice(0,32)}`;
}
export async function ensureExecutionGraph(){ await ensureSchema(); }
export async function upsertGraphNode({organizationId,executionId,nodeType,logicalKey,status='PENDING',label=null,metadata={}}){
  await ensureSchema(); if(!organizationId||!executionId||!nodeType||!logicalKey) throw new Error('GRAPH_NODE_INPUT_INVALID');
  const id=stableUsageId(organizationId,executionId,nodeType,logicalKey);
  const result=await pool.query(`INSERT INTO execution_graph_nodes (id,organization_id,execution_id,node_type,logical_key,status,label,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT (organization_id,execution_id,node_type,logical_key) DO UPDATE SET status=EXCLUDED.status,label=COALESCE(EXCLUDED.label,execution_graph_nodes.label),metadata=execution_graph_nodes.metadata||EXCLUDED.metadata,updated_at=NOW() RETURNING *`,[id,organizationId,executionId,nodeType,logicalKey,status,label,JSON.stringify(metadata)]);
  return result.rows[0];
}
export async function addDependencyEdge({organizationId,executionId,fromNodeId,toNodeId,edgeType='DEPENDS_ON',metadata={}}){
  await ensureSchema(); if(!organizationId||!executionId||!fromNodeId||!toNodeId||fromNodeId===toNodeId) throw new Error('GRAPH_EDGE_INPUT_INVALID');
  const id=stableEdgeId(executionId,fromNodeId,toNodeId,edgeType);
  const result=await pool.query(`INSERT INTO execution_graph_edges (id,organization_id,execution_id,from_node_id,to_node_id,edge_type,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT (execution_id,from_node_id,to_node_id,edge_type) DO UPDATE SET metadata=execution_graph_edges.metadata||EXCLUDED.metadata RETURNING *`,[id,organizationId,executionId,fromNodeId,toNodeId,edgeType,JSON.stringify(metadata)]);
  return result.rows[0];
}
export async function startNodeAttempt({organizationId,executionId,nodeId,metadata={}}){
  await ensureSchema(); if(!organizationId||!executionId||!nodeId) throw new Error('ATTEMPT_INPUT_INVALID');
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',[nodeId]);
    const node=await client.query('SELECT status FROM execution_graph_nodes WHERE id=$1 AND organization_id=$2 AND execution_id=$3 FOR UPDATE',[nodeId,organizationId,executionId]);
    if(!node.rows[0]) throw new Error('GRAPH_NODE_NOT_FOUND');
    const latest=await client.query('SELECT COALESCE(MAX(attempt_number),0) AS attempt_number FROM execution_attempts WHERE node_id=$1',[nodeId]);
    const attemptNumber=Number(latest.rows[0].attempt_number)+1;
    const id=`attempt_${crypto.randomUUID()}`;
    const result=await client.query(`INSERT INTO execution_attempts (id,organization_id,execution_id,node_id,attempt_number,status,metadata) VALUES ($1,$2,$3,$4,$5,'RUNNING',$6::jsonb) RETURNING *`,[id,organizationId,executionId,nodeId,attemptNumber,JSON.stringify(metadata)]);
    await client.query(`UPDATE execution_graph_nodes SET status='RUNNING',updated_at=NOW() WHERE id=$1 AND organization_id=$2 AND execution_id=$3`,[nodeId,organizationId,executionId]);
    await client.query('COMMIT'); return result.rows[0];
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
}
export async function finishNodeAttempt({attemptId,status,errorCode=null,errorMessage=null,metadata={}}){
  await ensureSchema(); const allowed=new Set(['SUCCEEDED','FAILED','CANCELLED','SKIPPED']); if(!allowed.has(status)) throw new Error('ATTEMPT_STATUS_INVALID');
  const result=await pool.query(`UPDATE execution_attempts SET status=$1,finished_at=NOW(),error_code=$2,error_message=$3,metadata=metadata||$4::jsonb WHERE id=$5 AND status='RUNNING' RETURNING *`,[status,errorCode,errorMessage,JSON.stringify(metadata),attemptId]);
  if(!result.rows[0]) throw new Error('ATTEMPT_NOT_FOUND_OR_ALREADY_FINISHED');
  const nodeStatus=status==='SUCCEEDED'?'SUCCEEDED':status==='SKIPPED'?'SKIPPED':status==='CANCELLED'?'CANCELLED':'FAILED';
  await pool.query('UPDATE execution_graph_nodes SET status=$1,updated_at=NOW() WHERE id=$2',[nodeStatus,result.rows[0].node_id]);
  return result.rows[0];
}
export async function getExecutionGraph(organizationId,executionId){
  await ensureSchema(); const [nodes,edges,attempts]=await Promise.all([
    pool.query('SELECT * FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2 ORDER BY created_at ASC',[organizationId,executionId]),
    pool.query('SELECT * FROM execution_graph_edges WHERE organization_id=$1 AND execution_id=$2 ORDER BY created_at ASC',[organizationId,executionId]),
    pool.query('SELECT * FROM execution_attempts WHERE organization_id=$1 AND execution_id=$2 ORDER BY started_at ASC',[organizationId,executionId])
  ]);
  return {executionId,organizationId,nodes:nodes.rows,edges:edges.rows,attempts:attempts.rows,timeline:attempts.rows.map(a=>({id:a.id,nodeId:a.node_id,attemptNumber:a.attempt_number,status:a.status,startedAt:a.started_at,finishedAt:a.finished_at,errorCode:a.error_code}))};
}
export async function getResumableNodes(organizationId,executionId){
  const graph=await getExecutionGraph(organizationId,executionId); const terminal=new Set(['SUCCEEDED','SKIPPED']); const retryable=new Set(['PENDING','FAILED','CANCELLED']);
  return graph.nodes.filter(node=>retryable.has(node.status)).filter(node=>graph.edges.filter(e=>e.to_node_id===node.id&&e.edge_type==='DEPENDS_ON').every(e=>{const d=graph.nodes.find(n=>n.id===e.from_node_id);return d&&terminal.has(d.status);}));
}
export async function claimResumableNode({organizationId,executionId,nodeId,metadata={}}){
  const nodes=await getResumableNodes(organizationId,executionId); if(!nodes.some(n=>n.id===nodeId)) throw new Error('NODE_NOT_RESUMABLE');
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',[nodeId]);
    const current=await client.query('SELECT status FROM execution_graph_nodes WHERE id=$1 AND organization_id=$2 AND execution_id=$3 FOR UPDATE',[nodeId,organizationId,executionId]);
    if(!current.rows[0]) throw new Error('GRAPH_NODE_NOT_FOUND');
    if(!['PENDING','FAILED','CANCELLED'].includes(current.rows[0].status)) throw new Error('NODE_NOT_RESUMABLE');
    const latest=await client.query('SELECT COALESCE(MAX(attempt_number),0) AS attempt_number FROM execution_attempts WHERE node_id=$1',[nodeId]);
    const attemptNumber=Number(latest.rows[0].attempt_number)+1; const id=`attempt_${crypto.randomUUID()}`;
    const result=await client.query(`INSERT INTO execution_attempts (id,organization_id,execution_id,node_id,attempt_number,status,metadata) VALUES ($1,$2,$3,$4,$5,'RUNNING',$6::jsonb) RETURNING *`,[id,organizationId,executionId,nodeId,attemptNumber,JSON.stringify({...metadata,resume:true})]);
    await client.query(`UPDATE execution_graph_nodes SET status='RUNNING',updated_at=NOW() WHERE id=$1`,[nodeId]);
    await client.query('COMMIT'); return result.rows[0];
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
}
export async function resumeExecution(organizationId,executionId){const nodes=await getResumableNodes(organizationId,executionId);return {organizationId,executionId,resumableNodeIds:nodes.map(n=>n.id),nodes};}
