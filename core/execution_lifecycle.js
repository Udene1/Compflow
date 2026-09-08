import crypto from 'crypto';
import pool from './db.js';
import { appendExecutionEvent } from './execution_events.js';

const LIFECYCLE_SCHEMA = `
CREATE TABLE IF NOT EXISTS execution_runs (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING',
  lease_owner TEXT, lease_token TEXT, lease_expires_at TIMESTAMPTZ, heartbeat_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, error_code TEXT, error_message TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb, version BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (status IN ('PENDING','RUNNING','SUCCEEDED','FAILED','CANCELLED'))
);
CREATE INDEX IF NOT EXISTS execution_runs_org_status_idx ON execution_runs (organization_id, status, updated_at);
CREATE INDEX IF NOT EXISTS execution_runs_lease_idx ON execution_runs (organization_id, lease_expires_at) WHERE status = 'RUNNING';
`;
const TERMINAL = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED']);
const LEGAL = { PENDING: new Set(['PENDING','RUNNING','CANCELLED']), RUNNING: new Set(['RUNNING','SUCCEEDED','FAILED','CANCELLED']), SUCCEEDED: new Set(['SUCCEEDED']), FAILED: new Set(['FAILED','RUNNING']), CANCELLED: new Set(['CANCELLED','RUNNING']) };
let schemaPromise;
async function ensureSchema() { if (!schemaPromise) schemaPromise = pool.query(LIFECYCLE_SCHEMA).catch(error => { schemaPromise = null; throw error; }); await schemaPromise; }
function cleanError(value) { if (!value) return null; return String(value).replace(/(authorization|token|secret|password|client_secret|api[_-]?key)\s*[:=]\s[^\s,;]+/gi, '$1=[REDACTED]').slice(0, 500); }
function assertTransition(current, next) { if (!LEGAL[current]?.has(next)) throw new Error(`EXECUTION_TRANSITION_INVALID:${current}->${next}`); }
function leaseToken() { return `lease_${crypto.randomUUID()}`; }
export async function ensureExecutionLifecycleSchema() { await ensureSchema(); }

export async function createExecutionRun({ organizationId, executionId = null, metadata = {} } = {}) {
  await ensureSchema(); if (!organizationId) throw new Error('ORGANIZATION_ID_REQUIRED');
  const id = executionId || `exec_${crypto.randomUUID()}`;
  const existing = await pool.query('SELECT * FROM execution_runs WHERE id=$1', [id]);
  if (existing.rows[0]) { if (existing.rows[0].organization_id !== organizationId) throw new Error('EXECUTION_ORGANIZATION_MISMATCH'); return existing.rows[0]; }
  const result = await pool.query(`INSERT INTO execution_runs (id, organization_id, status, metadata) VALUES ($1,$2,'PENDING',$3::jsonb) RETURNING *`, [id, organizationId, JSON.stringify(metadata)]);
  await appendExecutionEvent({ organizationId, executionId: id, eventType: 'EXECUTION_CREATED', result: 'success', payload: { status: 'PENDING' }, idempotencyKey: 'created' });
  return result.rows[0];
}
export async function getExecutionRun(organizationId, executionId) { await ensureSchema(); const result = await pool.query('SELECT * FROM execution_runs WHERE id=$1 AND organization_id=$2', [executionId, organizationId]); return result.rows[0] || null; }

export async function acquireExecutionLease({ organizationId, executionId, workerId, leaseSeconds = 60 } = {}) {
  await ensureSchema(); if (!organizationId || !executionId || !workerId) throw new Error('EXECUTION_LEASE_INPUT_INVALID');
  const ttl = Math.max(15, Math.min(Number(leaseSeconds) || 60, 3600)); const token = leaseToken(); const client = await pool.connect();
  try { await client.query('BEGIN'); const current = await client.query('SELECT * FROM execution_runs WHERE id=$1 AND organization_id=$2 FOR UPDATE', [executionId, organizationId]);
    if (!current.rows[0]) throw new Error('EXECUTION_NOT_FOUND'); const run = current.rows[0];
    if (TERMINAL.has(run.status)) throw new Error('EXECUTION_ALREADY_TERMINAL');
    if (run.status === 'RUNNING' && run.lease_expires_at && new Date(run.lease_expires_at).getTime() > Date.now() && run.lease_owner !== workerId) throw new Error('EXECUTION_ALREADY_LEASED');
    assertTransition(run.status, 'RUNNING');
    const result = await client.query(`UPDATE execution_runs SET status='RUNNING', lease_owner=$1, lease_token=$2, lease_expires_at=NOW()+($3 * INTERVAL '1 second'), heartbeat_at=NOW(), started_at=COALESCE(started_at,NOW()), version=version+1, updated_at=NOW() WHERE id=$4 AND organization_id=$5 RETURNING *`, [workerId, token, ttl, executionId, organizationId]);
    await appendExecutionEvent({ client, organizationId, executionId, eventType: 'EXECUTION_LEASE_ACQUIRED', actorType: 'WORKER', actorId: workerId, result: 'success', payload: { status: 'RUNNING', leaseSeconds: ttl } }); await client.query('COMMIT'); return result.rows[0];
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
}
export async function heartbeatExecutionLease({ organizationId, executionId, workerId, leaseToken: token, leaseSeconds = 60 } = {}) {
  await ensureSchema(); if (!organizationId || !executionId || !workerId || !token) throw new Error('EXECUTION_LEASE_INPUT_INVALID'); const ttl = Math.max(15, Math.min(Number(leaseSeconds) || 60, 3600));
  const result = await pool.query(`UPDATE execution_runs SET heartbeat_at=NOW(), lease_expires_at=NOW()+($1 * INTERVAL '1 second'), version=version+1, updated_at=NOW() WHERE id=$2 AND organization_id=$3 AND status='RUNNING' AND lease_owner=$4 AND lease_token=$5 AND lease_expires_at>NOW() RETURNING id,version,heartbeat_at,lease_expires_at`, [ttl, executionId, organizationId, workerId, token]);
  if (!result.rows[0]) throw new Error('EXECUTION_LEASE_LOST'); return result.rows[0];
}
export async function finishExecutionRun({ organizationId, executionId, workerId, leaseToken: token, status, errorCode = null, errorMessage = null, metadata = {} } = {}) {
  await ensureSchema(); if (!TERMINAL.has(status)) throw new Error('EXECUTION_TERMINAL_STATUS_INVALID'); if (!organizationId || !executionId || !workerId || !token) throw new Error('EXECUTION_LEASE_INPUT_INVALID'); const client = await pool.connect();
  try { await client.query('BEGIN'); const current = await client.query('SELECT status FROM execution_runs WHERE id=$1 AND organization_id=$2 AND lease_owner=$3 AND lease_token=$4 FOR UPDATE', [executionId, organizationId, workerId, token]); if (!current.rows[0]) throw new Error('EXECUTION_LEASE_LOST'); assertTransition(current.rows[0].status, status);
    const result = await client.query(`UPDATE execution_runs SET status=$1, finished_at=NOW(), heartbeat_at=NOW(), lease_expires_at=NULL, lease_owner=NULL, lease_token=NULL, error_code=$2, error_message=$3, metadata=metadata||$4::jsonb, version=version+1, updated_at=NOW() WHERE id=$5 AND organization_id=$6 AND lease_owner=$7 AND lease_token=$8 RETURNING *`, [status, errorCode, cleanError(errorMessage), JSON.stringify(metadata), executionId, organizationId, workerId, token]);
    await appendExecutionEvent({ client, organizationId, executionId, eventType: 'EXECUTION_FINISHED', actorType: 'WORKER', actorId: workerId, result: status === 'SUCCEEDED' ? 'success' : 'failed', payload: { status, errorCode: errorCode || null, errorMessage: cleanError(errorMessage) } }); await client.query('COMMIT'); return result.rows[0];
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
}
export async function cancelExecutionRun({ organizationId, executionId, reason = 'Cancelled by operator', actorId = null } = {}) {
  await ensureSchema(); if (!organizationId || !executionId) throw new Error('EXECUTION_CANCEL_INPUT_INVALID'); const client = await pool.connect();
  try { await client.query('BEGIN'); const result = await client.query(`UPDATE execution_runs SET status='CANCELLED', finished_at=NOW(), heartbeat_at=NOW(), lease_expires_at=NULL, lease_owner=NULL, lease_token=NULL, error_code='EXECUTION_CANCELLED', error_message=$3, version=version+1, updated_at=NOW() WHERE id=$1 AND organization_id=$2 AND status IN ('PENDING','RUNNING','FAILED') RETURNING *`, [executionId, organizationId, cleanError(reason)]);
    if (!result.rows[0]) { const current = await client.query('SELECT * FROM execution_runs WHERE id=$1 AND organization_id=$2 FOR UPDATE', [executionId, organizationId]); if (!current.rows[0]) throw new Error('EXECUTION_NOT_FOUND'); if (current.rows[0].status === 'CANCELLED') { await client.query('COMMIT'); return current.rows[0]; } throw new Error('EXECUTION_CANCEL_CONFLICT'); }
    await client.query(`UPDATE execution_attempts SET status='CANCELLED', finished_at=NOW(), heartbeat_at=NOW(), error_code='EXECUTION_CANCELLED', error_message=$3 WHERE organization_id=$1 AND execution_id=$2 AND status='RUNNING'`, [organizationId, executionId, cleanError(reason)]).catch(error => { if (error.code !== '42P01') throw error; });
    await client.query(`UPDATE execution_graph_nodes SET status='CANCELLED', updated_at=NOW() WHERE organization_id=$1 AND execution_id=$2 AND status IN ('PENDING','RUNNING','FAILED')`, [organizationId, executionId]);
    await appendExecutionEvent({ client, organizationId, executionId, eventType: 'EXECUTION_CANCELLED', actorType: 'USER', actorId, result: 'success', payload: { reason: cleanError(reason) } }); await client.query('COMMIT'); return result.rows[0];
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
}
export async function recoverExpiredExecutionLeases({ organizationId = null, executionId = null } = {}) {
  await ensureSchema(); const params = []; const filters = ["status='RUNNING'", 'lease_expires_at IS NOT NULL', 'lease_expires_at<=NOW()']; if (organizationId) { params.push(organizationId); filters.push(`organization_id=$${params.length}`); } if (executionId) { params.push(executionId); filters.push(`id=$${params.length}`); }
  const result = await pool.query(`UPDATE execution_runs SET status='FAILED', finished_at=NOW(), error_code='STALE_EXECUTION_LEASE', error_message='Execution worker lease expired', lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL, updated_at=NOW(), version=version+1 WHERE ${filters.join(' AND ')} RETURNING *`, params);
  for (const run of result.rows) await appendExecutionEvent({ organizationId: run.organization_id, executionId: run.id, eventType: 'EXECUTION_LEASE_EXPIRED', actorType: 'SYSTEM', result: 'failed', payload: { previousStatus: 'RUNNING', errorCode: 'STALE_EXECUTION_LEASE' } });
  return result.rows;
}
export async function listActiveExecutions(organizationId) { await ensureSchema(); if (!organizationId) throw new Error('ORGANIZATION_ID_REQUIRED'); const result = await pool.query('SELECT * FROM execution_runs WHERE organization_id=$1 ORDER BY created_at ASC', [organizationId]); return result.rows; }
