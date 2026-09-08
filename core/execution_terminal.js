import pool from './db.js';
import { appendExecutionEvent } from './execution_events.js';

const TERMINAL = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED', 'SKIPPED']);

function cleanError(value) {
  if (!value) return null;
  return String(value).replace(/(authorization|token|secret|password|client_secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]').slice(0, 500);
}

export async function finishExecutionFenced({ organizationId, executionId, attemptId, workerId, leaseToken, status, errorCode = null, errorMessage = null, metadata = {} } = {}) {
  if (!organizationId || !executionId || !attemptId || !workerId || !leaseToken) throw new Error('EXECUTION_LEASE_INPUT_INVALID');
  if (!TERMINAL.has(status)) throw new Error('ATTEMPT_STATUS_INVALID');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const run = await client.query(
      `SELECT * FROM execution_runs
        WHERE id=$1 AND organization_id=$2 AND status='RUNNING'
          AND lease_owner=$3 AND lease_token=$4 AND lease_expires_at>NOW()
        FOR UPDATE`,
      [executionId, organizationId, workerId, leaseToken]
    );
    if (!run.rows[0]) throw new Error('EXECUTION_LEASE_LOST');

    const attempt = await client.query(
      `UPDATE execution_attempts
          SET status=$1, finished_at=NOW(), heartbeat_at=NOW(), error_code=$2,
              error_message=$3, metadata=metadata||$4::jsonb
        WHERE id=$5 AND organization_id=$6 AND execution_id=$7 AND status='RUNNING'
        RETURNING *`,
      [status, errorCode, cleanError(errorMessage), JSON.stringify(metadata), attemptId, organizationId, executionId]
    );
    if (!attempt.rows[0]) throw new Error('ATTEMPT_NOT_FOUND_OR_ALREADY_FINISHED');

    const nodeStatus = status === 'SUCCEEDED' ? 'SUCCEEDED' : status === 'SKIPPED' ? 'SKIPPED' : status === 'CANCELLED' ? 'CANCELLED' : 'FAILED';
    await client.query(
      `UPDATE execution_graph_nodes
          SET status=$1, updated_at=NOW()
        WHERE id=$2 AND organization_id=$3 AND execution_id=$4
          AND status IN ('RUNNING','PENDING','FAILED','CANCELLED')`,
      [nodeStatus, attempt.rows[0].node_id, organizationId, executionId]
    );

    await appendExecutionEvent({
      client, organizationId, executionId, nodeId: attempt.rows[0].node_id, attemptId,
      eventType: 'NODE_ATTEMPT_FINISHED', actorType: 'WORKER', actorId: workerId,
      result: status === 'SUCCEEDED' ? 'success' : status === 'SKIPPED' ? 'skipped' : 'failed',
      payload: { nodeType: 'EXECUTION', status, errorCode: errorCode || null }
    });

    const execution = await client.query(
      `UPDATE execution_runs
          SET status=$1, finished_at=NOW(), heartbeat_at=NOW(), lease_expires_at=NULL,
              lease_owner=NULL, lease_token=NULL, error_code=$2, error_message=$3,
              metadata=metadata||$4::jsonb, version=version+1, updated_at=NOW()
        WHERE id=$5 AND organization_id=$6 AND status='RUNNING'
          AND lease_owner=$7 AND lease_token=$8
        RETURNING *`,
      [status === 'SUCCEEDED' ? 'SUCCEEDED' : 'FAILED', errorCode, cleanError(errorMessage), JSON.stringify(metadata), executionId, organizationId, workerId, leaseToken]
    );
    if (!execution.rows[0]) throw new Error('EXECUTION_LEASE_LOST');

    await appendExecutionEvent({
      client, organizationId, executionId, eventType: 'EXECUTION_FINISHED', actorType: 'WORKER', actorId: workerId,
      result: status === 'SUCCEEDED' ? 'success' : 'failed',
      payload: { status: execution.rows[0].status, errorCode: errorCode || null, errorMessage: cleanError(errorMessage) }
    });

    await client.query('COMMIT');
    return { attempt: attempt.rows[0], execution: execution.rows[0] };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}
