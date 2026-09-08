import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import pool from '../../core/db.js';
import { ensureExecutionGraph, upsertGraphNode, startNodeAttempt } from '../../core/execution_engine.js';
import { createExecutionRun, acquireExecutionLease, heartbeatExecutionLease, recoverExpiredExecutionLeases, getExecutionRun } from '../../core/execution_lifecycle.js';
import { recoverStaleExecutions } from '../../core/execution_recovery.js';

describe('Durable execution heartbeat and stale recovery', () => {
  const organizationId = 'org_execution_recovery_test';
  beforeAll(async () => { await ensureExecutionGraph(); await createExecutionRun({ organizationId, executionId: 'exec_heartbeat_test' }); await createExecutionRun({ organizationId, executionId: 'exec_recovery_test' }); });
  afterAll(async () => { await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]); await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]); });
  it('renews a real execution lease with worker fencing', async () => {
    const lease = await acquireExecutionLease({ organizationId, executionId: 'exec_heartbeat_test', workerId: 'heartbeat-worker', leaseSeconds: 30 });
    const heartbeat = await heartbeatExecutionLease({ organizationId, executionId: 'exec_heartbeat_test', workerId: 'heartbeat-worker', leaseToken: lease.lease_token, leaseSeconds: 30 });
    expect(BigInt(heartbeat.version)).toBeGreaterThan(BigInt(lease.version)); expect(new Date(heartbeat.lease_expires_at).getTime()).toBeGreaterThan(Date.now());
    await recoverExpiredExecutionLeases({ organizationId, executionId: 'exec_heartbeat_test' }); expect((await getExecutionRun(organizationId, 'exec_heartbeat_test')).status).toBe('RUNNING');
  });
  it('automatically marks expired execution leases and active attempts failed under the execution lease authority', async () => {
    const executionId = 'exec_recovery_test'; await acquireExecutionLease({ organizationId, executionId, workerId: 'dead-worker', leaseSeconds: 15 });
    const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'RECOVERY', logicalKey: 'stale', status: 'PENDING' }); const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id });
    await pool.query(`UPDATE execution_runs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1`, [executionId]); await pool.query(`UPDATE execution_attempts SET heartbeat_at=NOW()-INTERVAL '120 seconds' WHERE id=$1`, [attempt.id]);
    const recovered = await recoverStaleExecutions({ organizationId, staleAfterSeconds: 30 }); expect(recovered.executions.map(run => run.id)).toContain(executionId); expect(recovered.attempts.map(item => item.id)).toContain(attempt.id);
    const run = await getExecutionRun(organizationId, executionId); const attemptRow = (await pool.query('SELECT status,error_code FROM execution_attempts WHERE id=$1', [attempt.id])).rows[0];
    expect(run.status).toBe('FAILED'); expect(attemptRow.status).toBe('FAILED'); expect(attemptRow.error_code).toBe('STALE_EXECUTION_LEASE');
  });
});
