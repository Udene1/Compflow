import { describe, expect, it, beforeAll } from 'vitest';
import pool from '../../core/db.js';
import {
  ensureExecutionLifecycleSchema,
  createExecutionRun,
  acquireExecutionLease,
  heartbeatExecutionLease,
  finishExecutionRun,
  recoverExpiredExecutionLeases,
  getExecutionRun
} from '../../core/execution_lifecycle.js';
import { ensureExecutionGraph, upsertGraphNode, startNodeAttempt, finishNodeAttempt, recoverStaleNodeAttempts } from '../../core/execution_engine.js';

describe('Real execution lease fencing', () => {
  const organizationId = 'org_execution_fencing_test';

  beforeAll(async () => {
    await ensureExecutionLifecycleSchema();
    await ensureExecutionGraph();
    await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]);
  });

  it('rejects a stale worker heartbeat after automatic lease recovery', async () => {
    const executionId = 'exec_execution_fencing_stale';
    await createExecutionRun({ organizationId, executionId });
    const lease = await acquireExecutionLease({ organizationId, executionId, workerId: 'worker-a', leaseSeconds: 15 });

    await pool.query("UPDATE execution_runs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1", [executionId]);
    const recovered = await recoverExpiredExecutionLeases({ organizationId, executionId });
    expect(recovered).toHaveLength(1);
    expect(recovered[0].error_code).toBe('STALE_EXECUTION_LEASE');

    await expect(heartbeatExecutionLease({
      organizationId,
      executionId,
      workerId: 'worker-a',
      leaseToken: lease.lease_token
    })).rejects.toThrow('EXECUTION_LEASE_LOST');

    await expect(finishExecutionRun({
      organizationId,
      executionId,
      workerId: 'worker-a',
      leaseToken: lease.lease_token,
      status: 'SUCCEEDED'
    })).rejects.toThrow('EXECUTION_LEASE_LOST');

    expect((await getExecutionRun(organizationId, executionId)).status).toBe('FAILED');
  });

  it('fences terminal completion when the lease expires while the transaction waits for the execution row', async () => {
    const executionId = 'exec_execution_fencing_expiry_race';
    await createExecutionRun({ organizationId, executionId });
    const lease = await acquireExecutionLease({ organizationId, executionId, workerId: 'worker-race', leaseSeconds: 15 });
    await pool.query("UPDATE execution_runs SET lease_expires_at=clock_timestamp()+INTERVAL '1 second' WHERE id=$1", [executionId]);

    const blocker = await pool.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT id FROM execution_runs WHERE id=$1 FOR UPDATE', [executionId]);
      const finishing = finishExecutionRun({
        organizationId,
        executionId,
        workerId: 'worker-race',
        leaseToken: lease.lease_token,
        status: 'SUCCEEDED'
      });
      await new Promise(resolve => setTimeout(resolve, 1500));
      await blocker.query('COMMIT');
      await expect(finishing).rejects.toThrow('EXECUTION_LEASE_LOST');
      expect((await getExecutionRun(organizationId, executionId)).status).toBe('RUNNING');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('does not allow an old worker to finish a recovered node attempt', async () => {
    const executionId = 'exec_execution_fencing_attempt';
    await createExecutionRun({ organizationId, executionId });
    const lease = await acquireExecutionLease({ organizationId, executionId, workerId: 'worker-a', leaseSeconds: 15 });
    const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'EXECUTION', logicalKey: executionId, status: 'PENDING' });
    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id, metadata: { workerId: 'worker-a' } });

    await pool.query("UPDATE execution_attempts SET heartbeat_at=NOW()-INTERVAL '120 seconds' WHERE id=$1", [attempt.id]);
    const stale = await recoverStaleNodeAttempts({ organizationId, executionId, staleAfterSeconds: 30 });
    expect(stale).toHaveLength(1);
    expect(stale[0].error_code).toBe('STALE_ATTEMPT');

    await expect(finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED' })).rejects.toThrow('ATTEMPT_NOT_FOUND_OR_ALREADY_FINISHED');
    expect((await getExecutionRun(organizationId, executionId)).status).toBe('RUNNING');

    await heartbeatExecutionLease({ organizationId, executionId, workerId: 'worker-a', leaseToken: lease.lease_token });
  });
});
