import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import pool from '../../core/db.js';
import { ensureExecutionLifecycleSchema, createExecutionRun, acquireExecutionLease, recoverExpiredExecutionLeases, getExecutionRun } from '../../core/execution_lifecycle.js';
import { ensureExecutionGraph, upsertGraphNode, startNodeAttempt } from '../../core/execution_engine.js';
import { finishExecutionFenced } from '../../core/execution_terminal.js';
import { listExecutionEvents } from '../../core/execution_events.js';

describe('Real atomic execution terminal fencing', () => {
  const organizationId = 'org_execution_terminal_fencing_test';

  beforeAll(async () => {
    await ensureExecutionLifecycleSchema();
    await ensureExecutionGraph();
    await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]);
  });

  afterAll(async () => {
    await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]);
  });

  it('rejects terminal mutation after lease expiry without changing the attempt', async () => {
    const executionId = 'exec_atomic_terminal_expiry';
    await createExecutionRun({ organizationId, executionId });
    const lease = await acquireExecutionLease({ organizationId, executionId, workerId: 'worker-old', leaseSeconds: 15 });
    const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'EXECUTION', logicalKey: executionId });
    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id });

    await pool.query("UPDATE execution_runs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1", [executionId]);
    await recoverExpiredExecutionLeases({ organizationId, executionId });

    await expect(finishExecutionFenced({
      organizationId, executionId, attemptId: attempt.id,
      workerId: 'worker-old', leaseToken: lease.lease_token, status: 'SUCCEEDED'
    })).rejects.toThrow('EXECUTION_LEASE_LOST');

    const attemptRow = (await pool.query('SELECT status,error_code FROM execution_attempts WHERE id=$1', [attempt.id])).rows[0];
    expect(attemptRow.status).toBe('FAILED');
    expect(attemptRow.error_code).toBe('STALE_EXECUTION_LEASE');
    expect((await getExecutionRun(organizationId, executionId)).status).toBe('FAILED');
  });

  it('finishes attempt and execution in one durable transaction while preserving audit order', async () => {
    const executionId = 'exec_atomic_terminal_success';
    await createExecutionRun({ organizationId, executionId });
    const lease = await acquireExecutionLease({ organizationId, executionId, workerId: 'worker-good', leaseSeconds: 30 });
    const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'EXECUTION', logicalKey: executionId });
    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id });

    const result = await finishExecutionFenced({
      organizationId, executionId, attemptId: attempt.id,
      workerId: 'worker-good', leaseToken: lease.lease_token, status: 'SUCCEEDED'
    });

    expect(result.execution.status).toBe('SUCCEEDED');
    expect(result.attempt.status).toBe('SUCCEEDED');
    const events = await listExecutionEvents({ organizationId, executionId });
    const nodeFinished = events.find(event => event.event_type === 'NODE_ATTEMPT_FINISHED');
    const executionFinished = events.find(event => event.event_type === 'EXECUTION_FINISHED');
    expect(nodeFinished).toBeTruthy();
    expect(executionFinished).toBeTruthy();
    expect(BigInt(nodeFinished.sequence)).toBeLessThan(BigInt(executionFinished.sequence));
  });

  it('allows a replacement worker to acquire a recovered execution while the old token remains fenced', async () => {
    const executionId = 'exec_atomic_replacement_worker';
    await createExecutionRun({ organizationId, executionId });
    const oldLease = await acquireExecutionLease({ organizationId, executionId, workerId: 'worker-old', leaseSeconds: 15 });
    await pool.query("UPDATE execution_runs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1", [executionId]);
    await recoverExpiredExecutionLeases({ organizationId, executionId });
    const replacement = await acquireExecutionLease({ organizationId, executionId, workerId: 'worker-new', leaseSeconds: 30 });

    await expect(finishExecutionFenced({
      organizationId, executionId, attemptId: 'missing-attempt',
      workerId: 'worker-old', leaseToken: oldLease.lease_token, status: 'SUCCEEDED'
    })).rejects.toThrow('EXECUTION_LEASE_LOST');

    expect(replacement.lease_owner).toBe('worker-new');
    expect((await getExecutionRun(organizationId, executionId)).status).toBe('RUNNING');
  });
});
