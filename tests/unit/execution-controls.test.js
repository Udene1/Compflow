import { describe, expect, it, beforeAll } from 'vitest';
import pool from '../../core/db.js';
import { ensureExecutionGraph, upsertGraphNode, startNodeAttempt } from '../../core/execution_engine.js';
import { ensureExecutionLifecycleSchema, createExecutionRun, acquireExecutionLease, cancelExecutionRun, getExecutionRun } from '../../core/execution_lifecycle.js';

describe('Durable execution controls', () => {
  const organizationId = 'org_execution_controls_test';

  beforeAll(async () => {
    await ensureExecutionGraph();
    await ensureExecutionLifecycleSchema();
    await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]);
  });

  it('cancels an active execution and fences its running attempt', async () => {
    const executionId = 'exec_execution_controls_cancel';
    await createExecutionRun({ organizationId, executionId });
    const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'WORK', logicalKey: 'cancel-me' });
    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id });
    const leased = await acquireExecutionLease({ organizationId, executionId, workerId: 'controls-worker' });
    const cancelled = await cancelExecutionRun({ organizationId, executionId, reason: 'operator requested cancellation' });

    expect(cancelled.status).toBe('CANCELLED');
    const run = await getExecutionRun(organizationId, executionId);
    expect(run.status).toBe('CANCELLED');
    expect(run.lease_token).toBeNull();

    const attemptRow = await pool.query('SELECT status,error_code FROM execution_attempts WHERE id=$1', [attempt.id]);
    expect(attemptRow.rows[0].status).toBe('CANCELLED');
    expect(attemptRow.rows[0].error_code).toBe('EXECUTION_CANCELLED');
    expect(leased.lease_owner).toBe('controls-worker');
  });

  it('keeps a cancelled execution terminal', async () => {
    const executionId = 'exec_execution_controls_terminal';
    await createExecutionRun({ organizationId, executionId });
    const cancelled = await cancelExecutionRun({ organizationId, executionId });
    const again = await cancelExecutionRun({ organizationId, executionId });
    expect(cancelled.status).toBe('CANCELLED');
    expect(again.status).toBe('CANCELLED');
  });

  it('allows only one concurrent cancellation transition to win and preserves one terminal audit event per idempotency key', async () => {
    const executionId = 'exec_execution_controls_concurrent';
    await createExecutionRun({ organizationId, executionId });
    const idempotencyKey = 'cancel-concurrent-001';

    const results = await Promise.all([
      cancelExecutionRun({ organizationId, executionId, reason: 'first concurrent request', actorId: 'user-a', idempotencyKey }),
      cancelExecutionRun({ organizationId, executionId, reason: 'second concurrent request', actorId: 'user-b', idempotencyKey })
    ]);

    expect(results).toHaveLength(2);
    expect(results[0].status).toBe('CANCELLED');
    expect(results[1].status).toBe('CANCELLED');

    const run = await getExecutionRun(organizationId, executionId);
    expect(run.status).toBe('CANCELLED');

    const events = await pool.query(
      `SELECT id, idempotency_key FROM execution_events
       WHERE organization_id=$1 AND execution_id=$2 AND event_type='EXECUTION_CANCELLED'`,
      [organizationId, executionId]
    );
    expect(events.rows).toHaveLength(1);
    expect(events.rows[0].idempotency_key).toBe(idempotencyKey);
  });
});
