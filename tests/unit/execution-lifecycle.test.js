import { describe, expect, it, beforeAll } from 'vitest';
import pool from '../../core/db.js';
import {
  ensureExecutionLifecycleSchema,
  createExecutionRun,
  getExecutionRun,
  acquireExecutionLease,
  heartbeatExecutionLease,
  finishExecutionRun,
  recoverExpiredExecutionLeases
} from '../../core/execution_lifecycle.js';

describe('Durable execution lifecycle and leases', () => {
  const organizationId = 'org_engine_lifecycle_test';
  const executionId = 'exec_engine_lifecycle_test';

  beforeAll(async () => {
    await ensureExecutionLifecycleSchema();
    await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
  });

  it('creates a durable pending execution', async () => {
    const run = await createExecutionRun({ organizationId, executionId, metadata: { source: 'test' } });
    expect(run.status).toBe('PENDING');
    expect(run.organization_id).toBe(organizationId);
    expect(run.metadata).toMatchObject({ source: 'test' });
  });

  it('collapses concurrent creation of the same execution into one durable row', async () => {
    const raceId = 'exec_engine_lifecycle_create_race';
    await pool.query('DELETE FROM execution_runs WHERE id=$1', [raceId]);
    const [first, second] = await Promise.all([
      createExecutionRun({ organizationId, executionId: raceId, metadata: { source: 'race-a' } }),
      createExecutionRun({ organizationId, executionId: raceId, metadata: { source: 'race-b' } })
    ]);
    expect(first.id).toBe(raceId);
    expect(second.id).toBe(raceId);
    expect(first.organization_id).toBe(organizationId);
    expect(second.organization_id).toBe(organizationId);
    const rows = await pool.query('SELECT * FROM execution_runs WHERE id=$1', [raceId]);
    expect(rows.rows).toHaveLength(1);
  });

  it('grants exactly one live execution lease', async () => {
    const first = await acquireExecutionLease({ organizationId, executionId, workerId: 'worker-a', leaseSeconds: 60 });
    expect(first.status).toBe('RUNNING');
    expect(first.lease_owner).toBe('worker-a');
    expect(first.lease_token).toBeTruthy();

    await expect(acquireExecutionLease({ organizationId, executionId, workerId: 'worker-b', leaseSeconds: 60 }))
      .rejects.toThrow('EXECUTION_ALREADY_LEASED');
  });

  it('rejects active lease replacement even when the contender has the same worker identity', async () => {
    const run = await getExecutionRun(organizationId, executionId);
    await expect(acquireExecutionLease({ organizationId, executionId, workerId: 'worker-a', leaseSeconds: 60 }))
      .rejects.toThrow('EXECUTION_ALREADY_LEASED');

    const after = await getExecutionRun(organizationId, executionId);
    expect(after.lease_token).toBe(run.lease_token);
    expect(after.lease_owner).toBe('worker-a');
  });

  it('heartbeats only with the current fencing credentials', async () => {
    const run = await getExecutionRun(organizationId, executionId);
    const heartbeat = await heartbeatExecutionLease({ organizationId, executionId, workerId: 'worker-a', leaseToken: run.lease_token, leaseSeconds: 60 });
    expect(heartbeat.id).toBe(executionId);
    await expect(heartbeatExecutionLease({ organizationId, executionId, workerId: 'worker-b', leaseToken: run.lease_token, leaseSeconds: 60 })).rejects.toThrow('EXECUTION_LEASE_LOST');
  });

  it('finishes only through the active lease and prevents terminal regression', async () => {
    const run = await getExecutionRun(organizationId, executionId);
    const finished = await finishExecutionRun({ organizationId, executionId, workerId: 'worker-a', leaseToken: run.lease_token, status: 'SUCCEEDED' });
    expect(finished.status).toBe('SUCCEEDED');
    expect(finished.lease_token).toBeNull();
    expect(finished.finished_at).toBeTruthy();
    await expect(acquireExecutionLease({ organizationId, executionId, workerId: 'worker-b' })).rejects.toThrow('EXECUTION_ALREADY_TERMINAL');
  });

  it('recovers an expired running execution lease atomically', async () => {
    const staleId = 'exec_engine_lifecycle_stale';
    await createExecutionRun({ organizationId, executionId: staleId });
    const run = await acquireExecutionLease({ organizationId, executionId: staleId, workerId: 'dead-worker', leaseSeconds: 15 });
    await pool.query(`UPDATE execution_runs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1`, [staleId]);
    const recovered = await recoverExpiredExecutionLeases({ organizationId, executionId: staleId });
    expect(recovered).toHaveLength(1);
    expect(recovered[0].status).toBe('FAILED');
    expect(recovered[0].error_code).toBe('STALE_EXECUTION_LEASE');
    const after = await getExecutionRun(organizationId, staleId);
    expect(after.lease_owner).toBeNull();
    expect(after.lease_token).toBeNull();
    expect(after.status).toBe('FAILED');
    await expect(heartbeatExecutionLease({ organizationId, executionId: staleId, workerId: 'dead-worker', leaseToken: run.lease_token })).rejects.toThrow('EXECUTION_LEASE_LOST');
  });

  it('hands an expired execution from recovery to one new lease holder without reviving the old worker', async () => {
    const raceId = 'exec_engine_lifecycle_recovery_race';
    await createExecutionRun({ organizationId, executionId: raceId });
    const oldLease = await acquireExecutionLease({ organizationId, executionId: raceId, workerId: 'old-worker', leaseSeconds: 15 });
    await pool.query(`UPDATE execution_runs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1`, [raceId]);
    const [recoveryResult, acquireResult] = await Promise.all([
      recoverExpiredExecutionLeases({ organizationId, executionId: raceId }),
      acquireExecutionLease({ organizationId, executionId: raceId, workerId: 'new-worker', leaseSeconds: 60 })
    ]);
    const finalRun = await getExecutionRun(organizationId, raceId);
    expect(finalRun.status).toBe('RUNNING');
    expect(finalRun.lease_owner).toBe('new-worker');
    expect(finalRun.lease_token).toBeTruthy();
    expect(finalRun.lease_token).not.toBe(oldLease.lease_token);
    expect(recoveryResult.length + (acquireResult ? 1 : 0)).toBeGreaterThanOrEqual(1);
    await expect(heartbeatExecutionLease({ organizationId, executionId: raceId, workerId: 'old-worker', leaseToken: oldLease.lease_token })).rejects.toThrow('EXECUTION_LEASE_LOST');
    await finishExecutionRun({ organizationId, executionId: raceId, workerId: 'new-worker', leaseToken: finalRun.lease_token, status: 'FAILED', errorCode: 'TEST_CLEANUP' });
  });
});
