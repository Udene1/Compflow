import { describe, expect, it, beforeAll } from 'vitest';
import pool from '../../core/db.js';
import { ensureExecutionLifecycleSchema, createExecutionRun, acquireExecutionLease, finishExecutionRun, cancelExecutionRun } from '../../core/execution_lifecycle.js';
import { ensureExecutionEventsSchema, appendExecutionEvent, listExecutionEvents } from '../../core/execution_events.js';

describe('Durable execution event history', () => {
  const organizationId = 'org_execution_events_test';

  beforeAll(async () => {
    await ensureExecutionLifecycleSchema();
    await ensureExecutionEventsSchema();
    await pool.query('DELETE FROM execution_events WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
  });

  it('records ordered lifecycle events in PostgreSQL and is idempotent', async () => {
    const executionId = 'exec_events_ordered';
    await createExecutionRun({ organizationId, executionId, metadata: { provider: 'aws' } });
    const lease = await acquireExecutionLease({ organizationId, executionId, workerId: 'events-worker' });
    await finishExecutionRun({ organizationId, executionId, workerId: 'events-worker', leaseToken: lease.lease_token, status: 'SUCCEEDED' });

    const events = await listExecutionEvents({ organizationId, executionId });
    expect(events.map(event => event.event_type)).toEqual([
      'EXECUTION_CREATED',
      'EXECUTION_LEASE_ACQUIRED',
      'EXECUTION_FINISHED'
    ]);
    expect(BigInt(events[1].sequence)).toBeGreaterThan(BigInt(events[0].sequence));
    expect(BigInt(events[2].sequence)).toBeGreaterThan(BigInt(events[1].sequence));

    await appendExecutionEvent({ organizationId, executionId, eventType: 'EXECUTION_CREATED', payload: { should: 'not duplicate' }, idempotencyKey: 'created' });
    expect(await listExecutionEvents({ organizationId, executionId })).toHaveLength(3);
  });

  it('sanitizes sensitive event payload keys', async () => {
    const executionId = 'exec_events_sanitize';
    await createExecutionRun({ organizationId, executionId });
    await appendExecutionEvent({
      organizationId,
      executionId,
      eventType: 'TEST_EVENT',
      payload: { safe: 'visible', token: 'secret-token', nested: { password: 'secret-password', value: 'kept' } }
    });
    const events = await listExecutionEvents({ organizationId, executionId });
    const payload = events.find(event => event.event_type === 'TEST_EVENT').payload;
    expect(payload.safe).toBe('visible');
    expect(payload.token).toBeUndefined();
    expect(payload.nested.password).toBeUndefined();
    expect(payload.nested.value).toBe('kept');
  });

  it('records operator cancellation as an auditable terminal event', async () => {
    const executionId = 'exec_events_cancel';
    await createExecutionRun({ organizationId, executionId });
    await acquireExecutionLease({ organizationId, executionId, workerId: 'cancel-worker' });
    await cancelExecutionRun({ organizationId, executionId, reason: 'Operator requested cancellation' });
    const events = await listExecutionEvents({ organizationId, executionId });
    const event = events.find(item => item.event_type === 'EXECUTION_CANCELLED');
    expect(event).toBeTruthy();
    expect(event.actor_type).toBe('USER');
    expect(event.result).toBe('success');
    expect(event.payload.reason).toBe('Operator requested cancellation');
  });
});
