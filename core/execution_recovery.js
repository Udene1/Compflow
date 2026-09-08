import pool from './db.js';
import { recoverExpiredExecutionLeases } from './execution_lifecycle.js';
import { recoverStaleNodeAttempts } from './execution_engine.js';
import { appendExecutionEvent } from './execution_events.js';

const DEFAULT_INTERVAL_MS = 15_000;
const DEFAULT_STALE_AFTER_SECONDS = 90;

export async function recoverStaleExecutions({ organizationId = null, staleAfterSeconds = DEFAULT_STALE_AFTER_SECONDS } = {}) {
  const recoveredExecutions = await recoverExpiredExecutionLeases({ organizationId });
  const attempts = recoveredExecutions.flatMap(run => run.recoveredAttempts || []);
  const recoveredExecutionIds = new Set(recoveredExecutions.map(run => run.id));
  const organizations = organizationId
    ? [organizationId]
    : (await pool.query('SELECT DISTINCT organization_id FROM execution_attempts WHERE status=\'RUNNING\'')).rows.map(row => row.organization_id);

  for (const attempt of attempts) {
    await appendExecutionEvent({
      organizationId: attempt.organization_id,
      executionId: attempt.execution_id,
      nodeId: attempt.node_id,
      attemptId: attempt.id,
      eventType: 'NODE_ATTEMPT_STALE_RECOVERED',
      actorType: 'SYSTEM',
      result: 'failed',
      payload: { errorCode: 'STALE_EXECUTION_LEASE', attemptNumber: attempt.attempt_number }
    });
  }

  const staleAttempts = [];
  for (const orgId of organizations) {
    const recovered = await recoverStaleNodeAttempts({ organizationId: orgId, staleAfterSeconds });
    for (const attempt of recovered) {
      if (recoveredExecutionIds.has(attempt.execution_id)) continue;
      staleAttempts.push(attempt);
      await appendExecutionEvent({
        organizationId: attempt.organization_id,
        executionId: attempt.execution_id,
        nodeId: attempt.node_id,
        attemptId: attempt.id,
        eventType: 'NODE_ATTEMPT_STALE_RECOVERED',
        actorType: 'SYSTEM',
        result: 'failed',
        payload: { errorCode: 'STALE_ATTEMPT', attemptNumber: attempt.attempt_number }
      });
    }
  }

  return { executions: recoveredExecutions, attempts: [...attempts, ...staleAttempts] };
}

export function startExecutionRecovery({
  intervalMs = DEFAULT_INTERVAL_MS,
  staleAfterSeconds = DEFAULT_STALE_AFTER_SECONDS,
  organizationId = null,
  onError = (error) => console.error('[EXECUTION-RECOVERY] Recovery cycle failed:', error?.message || error)
} = {}) {
  const interval = Math.max(5_000, Number(intervalMs) || DEFAULT_INTERVAL_MS);
  let stopped = false;
  let running = false;

  const tick = async () => {
    if (stopped || running) return;
    running = true;
    try {
      await recoverStaleExecutions({ organizationId, staleAfterSeconds });
    } catch (error) {
      onError(error);
    } finally {
      running = false;
    }
  };

  const timer = setInterval(tick, interval);
  timer.unref?.();
  void tick();

  return () => {
    stopped = true;
    clearInterval(timer);
  };
}
