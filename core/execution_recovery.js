import pool from './db.js';
import { recoverExpiredExecutionLeases } from './execution_lifecycle.js';
import { recoverStaleNodeAttempts } from './execution_engine.js';

const DEFAULT_INTERVAL_MS = 15_000;
const DEFAULT_STALE_AFTER_SECONDS = 90;

export async function recoverStaleExecutions({ organizationId = null, staleAfterSeconds = DEFAULT_STALE_AFTER_SECONDS } = {}) {
  const executions = await recoverExpiredExecutionLeases({ organizationId });
  const organizations = organizationId
    ? [organizationId]
    : (await pool.query("SELECT DISTINCT organization_id FROM execution_runs WHERE status='RUNNING' OR lease_expires_at IS NOT NULL")).rows.map(row => row.organization_id);

  const attempts = [];
  for (const orgId of organizations) {
    attempts.push(...await recoverStaleNodeAttempts({ organizationId: orgId, staleAfterSeconds }));
  }

  return { executions, attempts };
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
