import { recoverExpiredExecutionLeases } from './execution_lifecycle.js';
import { recoverStaleNodeAttempts } from './execution_engine.js';

const DEFAULT_INTERVAL_MS = 15_000;
const DEFAULT_STALE_AFTER_SECONDS = 90;

export async function recoverStaleExecutions({ organizationId = null, staleAfterSeconds = DEFAULT_STALE_AFTER_SECONDS } = {}) {
  const leaseRecovery = organizationId
    ? await recoverExpiredExecutionLeases({ organizationId })
    : [];

  const organizations = organizationId
    ? [organizationId]
    : leaseRecovery.map(run => run.organization_id);

  const attemptRecovery = [];
  for (const orgId of organizations) {
    attemptRecovery.push(...await recoverStaleNodeAttempts({
      organizationId: orgId,
      staleAfterSeconds
    }));
  }

  return { executions: leaseRecovery, attempts: attemptRecovery };
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
