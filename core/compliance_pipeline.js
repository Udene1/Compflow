import { normalizeIntent, persistIntent, intentToPolicy } from './intent.js';
import { compilePolicyPlan } from './policy_planner.js';
import { materializeExecutionPlan } from './execution_plans.js';
import { startPersistedPlanExecution } from './plan_executor.js';
import { finalizeExecutionDecision } from './compliance_decision.js';

/**
 * Canonical compliance entrypoint. It creates immutable intent, compiles it once,
 * materializes the durable graph, and starts real worker execution. No step here
 * claims evidence or compliance before the worker has actually produced it.
 */
export async function startComplianceExecution({ organizationId, executionId, intent } = {}) {
  const normalized = normalizeIntent({ organizationId, intent, targets: intent?.targets });
  const storedIntent = await persistIntent({ organizationId, intent: normalized });
  const policy = { ...intentToPolicy(normalized), intentHash: normalized.intentHash };
  const plan = compilePolicyPlan({ organizationId, executionId, policy, targets: normalized.targets });
  await materializeExecutionPlan({ organizationId, executionId, plan });
  const execution = await startPersistedPlanExecution({ organizationId, executionId });
  return { intent: storedIntent, plan, execution };
}

/** Final decision is intentionally separate from dispatch: it must consume durable evaluation/verification results. */
export async function finalizeComplianceDecision({ organizationId, executionId } = {}) {
  return finalizeExecutionDecision({ organizationId, executionId });
}
