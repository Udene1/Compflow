import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import pool from '../../core/db.js';
import { compilePolicyPlan } from '../../core/policy_planner.js';
import { materializeExecutionPlan, getExecutionPlan } from '../../core/execution_plans.js';
import { ensureExecutionGraph, getExecutionGraph, startNodeAttempt, finishNodeAttempt } from '../../core/execution_engine.js';
import { createExecutionRun, getExecutionRun } from '../../core/execution_lifecycle.js';
import { dispatchReadyPlanNodes, startPersistedPlanExecution, approveExecutionNode } from '../../core/plan_executor.js';
import { closeQueue } from '../../core/queue.js';

const organizationId = 'org_plan_execution_test';
const executionId = 'exec_plan_execution_test';
const policy = { id: 'plan-execution-policy', version: '1', frameworks: ['soc2'], mode: 'REMEDIATE', rules: [{ id: 'storage', controlId: 'S3_PUBLIC', action: 'REMEDIATE', requiresApproval: true }] };
const targets = [{ connectionId: 'conn-plan-test', provider: 'aws', resourceId: 'bucket-test' }];

beforeAll(async () => {
  await ensureExecutionGraph();
  await pool.query(`CREATE TABLE IF NOT EXISTS execution_plans (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, policy_id TEXT NOT NULL, policy_version TEXT NOT NULL, plan_version INTEGER NOT NULL, plan_hash TEXT NOT NULL, plan JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (organization_id, execution_id), UNIQUE (organization_id, plan_hash))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS execution_evidence (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, node_id TEXT NOT NULL, attempt_id TEXT NOT NULL, control_id TEXT NOT NULL, provider TEXT NOT NULL, connection_id TEXT NOT NULL, resource_id TEXT, source_type TEXT NOT NULL, evidence JSONB NOT NULL, evidence_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (organization_id, execution_id, node_id))`);
  await pool.query('DELETE FROM execution_evidence WHERE organization_id=$1', [organizationId]);
  await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]);
  await pool.query('DELETE FROM execution_plans WHERE organization_id=$1', [organizationId]);
  await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
});

afterAll(async () => { await closeQueue().catch(() => {}); });

describe('persisted plan execution', () => {
  it('activates the persisted plan and dispatches only dependency-ready nodes', async () => {
    const plan = compilePolicyPlan({ organizationId, executionId, policy, targets });
    await materializeExecutionPlan({ organizationId, executionId, plan });
    const result = await startPersistedPlanExecution({ organizationId, executionId });
    expect(result.planHash).toBe(plan.planHash);
    expect(result.dispatched).toHaveLength(1);
    const graph = await getExecutionGraph(organizationId, executionId);
    const planNode = graph.nodes.find(n => n.node_type === 'PLAN');
    const evidence = graph.nodes.find(n => n.node_type === 'EVIDENCE_COLLECTION');
    const evaluation = graph.nodes.find(n => n.node_type === 'CONTROL_EVALUATION');
    expect(planNode.status).toBe('SUCCEEDED');
    expect(evidence.status).toBe('RUNNING');
    expect(evaluation.status).toBe('PENDING');
    expect((await getExecutionRun(organizationId, executionId)).status).toBe('RUNNING');
  });

  it('does not dispatch remediation until a human approval node is granted', async () => {
    const graph = await getExecutionGraph(organizationId, executionId);
    const evaluation = graph.nodes.find(n => n.node_type === 'CONTROL_EVALUATION');
    const evidence = graph.nodes.find(n => n.node_type === 'EVIDENCE_COLLECTION');
    const evidenceAttempt = graph.attempts.find(a => a.node_id === evidence.id && a.status === 'RUNNING');
    await finishNodeAttempt({ attemptId: evidenceAttempt.id, status: 'SUCCEEDED', metadata: { testSetup: 'real-db-state' } });
    const evaluationAttempt = await startNodeAttempt({ organizationId, executionId, nodeId: evaluation.id, metadata: { testSetup: 'real-db-state' } });
    await finishNodeAttempt({ attemptId: evaluationAttempt.id, status: 'SUCCEEDED', metadata: { assessment: 'FAIL' } });
    const refreshed = await getExecutionGraph(organizationId, executionId);
    const approval = refreshed.nodes.find(n => n.node_type === 'APPROVAL');
    const remediation = refreshed.nodes.find(n => n.node_type === 'REMEDIATION');
    expect(approval.status).toBe('PENDING');
    expect(remediation.status).toBe('PENDING');
    await expect(approveExecutionNode({ organizationId, executionId, nodeId: approval.id, actorId: 'operator-test' })).resolves.toMatchObject({ status: 'SUCCEEDED' });
    const afterApproval = await getExecutionGraph(organizationId, executionId);
    expect(afterApproval.nodes.find(n => n.id === remediation.id).status).toBe('RUNNING');
  });

  it('rejects replacement of an already persisted plan with a different hash', async () => {
    const stored = await getExecutionPlan({ organizationId, executionId });
    const altered = structuredClone(policy); altered.version = '2';
    const different = compilePolicyPlan({ organizationId, executionId, policy: altered, targets });
    expect(different.planHash).not.toBe(stored.plan_hash);
    await expect(materializeExecutionPlan({ organizationId, executionId, plan: different })).rejects.toThrow('EXECUTION_PLAN_IMMUTABLE');
  });
});
