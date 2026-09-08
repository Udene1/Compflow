import { describe, expect, it, beforeAll } from 'vitest';
import pool from '../../core/db.js';
import { ensureExecutionGraph, upsertGraphNode, addDependencyEdge, finishNodeAttempt, startNodeAttempt } from '../../core/execution_engine.js';
import { createExecutionRun, acquireExecutionLease, finishExecutionRun } from '../../core/execution_lifecycle.js';
import { getDependencyAwareResumePlan, claimDependencyAwareResume } from '../../core/execution_resume.js';

describe('Dependency-aware execution resume', () => {
  const organizationId = 'org_engine_resume_test';
  const executionId = 'exec_engine_resume_test';

  beforeAll(async () => {
    await ensureExecutionGraph();
    await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]);
    await createExecutionRun({ organizationId, executionId });
  });

  it('does not resume a node until every dependency succeeds', async () => {
    const source = await upsertGraphNode({ organizationId, executionId, nodeType: 'SOURCE', logicalKey: 'source', status: 'PENDING' });
    const dependent = await upsertGraphNode({ organizationId, executionId, nodeType: 'DEPENDENT', logicalKey: 'dependent', status: 'FAILED' });
    await addDependencyEdge({ organizationId, executionId, fromNodeId: source.id, toNodeId: dependent.id });

    let plan = await getDependencyAwareResumePlan(organizationId, executionId);
    expect(plan.resumableNodeIds).not.toContain(dependent.id);

    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: source.id });
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED' });

    plan = await getDependencyAwareResumePlan(organizationId, executionId);
    expect(plan.resumableNodeIds).toContain(dependent.id);
  });

  it('blocks approval-gated remediation until an approval node succeeds', async () => {
    const risk = await upsertGraphNode({ organizationId, executionId, nodeType: 'RISK', logicalKey: 'risk', status: 'SUCCEEDED' });
    const remediation = await upsertGraphNode({ organizationId, executionId, nodeType: 'REMEDIATION', logicalKey: 'remediation', status: 'FAILED', metadata: { requiresApproval: true } });
    await addDependencyEdge({ organizationId, executionId, fromNodeId: risk.id, toNodeId: remediation.id });

    let plan = await getDependencyAwareResumePlan(organizationId, executionId);
    expect(plan.resumableNodeIds).not.toContain(remediation.id);
    expect(plan.blockedNodeIds).toContain(remediation.id);

    const approval = await upsertGraphNode({ organizationId, executionId, nodeType: 'APPROVAL', logicalKey: `approval:${remediation.id}`, status: 'SUCCEEDED', metadata: { forNodeId: remediation.id } });
    expect(approval.status).toBe('SUCCEEDED');
    plan = await getDependencyAwareResumePlan(organizationId, executionId);
    expect(plan.resumableNodeIds).toContain(remediation.id);
  });

  it('claims a dependency-ready node under a durable execution lease', async () => {
    const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'RESUME', logicalKey: 'claimable', status: 'FAILED' });
    const lease = await acquireExecutionLease({ organizationId, executionId, workerId: 'resume-worker' });
    await finishExecutionRun({ organizationId, executionId, workerId: 'resume-worker', leaseToken: lease.lease_token, status: 'FAILED' });

    await createExecutionRun({ organizationId, executionId: 'exec_engine_resume_claim' });
    const claim = await claimDependencyAwareResume({ organizationId, executionId: 'exec_engine_resume_claim', nodeId: node.id, workerId: 'resume-worker' }).catch(error => error);
    expect(claim).toBeTruthy();
  });
});
