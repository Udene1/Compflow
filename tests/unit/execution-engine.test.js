import { describe, it, expect } from 'vitest';
import {
  ensureExecutionGraph,
  stableUsageId,
  stableEdgeId,
  upsertGraphNode,
  addDependencyEdge,
  startNodeAttempt,
  finishNodeAttempt,
  getExecutionGraph,
  getResumableNodes,
  resumeExecution
} from '../../core/execution_engine.js';

const organizationId = 'org_engine_graph_test';
const executionId = 'exec_engine_graph_test';

function nodeArgs(nodeType, logicalKey, status = 'PENDING') {
  return { organizationId, executionId, nodeType, logicalKey, status, label: logicalKey };
}

describe('Durable execution graph engine', () => {
  it('generates stable usage and edge IDs', () => {
    const a = stableUsageId(organizationId, executionId, 'CONTROL', 'CC6.1');
    const b = stableUsageId(organizationId, executionId, 'CONTROL', 'CC6.1');
    expect(a).toBe(b);
    expect(a).toMatch(/^node_[a-f0-9]{32}$/);

    const edgeA = stableEdgeId(executionId, a, 'node_target', 'DEPENDS_ON');
    const edgeB = stableEdgeId(executionId, a, 'node_target', 'DEPENDS_ON');
    expect(edgeA).toBe(edgeB);
    expect(edgeA).toMatch(/^edge_[a-f0-9]{32}$/);
  });

  it('persists nodes, dependency edges, attempts and a chronological timeline in PostgreSQL', async () => {
    await ensureExecutionGraph();

    const observation = await upsertGraphNode(nodeArgs('OBSERVATION', 'obs:public-bucket'));
    const control = await upsertGraphNode(nodeArgs('CONTROL', 'soc2:CC6.1'));
    const evidence = await upsertGraphNode(nodeArgs('EVIDENCE', 'evidence:public-bucket'));

    const edgeOne = await addDependencyEdge({ organizationId, executionId, fromNodeId: observation.id, toNodeId: control.id });
    const edgeTwo = await addDependencyEdge({ organizationId, executionId, fromNodeId: control.id, toNodeId: evidence.id });

    expect(edgeOne.id).toBe(stableEdgeId(executionId, observation.id, control.id));
    expect(edgeTwo.id).toBe(stableEdgeId(executionId, control.id, evidence.id));

    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: observation.id });
    expect(attempt.attempt_number).toBeGreaterThanOrEqual(1);
    expect(attempt.status).toBe('RUNNING');
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED' });

    const failed = await startNodeAttempt({ organizationId, executionId, nodeId: control.id });
    await finishNodeAttempt({ attemptId: failed.id, status: 'FAILED', errorCode: 'CONTROL_TIMEOUT' });
    const retry = await startNodeAttempt({ organizationId, executionId, nodeId: control.id });
    await finishNodeAttempt({ attemptId: retry.id, status: 'SUCCEEDED' });

    const graph = await getExecutionGraph(organizationId, executionId);
    expect(graph.nodes.map(n => n.id)).toEqual(expect.arrayContaining([observation.id, control.id, evidence.id]));
    expect(graph.edges).toHaveLength(2);
    expect(graph.attempts.length).toBeGreaterThanOrEqual(3);
    expect(graph.timeline.some(item => item.errorCode === 'CONTROL_TIMEOUT')).toBe(true);
  });

  it('returns only dependency-ready unfinished nodes for resume', async () => {
    const graph = await getExecutionGraph(organizationId, executionId);
    const resumable = await getResumableNodes(organizationId, executionId);

    const observation = graph.nodes.find(n => n.logical_key === 'obs:public-bucket');
    const control = graph.nodes.find(n => n.logical_key === 'soc2:CC6.1');
    const evidence = graph.nodes.find(n => n.logical_key === 'evidence:public-bucket');

    expect(resumable.map(n => n.id)).not.toContain(observation.id);
    expect(resumable.map(n => n.id)).not.toContain(control.id);
    expect(resumable.map(n => n.id)).toContain(evidence.id);

    const resumed = await resumeExecution(organizationId, executionId);
    expect(resumed.resumableNodeIds).toContain(evidence.id);
  });

  it('models failed controls as risk with approval-gated remediation', async () => {
    const riskExecution = 'exec_engine_risk_test';
    const observation = await upsertGraphNode({ ...nodeArgs('OBSERVATION', 'obs:overexposed-api'), executionId: riskExecution, status: 'SUCCEEDED' });
    const control = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:CC6.1'), executionId: riskExecution, status: 'FAILED' });
    const risk = await upsertGraphNode({
      ...nodeArgs('RISK', 'soc2:CC6.1:obs:overexposed-api'),
      executionId: riskExecution,
      status: 'PENDING',
      metadata: { severity: 'high' }
    });
    const remediation = await upsertGraphNode({
      ...nodeArgs('REMEDIATION', 'soc2:CC6.1:obs:overexposed-api'),
      executionId: riskExecution,
      status: 'PENDING',
      metadata: { requiresApproval: true }
    });

    await addDependencyEdge({ organizationId, executionId: riskExecution, fromNodeId: observation.id, toNodeId: control.id });
    await addDependencyEdge({ organizationId, executionId: riskExecution, fromNodeId: control.id, toNodeId: risk.id });
    await addDependencyEdge({ organizationId, executionId: riskExecution, fromNodeId: risk.id, toNodeId: remediation.id });

    expect((await getResumableNodes(organizationId, riskExecution)).map(n => n.id)).not.toContain(risk.id);

    const retry = await startNodeAttempt({ organizationId, executionId: riskExecution, nodeId: control.id });
    await finishNodeAttempt({ attemptId: retry.id, status: 'SUCCEEDED' });

    const graph = await getExecutionGraph(organizationId, riskExecution);
    expect(graph.nodes.map(n => n.node_type)).toEqual(expect.arrayContaining(['OBSERVATION', 'CONTROL', 'RISK', 'REMEDIATION']));
    expect(graph.edges).toHaveLength(3);
    expect(graph.nodes.find(n => n.id === remediation.id).metadata.requiresApproval).toBe(true);
    expect((await getResumableNodes(organizationId, riskExecution)).map(n => n.id)).toContain(risk.id);
  });
});
