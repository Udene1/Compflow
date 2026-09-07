import { describe, it, expect } from 'vitest';
import {
  ensureExecutionGraph,
  stableUsageId,
  stableEdgeId,
  upsertGraphNode,
  addDependencyEdge,
  startNodeAttempt,
  heartbeatNodeAttempt,
  recoverStaleNodeAttempts,
  finishNodeAttempt,
  getExecutionGraph,
  getResumableNodes,
  claimResumableNode,
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

  it('allows only one live worker lease for a node', async () => {
    const concurrentExecution = 'exec_engine_concurrency_test';
    const node = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:CONCURRENT'), executionId: concurrentExecution });
    const first = await startNodeAttempt({ organizationId, executionId: concurrentExecution, nodeId: node.id, metadata: { worker: 'a' } });
    await expect(startNodeAttempt({ organizationId, executionId: concurrentExecution, nodeId: node.id, metadata: { worker: 'b' } })).rejects.toThrow('NODE_ALREADY_RUNNING');
    await finishNodeAttempt({ attemptId: first.id, status: 'SUCCEEDED' });
  });

  it('returns only dependency-ready retryable nodes for resume', async () => {
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

  it('claims a dependency-ready node exactly once for resume', async () => {
    const resumeExecutionId = 'exec_engine_claim_test';
    const dependency = await upsertGraphNode({ ...nodeArgs('OBSERVATION', 'obs:resume-dependency', 'SUCCEEDED'), executionId: resumeExecutionId });
    const node = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:RESUME', 'FAILED'), executionId: resumeExecutionId });
    await addDependencyEdge({ organizationId, executionId: resumeExecutionId, fromNodeId: dependency.id, toNodeId: node.id });

    const attempt = await claimResumableNode({ organizationId, executionId: resumeExecutionId, nodeId: node.id, metadata: { worker: 'resume-worker' } });
    expect(attempt.status).toBe('RUNNING');
    expect(attempt.metadata.resume).toBe(true);
    await expect(claimResumableNode({ organizationId, executionId: resumeExecutionId, nodeId: node.id })).rejects.toThrow('NODE_NOT_RESUMABLE');
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED' });
  });

  it('does not expose a RUNNING node as resumable', async () => {
    const runningExecution = 'exec_engine_running_test';
    const node = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:RUNNING'), executionId: runningExecution });
    await startNodeAttempt({ organizationId, executionId: runningExecution, nodeId: node.id });

    expect((await getResumableNodes(organizationId, runningExecution)).map(n => n.id)).not.toContain(node.id);
  });

  it('recovers stale attempts into failed nodes that can be resumed', async () => {
    const staleExecution = 'exec_engine_stale_test';
    const node = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:STALE'), executionId: staleExecution });
    const attempt = await startNodeAttempt({ organizationId, executionId: staleExecution, nodeId: node.id });
    await recoverStaleNodeAttempts({ organizationId, executionId: staleExecution, staleAfterSeconds: 30 });
    const graph = await getExecutionGraph(organizationId, staleExecution);
    const recovered = graph.attempts.find(a => a.id === attempt.id);
    expect(recovered.status).toBe('FAILED');
    expect(recovered.errorCode).toBe('STALE_ATTEMPT');
    expect(graph.nodes.find(n => n.id === node.id).status).toBe('FAILED');
    expect((await getResumableNodes(organizationId, staleExecution)).map(n => n.id)).toContain(node.id);
  });

  it('refreshes a running attempt heartbeat and rejects terminal regressions', async () => {
    const heartbeatExecution = 'exec_engine_heartbeat_test';
    const node = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:HEARTBEAT'), executionId: heartbeatExecution });
    const attempt = await startNodeAttempt({ organizationId, executionId: heartbeatExecution, nodeId: node.id });
    const heartbeat = await heartbeatNodeAttempt({ attemptId: attempt.id });
    expect(heartbeat.id).toBe(attempt.id);
    expect(heartbeat.heartbeat_at).toBeTruthy();

    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED' });
    const terminal = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:HEARTBEAT', 'FAILED'), executionId: heartbeatExecution });
    expect(terminal.status).toBe('SUCCEEDED');
    await expect(heartbeatNodeAttempt({ attemptId: attempt.id })).rejects.toThrow('ATTEMPT_NOT_RUNNING');
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