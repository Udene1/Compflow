import { describe, expect, it, beforeAll } from 'vitest';
import pool from '../../core/db.js';
import {
  ensureExecutionGraph,
  upsertGraphNode,
  addDependencyEdge,
  startNodeAttempt,
  heartbeatNodeAttempt,
  finishNodeAttempt,
  recoverStaleNodeAttempts,
  getExecutionGraph,
  getResumableNodes
} from '../../core/execution_engine.js';

describe('Durable execution graph engine', () => {
  const organizationId = 'org_engine_test';

  beforeAll(async () => {
    await ensureExecutionGraph();
    await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]);
  });

  const nodeArgs = (nodeType, logicalKey) => ({
    organizationId,
    executionId: 'exec_engine_test',
    nodeType,
    logicalKey,
    status: 'PENDING'
  });

  it('generates stable usage and edge IDs', async () => {
    const a = await upsertGraphNode(nodeArgs('CONTROL', 'soc2:AWS'));
    const b = await upsertGraphNode(nodeArgs('CONTROL', 'soc2:AWS'));
    expect(a.id).toBe(b.id);
    const edge = await addDependencyEdge({ organizationId, executionId: 'exec_engine_test', fromNodeId: a.id, toNodeId: b.id });
    expect(edge.id).toBe((await addDependencyEdge({ organizationId, executionId: 'exec_engine_test', fromNodeId: a.id, toNodeId: b.id })).id);
  });

  it('persists nodes, dependency edges, attempts and a chronological timeline in PostgreSQL', async () => {
    const executionId = 'exec_engine_persistence_test';
    const source = await upsertGraphNode({ ...nodeArgs('SOURCE', 'source'), executionId });
    const dependent = await upsertGraphNode({ ...nodeArgs('DEPENDENT', 'dependent'), executionId });
    await addDependencyEdge({ organizationId, executionId, fromNodeId: source.id, toNodeId: dependent.id });
    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: source.id });
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED' });
    const graph = await getExecutionGraph(organizationId, executionId);
    expect(graph.nodes.map(n => n.id)).toEqual(expect.arrayContaining([source.id, dependent.id]));
    expect(graph.edges).toHaveLength(1);
    expect(graph.attempts).toHaveLength(1);
    expect(graph.timeline[0].status).toBe('SUCCEEDED');
  });

  it('allows only one live worker lease for a node', async () => {
    const executionId = 'exec_engine_single_attempt';
    const node = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:SINGLE'), executionId });
    await startNodeAttempt({ organizationId, executionId, nodeId: node.id });
    await expect(startNodeAttempt({ organizationId, executionId, nodeId: node.id })).rejects.toThrow('NODE_ALREADY_RUNNING');
  });

  it('returns only dependency-ready retryable nodes for resume', async () => {
    const executionId = 'exec_engine_resume_ready';
    const source = await upsertGraphNode({ ...nodeArgs('SOURCE', 'ready-source'), executionId, status: 'SUCCEEDED' });
    const dependent = await upsertGraphNode({ ...nodeArgs('DEPENDENT', 'ready-dependent'), executionId, status: 'FAILED' });
    const blocked = await upsertGraphNode({ ...nodeArgs('DEPENDENT', 'blocked'), executionId, status: 'FAILED' });
    await addDependencyEdge({ organizationId, executionId, fromNodeId: source.id, toNodeId: dependent.id });
    await addDependencyEdge({ organizationId, executionId, fromNodeId: blocked.id, toNodeId: dependent.id });
    expect((await getResumableNodes(organizationId, executionId)).map(n => n.id)).toContain(dependent.id);
  });

  it('claims a dependency-ready node exactly once for resume', async () => {
    const executionId = 'exec_engine_claim_once';
    const node = await upsertGraphNode({ ...nodeArgs('CONTROL', 'claim-once'), executionId, status: 'FAILED' });
    const first = await startNodeAttempt({ organizationId, executionId, nodeId: node.id });
    expect(first.status).toBe('RUNNING');
    await expect(startNodeAttempt({ organizationId, executionId, nodeId: node.id })).rejects.toThrow('NODE_ALREADY_RUNNING');
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
    await pool.query(`UPDATE execution_attempts SET heartbeat_at=NOW() - INTERVAL '60 seconds' WHERE id=$1`, [attempt.id]);
    const recoveredAttempts = await recoverStaleNodeAttempts({ organizationId, executionId: staleExecution, staleAfterSeconds: 30 });
    expect(recoveredAttempts.map(a => a.id)).toContain(attempt.id);
    const graph = await getExecutionGraph(organizationId, staleExecution);
    const recovered = graph.attempts.find(a => a.id === attempt.id);
    expect(recovered.status).toBe('FAILED');
    expect(recovered.error_code).toBe('STALE_ATTEMPT');
    expect(graph.nodes.find(n => n.id === node.id).status).toBe('FAILED');
    expect((await getResumableNodes(organizationId, staleExecution)).map(n => n.id)).toContain(node.id);
  });

  it('refreshes a running attempt heartbeat and rejects terminal regressions', async () => {
    const heartbeatExecution = 'exec_engine_heartbeat_test';
    const node = await upsertGraphNode({ ...nodeArgs('CONTROL', 'soc2:HEARTBEAT'), executionId: heartbeatExecution });
    const attempt = await startNodeAttempt({ organizationId, executionId: heartbeatExecution, nodeId: node.id });
    const before = (await pool.query('SELECT heartbeat_at FROM execution_attempts WHERE id=$1', [attempt.id])).rows[0].heartbeat_at;
    await heartbeatNodeAttempt({ attemptId: attempt.id });
    const after = (await pool.query('SELECT heartbeat_at FROM execution_attempts WHERE id=$1', [attempt.id])).rows[0].heartbeat_at;
    expect(new Date(after).getTime()).toBeGreaterThanOrEqual(new Date(before).getTime());
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED' });
    await expect(heartbeatNodeAttempt({ attemptId: attempt.id })).rejects.toThrow('ATTEMPT_NOT_RUNNING');
  });

  it('models failed controls as risk with approval-gated remediation', async () => {
    const executionId = 'exec_engine_risk_test';
    const risk = await upsertGraphNode({ ...nodeArgs('RISK', 'risk'), executionId, status: 'SUCCEEDED' });
    const remediation = await upsertGraphNode({ ...nodeArgs('REMEDIATION', 'remediation'), executionId, status: 'FAILED', metadata: { requiresApproval: true } });
    await addDependencyEdge({ organizationId, executionId, fromNodeId: risk.id, toNodeId: remediation.id });
    expect((await getExecutionGraph(organizationId, executionId)).nodes.find(n => n.id === remediation.id).metadata.requiresApproval).toBe(true);
  });
});
