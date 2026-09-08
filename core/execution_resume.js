import {
  getExecutionGraph,
  getResumableNodes,
  claimResumableNode
} from './execution_engine.js';
import {
  getExecutionRun,
  acquireExecutionLease,
  heartbeatExecutionLease,
  finishExecutionRun
} from './execution_lifecycle.js';

const TERMINAL_SUCCESS = new Set(['SUCCEEDED', 'SKIPPED']);
const RETRYABLE = new Set(['PENDING', 'FAILED', 'CANCELLED']);

function approvalBlocked(node, graph) {
  if (node.metadata?.requiresApproval !== true) return false;
  const approval = graph.nodes.find(candidate =>
    candidate.node_type === 'APPROVAL' &&
    (candidate.metadata?.forNodeId === node.id || candidate.metadata?.nodeId === node.id)
  );
  return !approval || !TERMINAL_SUCCESS.has(approval.status);
}

function dependenciesReady(node, graph) {
  return graph.edges
    .filter(edge => edge.to_node_id === node.id && edge.edge_type === 'DEPENDS_ON')
    .every(edge => {
      const dependency = graph.nodes.find(candidate => candidate.id === edge.from_node_id);
      return dependency && TERMINAL_SUCCESS.has(dependency.status);
    });
}

export async function getDependencyAwareResumePlan(organizationId, executionId) {
  const run = await getExecutionRun(organizationId, executionId);
  if (!run) throw new Error('EXECUTION_NOT_FOUND');
  if (run.status === 'SUCCEEDED' || run.status === 'CANCELLED') throw new Error('EXECUTION_NOT_RESUMABLE');

  const graph = await getExecutionGraph(organizationId, executionId);
  const candidates = graph.nodes.filter(node => RETRYABLE.has(node.status));
  const nodes = candidates.filter(node => dependenciesReady(node, graph) && !approvalBlocked(node, graph));
  return {
    execution: run,
    executionId,
    organizationId,
    nodes,
    resumableNodeIds: nodes.map(node => node.id),
    blockedNodeIds: candidates.filter(node => !nodes.includes(node)).map(node => node.id)
  };
}

export async function claimDependencyAwareResume({ organizationId, executionId, nodeId, workerId, metadata = {} } = {}) {
  if (!organizationId || !executionId || !nodeId || !workerId) throw new Error('RESUME_INPUT_INVALID');
  const plan = await getDependencyAwareResumePlan(organizationId, executionId);
  if (!plan.resumableNodeIds.includes(nodeId)) throw new Error('NODE_NOT_RESUMABLE');

  const lease = await acquireExecutionLease({ organizationId, executionId, workerId });
  try {
    const attempt = await claimResumableNode({ organizationId, executionId, nodeId, metadata: { ...metadata, executionLeaseVersion: lease.version } });
    return { attempt, lease };
  } catch (error) {
    await finishExecutionRun({
      organizationId,
      executionId,
      workerId,
      leaseToken: lease.lease_token,
      status: 'FAILED',
      errorCode: 'RESUME_CLAIM_FAILED',
      errorMessage: 'Resume claim failed'
    }).catch(() => {});
    throw error;
  }
}

export async function heartbeatResumedExecution({ organizationId, executionId, workerId, leaseToken, leaseSeconds = 60 }) {
  return heartbeatExecutionLease({ organizationId, executionId, workerId, leaseToken, leaseSeconds });
}
