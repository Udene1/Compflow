import { handler as workerHandler } from '../worker.js';
import { beginExecution, finishExecution } from './execution_worker_hooks.js';
import { withExecutionContext } from './execution_context.js';
import {
  createExecutionRun,
  acquireExecutionLease,
  heartbeatExecutionLease,
  finishExecutionRun
} from './execution_lifecycle.js';

function workerId() {
  return process.env.COMPFLOW_WORKER_ID || process.env.HOSTNAME || `worker-${process.pid}`;
}

export async function durableWorkerHandler(payload) {
  let data = payload;
  if (payload?.Records?.[0]?.body) {
    data = typeof payload.Records[0].body === 'string' ? JSON.parse(payload.Records[0].body) : payload.Records[0].body;
  }

  const jobId = data?.jobId || `exec-${Date.now()}`;
  const executionId = data?.executionId || jobId;
  const organizationId = data?.organizationId || data?.orgId || 'org_default';
  const provider = data?.provider || 'aws';
  const clientId = data?.clientId || data?.id || 'adhoc_user';
  const resumeNodeIds = Array.isArray(data?.resumeNodeIds) ? [...new Set(data.resumeNodeIds)].slice(0, 100) : [];
  const owner = workerId();

  await createExecutionRun({
    organizationId,
    executionId,
    metadata: { provider, clientId, jobId: data?.jobId || null, connectionId: data?.connectionId || null, scanId: data?.scanId || null }
  });
  const lease = await acquireExecutionLease({ organizationId, executionId, workerId: owner });
  const execution = await beginExecution({
    organizationId,
    executionId,
    provider,
    clientId,
    jobId: data?.jobId || null,
    connectionId: data?.connectionId || null,
    scanId: data?.scanId || null
  });

  return withExecutionContext({
    organizationId,
    executionId,
    provider,
    resumeNodeIds,
    executionNodeId: execution.node.id,
    executionAttemptId: execution.attempt.id
  }, async () => {
    try {
      const result = await workerHandler(payload);
      await heartbeatExecutionLease({ organizationId, executionId, workerId: owner, leaseToken: lease.lease_token });
      const terminalStatus = result?.status === 'completed' || result?.status === 'partial' ? 'SUCCEEDED' : 'FAILED';
      await finishExecution(execution.attempt.id, terminalStatus, terminalStatus === 'SUCCEEDED' ? null : 'EXECUTION_FAILED');
      await finishExecutionRun({
        organizationId,
        executionId,
        workerId: owner,
        leaseToken: lease.lease_token,
        status: terminalStatus,
        errorCode: terminalStatus === 'SUCCEEDED' ? null : 'EXECUTION_FAILED'
      });
      return result;
    } catch (error) {
      await finishExecution(execution.attempt.id, 'FAILED', 'EXECUTION_FAILED', 'Execution failed').catch(() => {});
      await finishExecutionRun({
        organizationId,
        executionId,
        workerId: owner,
        leaseToken: lease.lease_token,
        status: 'FAILED',
        errorCode: 'EXECUTION_FAILED',
        errorMessage: 'Execution failed'
      }).catch(() => {});
      throw error;
    }
  });
}
