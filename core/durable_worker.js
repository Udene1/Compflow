import { processCloudScanJob } from './cloud_scan_worker.js';
import { beginExecution } from './execution_worker_hooks.js';
import { withExecutionContext } from './execution_context.js';
import { heartbeatNodeAttempt } from './execution_engine.js';
import { finishExecutionFenced } from './execution_terminal.js';
import { createExecutionRun, acquireExecutionLease, heartbeatExecutionLease, finishExecutionRun } from './execution_lifecycle.js';

function workerId() { return process.env.COMPFLOW_WORKER_ID || process.env.HOSTNAME || `worker-${process.pid}`; }
function heartbeatIntervalMs() { const seconds = Math.max(5, Math.min(Number(process.env.COMPFLOW_HEARTBEAT_SECONDS) || 20, 120)); return seconds * 1000; }

export async function durableWorkerHandler(payload) {
  const data = payload?.Records?.[0]?.body
    ? (typeof payload.Records[0].body === 'string' ? JSON.parse(payload.Records[0].body) : payload.Records[0].body)
    : payload;

  if (data?.executionNodeType) {
    const { executePersistedPlanNode } = await import('./plan_executor.js');
    return executePersistedPlanNode(data);
  }

  const jobId = data?.jobId || `exec-${Date.now()}`;
  const executionId = data?.executionId || jobId;
  const organizationId = data?.organizationId || data?.orgId || 'org_default';
  const provider = data?.provider || 'aws';
  const clientId = data?.clientId || data?.id || 'adhoc_user';
  const connectionId = data?.connectionId || null;
  const resumeNodeIds = Array.isArray(data?.resumeNodeIds) ? [...new Set(data.resumeNodeIds)].filter(id => typeof id === 'string' && id.length <= 128).slice(0, 100) : [];
  const owner = workerId();

  await createExecutionRun({ organizationId, executionId, metadata: { provider, clientId, jobId: data?.jobId || null, connectionId, scanId: data?.scanId || null } });
  const lease = await acquireExecutionLease({ organizationId, executionId, workerId: owner });
  let execution;
  try {
    execution = await beginExecution({ organizationId, executionId, provider, clientId, jobId: data?.jobId || null, connectionId, scanId: data?.scanId || null });
  } catch (error) {
    await finishExecutionRun({ organizationId, executionId, workerId: owner, leaseToken: lease.lease_token, status: 'FAILED', errorCode: 'EXECUTION_BEGIN_FAILED', errorMessage: 'Execution initialization failed' }).catch(() => {});
    throw error;
  }

  return withExecutionContext({ organizationId, executionId, provider, connectionId, scanId: data?.scanId || null, resumeNodeIds, executionNodeId: execution.node.id, executionAttemptId: execution.attempt.id }, async () => {
    let heartbeatTimer; let heartbeatFailure = null; let heartbeatInFlight = false; let leaseLost = false;
    const heartbeat = async () => {
      if (heartbeatInFlight || heartbeatFailure || leaseLost) return;
      heartbeatInFlight = true;
      try {
        await heartbeatExecutionLease({ organizationId, executionId, workerId: owner, leaseToken: lease.lease_token });
        await heartbeatNodeAttempt({ attemptId: execution.attempt.id });
      } catch (error) {
        heartbeatFailure = error;
        leaseLost = true;
        console.error('[EXECUTION-HEARTBEAT] Lease heartbeat failed:', error?.message || error);
      } finally { heartbeatInFlight = false; }
    };
    heartbeatTimer = setInterval(() => { void heartbeat(); }, heartbeatIntervalMs()); heartbeatTimer.unref?.();
    try {
      const result = await processCloudScanJob(data);
      await heartbeat();
      if (heartbeatFailure || leaseLost) throw heartbeatFailure || new Error('EXECUTION_LEASE_LOST');
      const terminalStatus = result?.status === 'completed' || result?.status === 'partial' ? 'SUCCEEDED' : 'FAILED';
      await finishExecutionFenced({ organizationId, executionId, attemptId: execution.attempt.id, workerId: owner, leaseToken: lease.lease_token, status: terminalStatus, errorCode: terminalStatus === 'SUCCEEDED' ? null : 'EXECUTION_FAILED' });
      return result;
    } catch (error) {
      if (!leaseLost && !heartbeatFailure) await finishExecutionFenced({ organizationId, executionId, attemptId: execution.attempt.id, workerId: owner, leaseToken: lease.lease_token, status: 'FAILED', errorCode: 'EXECUTION_FAILED', errorMessage: 'Execution failed' }).catch(() => {});
      throw error;
    } finally { clearInterval(heartbeatTimer); }
  });
}
