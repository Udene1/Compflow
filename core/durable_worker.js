import { handler as workerHandler } from '../worker.js';
import { beginExecution, finishExecution } from './execution_worker_hooks.js';
import { withExecutionContext } from './execution_context.js';
import { heartbeatNodeAttempt } from './execution_engine.js';
import { assertExecutionLease } from './execution_fencing.js';
import {
  createExecutionRun,
  acquireExecutionLease,
  heartbeatExecutionLease,
  finishExecutionRun
} from './execution_lifecycle.js';

function workerId() {
  return process.env.COMPFLOW_WORKER_ID || process.env.HOSTNAME || `worker-${process.pid}`;
}

function heartbeatIntervalMs() {
  const seconds = Math.max(5, Math.min(Number(process.env.COMPFLOW_HEARTBEAT_SECONDS) || 20, 120));
  return seconds * 1000;
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
  let execution;
  try {
    execution = await beginExecution({
      organizationId,
      executionId,
      provider,
      clientId,
      jobId: data?.jobId || null,
      connectionId: data?.connectionId || null,
      scanId: data?.scanId || null
    });
  } catch (error) {
    await finishExecutionRun({
      organizationId,
      executionId,
      workerId: owner,
      leaseToken: lease.lease_token,
      status: 'FAILED',
      errorCode: 'EXECUTION_BEGIN_FAILED',
      errorMessage: 'Execution initialization failed'
    }).catch(() => {});
    throw error;
  }

  return withExecutionContext({
    organizationId,
    executionId,
    provider,
    resumeNodeIds,
    executionNodeId: execution.node.id,
    executionAttemptId: execution.attempt.id
  }, async () => {
    let heartbeatTimer;
    let heartbeatFailure = null;
    let heartbeatInFlight = false;

    const heartbeat = async () => {
      if (heartbeatInFlight || heartbeatFailure) return;
      heartbeatInFlight = true;
      try {
        await heartbeatExecutionLease({ organizationId, executionId, workerId: owner, leaseToken: lease.lease_token });
        await heartbeatNodeAttempt({ attemptId: execution.attempt.id });
      } catch (error) {
        heartbeatFailure = error;
        console.error('[EXECUTION-HEARTBEAT] Lease heartbeat failed:', error?.message || error);
      } finally {
        heartbeatInFlight = false;
      }
    };

    heartbeatTimer = setInterval(() => { void heartbeat(); }, heartbeatIntervalMs());
    heartbeatTimer.unref?.();

    try {
      const result = await workerHandler(payload);

      // Fence the terminal commit: a worker that lost its lease cannot publish a
      // successful execution merely because its provider work returned normally.
      await heartbeat();
      if (heartbeatFailure) throw heartbeatFailure;
      await assertExecutionLease({ organizationId, executionId, workerId: owner, leaseToken: lease.lease_token });

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
      await finishExecution(execution.attempt.id, 'FAILED', heartbeatFailure ? 'EXECUTION_LEASE_LOST' : 'EXECUTION_FAILED', heartbeatFailure ? 'Execution worker lease lost' : 'Execution failed').catch(() => {});
      await finishExecutionRun({
        organizationId,
        executionId,
        workerId: owner,
        leaseToken: lease.lease_token,
        status: 'FAILED',
        errorCode: heartbeatFailure ? 'EXECUTION_LEASE_LOST' : 'EXECUTION_FAILED',
        errorMessage: heartbeatFailure ? 'Execution worker lease lost' : 'Execution failed'
      }).catch(() => {});
      throw error;
    } finally {
      clearInterval(heartbeatTimer);
    }
  });
}
