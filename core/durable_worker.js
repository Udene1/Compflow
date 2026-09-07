import { handler as workerHandler } from '../worker.js';
import { beginExecution, finishExecution } from './execution_worker_hooks.js';
import { withExecutionContext } from './execution_context.js';

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
    executionNodeId: execution.node.id,
    executionAttemptId: execution.attempt.id
  }, async () => {
    try {
      const result = await workerHandler(payload);
      const terminalStatus = result?.status === 'completed' || result?.status === 'partial' ? 'SUCCEEDED' : 'FAILED';
      await finishExecution(execution.attempt.id, terminalStatus, terminalStatus === 'SUCCEEDED' ? null : 'EXECUTION_FAILED');
      return result;
    } catch (error) {
      await finishExecution(execution.attempt.id, 'FAILED', 'EXECUTION_FAILED', 'Execution failed');
      throw error;
    }
  });
}
