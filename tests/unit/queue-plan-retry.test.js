import { afterAll, describe, expect, it } from 'vitest';
import { enqueueJob, closeQueue } from '../../core/queue.js';

const organizationId = 'org_queue_plan_retry_test';
const jobId = 'plan-retry-policy-exec-node-attempt';
const bullJobId = `org-${organizationId}-job-${jobId}`;

describe('BullMQ persisted execution-node delivery', () => {
  it('does not independently retry an execution-node attempt after the durable attempt has failed', async () => {
    const job = await enqueueJob({
      jobId,
      executionId: 'exec_queue_plan_retry_test',
      organizationId,
      connectionId: 'execution',
      provider: 'azure',
      scanId: 'exec_queue_plan_retry_test',
      scanType: 'execution_node',
      executionNodeType: 'CONTROL_EVALUATION',
      executionNodeId: 'node_queue_plan_retry_test',
      executionAttemptId: 'attempt_queue_plan_retry_test',
      planHash: 'a'.repeat(64),
      enqueuedAt: new Date().toISOString()
    });

    expect(job.opts.attempts).toBe(1);
    expect(job.name).toBe('execution_node');
    expect(job.id).toBe(bullJobId);
  });
});

afterAll(async () => {
  const { Queue } = await import('bullmq');
  const { default: Redis } = await import('ioredis');
  const connection = new Redis({ host: process.env.REDIS_HOST || 'localhost', port: Number(process.env.REDIS_PORT || 6379), maxRetriesPerRequest: null });
  const queue = new Queue('scan_jobs', { connection });
  await queue.remove(bullJobId).catch(() => {});
  await queue.close().catch(() => {});
  await connection.quit().catch(() => {});
  await closeQueue().catch(() => {});
});
