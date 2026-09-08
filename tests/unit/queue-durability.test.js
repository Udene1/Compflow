import { describe, expect, it, afterAll } from 'vitest';
import { enqueueJob, closeQueue } from '../../core/queue.js';

describe('Durable BullMQ queue identity', () => {
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const base = {
    scanId: `scan-${suffix}`,
    executionId: `exec-${suffix}`,
    connectionId: `conn-${suffix}`,
    provider: 'aws',
    scanType: 'manual',
    enqueuedAt: new Date().toISOString()
  };

  afterAll(async () => {
    await closeQueue();
  });

  it('deduplicates the same job identity within one organization', async () => {
    const jobId = `job-${suffix}`;
    const first = await enqueueJob({ ...base, jobId, organizationId: 'org-queue-a' });
    const second = await enqueueJob({ ...base, jobId, organizationId: 'org-queue-a' });

    expect(first.id).toBe(second.id);
  });

  it('keeps identical producer job IDs isolated across organizations', async () => {
    const jobId = `shared-job-${suffix}`;
    const first = await enqueueJob({ ...base, jobId, organizationId: 'org-queue-a' });
    const second = await enqueueJob({ ...base, jobId, organizationId: 'org-queue-b' });

    expect(first.id).not.toBe(second.id);
  });
});
