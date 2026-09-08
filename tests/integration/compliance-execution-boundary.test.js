import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pool from '../../core/db.js';
import { startComplianceExecution } from '../../core/compliance_pipeline.js';
import { getExecutionGraph } from '../../core/execution_engine.js';
import { getExecutionPlan } from '../../core/execution_plans.js';
import { getExecutionRun } from '../../core/execution_lifecycle.js';
import { getQueue, listenWorkerQueue } from '../../core/queue.js';

const organizationId = 'org_real_compliance_integration';
const executionId = 'exec_real_compliance_integration';
const workerExecutionId = 'exec_real_worker_failure';

async function cleanExecution(id) {
  await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM execution_attempts WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM execution_graph_edges WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM execution_plans WHERE organization_id=$1 AND execution_id=$2', [organizationId, id]).catch(() => {});
  await pool.query('DELETE FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, id]).catch(() => {});
}

beforeAll(async () => { await cleanExecution(executionId); await cleanExecution(workerExecutionId); });
afterAll(async () => { await cleanExecution(executionId); await cleanExecution(workerExecutionId); });

describe('real compliance execution boundary', () => {
  it('persists intent-derived plan, graph, execution lease state and real BullMQ dispatch', async () => {
    const result = await startComplianceExecution({ organizationId, executionId, intent: { id: 'intent_real_integration', version: '1', objective: 'Evaluate a real provider connection', mode: 'AUDIT', frameworks: ['soc2'], rules: [{ id: 'rule-real-1', controlId: 'CC6.1', action: 'EVALUATE' }], targets: [{ connectionId: 'missing-real-connection', provider: 'aws', resourceId: 'resource-real-1' }] } });
    expect(result.intent.intent_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(result.plan.planHash).toMatch(/^[a-f0-9]{64}$/);
    const storedPlan = await getExecutionPlan({ organizationId, executionId });
    expect(storedPlan.plan_hash).toBe(result.plan.planHash);
    const graph = await getExecutionGraph(organizationId, executionId);
    expect(graph.nodes.some(node => node.node_type === 'PLAN')).toBe(true);
    expect(graph.nodes.some(node => node.node_type === 'EVIDENCE_COLLECTION')).toBe(true);
    expect(graph.nodes.some(node => node.node_type === 'CONTROL_EVALUATION')).toBe(true);
    const run = await getExecutionRun(organizationId, executionId);
    expect(run.status).toBe('RUNNING');
    const queue = await getQueue();
    const jobs = await queue.getJobs(['waiting','delayed','active'], 0, 50);
    expect(jobs.some(job => job.data.executionId === executionId && job.data.scanType === 'execution_node')).toBe(true);
  });

  it('runs a real worker against PostgreSQL and Redis and durably records provider failure', async () => {
    const worker = await listenWorkerQueue();
    try {
      await startComplianceExecution({ organizationId, executionId: workerExecutionId, intent: { id: 'intent_real_worker_failure', version: '1', objective: 'Exercise the real worker failure boundary', mode: 'AUDIT', frameworks: ['soc2'], rules: [{ id: 'rule-worker-1', controlId: 'CC6.1', action: 'EVALUATE' }], targets: [{ connectionId: 'missing-worker-credentials', provider: 'aws', resourceId: 'resource-worker-1' }] } });
      const deadline = Date.now() + 10_000; let graph;
      while (Date.now() < deadline) { graph = await getExecutionGraph(organizationId, workerExecutionId); const evidenceNode = graph.nodes.find(node => node.node_type === 'EVIDENCE_COLLECTION'); if (evidenceNode?.status === 'FAILED') break; await new Promise(resolve => setTimeout(resolve, 100)); }
      const failed = graph?.nodes.find(node => node.node_type === 'EVIDENCE_COLLECTION');
      expect(failed?.status).toBe('FAILED');
      const failedAttempt = graph.attempts.find(attempt => attempt.node_id === failed.id);
      expect(failedAttempt?.status).toBe('FAILED');
      expect(failedAttempt?.error_code).toBe('EXECUTION_NODE_FAILED');
      expect(failedAttempt?.error_message).not.toMatch(/AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC )?PRIVATE KEY-----|password\s*[:=]|token\s*[:=]|secret\s*[:=]/i);
      const run = await getExecutionRun(organizationId, workerExecutionId);
      expect(['RUNNING', 'FAILED']).toContain(run.status);
    } finally { await worker.close(); }
  });
});
