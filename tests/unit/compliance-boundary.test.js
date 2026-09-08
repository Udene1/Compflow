import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import pool from '../../core/db.js';
import { getProvider, listProviders, normalizeProvider } from '../../core/provider_registry.js';
import { ensureDecisionSchema, recordControlDecision, finalizeExecutionDecision } from '../../core/compliance_decision.js';
import { ensureExecutionGraph, upsertGraphNode } from '../../core/execution_engine.js';

const organizationId = 'org_boundary_test';
const executionId = 'exec_boundary_test';

beforeAll(async () => {
  await ensureDecisionSchema();
  await ensureExecutionGraph();
  await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_graph_edges WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
});

afterAll(async () => {
  await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_graph_edges WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
});

describe('compliance product boundary', () => {
  it('centralizes provider capabilities without aliases leaking into execution', () => {
    expect(normalizeProvider('DO')).toBe('digitalocean');
    expect(listProviders()).toEqual(expect.arrayContaining(['aws','azure','gcp','digitalocean','hetzner']));
    expect(getProvider('aws').id).toBe('aws');
    expect(() => getProvider('unknown')).toThrow('Unsupported cloud provider');
  });

  it('records decision history while keeping the final decision immutable', async () => {
    await upsertGraphNode({ organizationId, executionId, nodeType: 'CONTROL_EVALUATION', logicalKey: 'CC6.1:evaluate:boundary', status: 'SUCCEEDED', metadata: { controlId: 'CC6.1' } });
    await recordControlDecision({ organizationId, executionId, controlId: 'CC6.1', scopeKey: 'boundary', outcome: 'PASS', evidenceHash: 'e'.repeat(64), verificationHash: 'v'.repeat(64), rationale: { verified: true } });
    const first = await finalizeExecutionDecision({ organizationId, executionId });
    expect(first.outcome).toBe('PASS');
    expect(first.decision_hash).toMatch(/^[a-f0-9]{64}$/);
    const second = await finalizeExecutionDecision({ organizationId, executionId });
    expect(second.decision_hash).toBe(first.decision_hash);
    const history = await pool.query('SELECT * FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    expect(history.rows).toHaveLength(1);
    await pool.query("UPDATE compliance_decisions SET outcome='FAIL' WHERE organization_id=$1 AND execution_id=$2 AND scope_key='boundary'", [organizationId, executionId]);
    await expect(finalizeExecutionDecision({ organizationId, executionId })).rejects.toThrow('FINAL_DECISION_IMMUTABLE');
  });
});
