import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import pool from '../../core/db.js';
import { getProvider, listProviders, normalizeProvider } from '../../core/provider_registry.js';
import { ensureDecisionSchema, recordControlDecision, finalizeExecutionDecision } from '../../core/compliance_decision.js';
import { ensureExecutionGraph, upsertGraphNode, startNodeAttempt, finishNodeAttempt } from '../../core/execution_engine.js';

const organizationId = 'org_boundary_test';
const executionId = 'exec_boundary_test';

async function clean() {
  await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_attempts WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_graph_edges WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
}

beforeAll(async () => { await ensureDecisionSchema(); await ensureExecutionGraph(); await clean(); });
afterAll(clean);

describe('compliance product boundary', () => {
  it('centralizes provider capabilities without aliases leaking into execution', () => {
    expect(normalizeProvider('DO')).toBe('digitalocean');
    expect(listProviders()).toEqual(expect.arrayContaining(['aws','azure','gcp','digitalocean','hetzner']));
    expect(getProvider('aws').id).toBe('aws');
    expect(() => getProvider('unknown')).toThrow('Unsupported cloud provider');
  });

  it('records decision history and treats the final decision as an immutable artifact', async () => {
    await clean();
    const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'CONTROL_EVALUATION', logicalKey: 'CC6.1:evaluate:boundary', status: 'PENDING', metadata: { controlId: 'CC6.1' } });
    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id, metadata: { result: { assessment: 'PASS', evidenceHash: 'e'.repeat(64) } } });
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED', metadata: { result: { assessment: 'PASS', evidenceHash: 'e'.repeat(64) } } });
    await recordControlDecision({ organizationId, executionId, controlId: 'CC6.1', scopeKey: node.logical_key, outcome: 'PASS', evidenceHash: 'e'.repeat(64), verificationHash: null, rationale: { verified: false } });
    const first = await finalizeExecutionDecision({ organizationId, executionId });
    expect(first.outcome).toBe('PASS');
    expect(first.decision_hash).toMatch(/^[a-f0-9]{64}$/);
    const second = await finalizeExecutionDecision({ organizationId, executionId });
    expect(second.decision_hash).toBe(first.decision_hash);
    const history = await pool.query('SELECT * FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2 AND decision_id=(SELECT id FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2 AND scope_key=$3)', [organizationId, executionId, node.logical_key]);
    expect(history.rows).toHaveLength(1);
    await pool.query("UPDATE execution_final_decisions SET decision_hash=$1 WHERE organization_id=$2 AND execution_id=$3", ['f'.repeat(64), organizationId, executionId]);
    const replay = await finalizeExecutionDecision({ organizationId, executionId });
    expect(replay.decision_hash).toBe('f'.repeat(64));
    expect(replay.id).toBe(first.id);
  });
});
