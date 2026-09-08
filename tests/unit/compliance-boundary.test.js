import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import pool from '../../core/db.js';
import { getProvider, listProviders, normalizeProvider } from '../../core/provider_registry.js';
import { ensureDecisionSchema, recordControlDecision, finalizeExecutionDecision } from '../../core/compliance_decision.js';
import { recordEvidence, ensureEvidenceSchema } from '../../core/evidence.js';
import { ensureExecutionGraph, upsertGraphNode, startNodeAttempt, finishNodeAttempt } from '../../core/execution_engine.js';

const organizationId = 'org_boundary_test';
const executionId = 'exec_boundary_test';

async function clean() {
  await ensureDecisionSchema(); await ensureEvidenceSchema(); await ensureExecutionGraph();
  await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_attempts WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_graph_edges WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
}

beforeAll(clean);
afterAll(clean);

describe('compliance product boundary', () => {
  it('centralizes provider capabilities without aliases leaking into execution', () => {
    expect(normalizeProvider('DO')).toBe('digitalocean');
    expect(listProviders()).toEqual(expect.arrayContaining(['aws','azure','gcp','digitalocean','hetzner']));
    expect(getProvider('aws').id).toBe('aws');
    expect(() => getProvider('unknown')).toThrow('Unsupported cloud provider');
  });

  it('records decision history idempotently while keeping the final decision immutable', async () => {
    await clean();
    await expect(recordControlDecision({ organizationId, executionId, controlId: 'CC6.1', scopeKey: 'CC6.1:evaluate:missing-evidence', outcome: 'PASS', evidenceHash: 'e'.repeat(64) })).rejects.toThrow('DECISION_EVIDENCE_INVALID');
    const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'CONTROL_EVALUATION', logicalKey: 'CC6.1:evaluate:boundary', status: 'PENDING', metadata: { controlId: 'CC6.1' } });
    const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id, metadata: { result: { assessment: 'PASS' } } });
    const evidence = await recordEvidence({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, controlId: 'CC6.1', provider: 'aws', connectionId: 'conn_boundary_test', resourceId: 'resource-boundary', sourceType: 'aws_config', sourceRef: 'scan:resource-boundary', evidenceKind: 'observation', evidence: { resource: { id: 'resource-boundary', assessment: 'PASS' } } });
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED', metadata: { result: { assessment: 'PASS', evidenceHash: evidence.evidence_hash } } });
    const firstRecorded = await recordControlDecision({ organizationId, executionId, controlId: 'CC6.1', scopeKey: node.logical_key, outcome: 'PASS', evidenceHash: evidence.evidence_hash, verificationHash: null, rationale: { verified: false } });
    const repeated = await recordControlDecision({ organizationId, executionId, controlId: 'CC6.1', scopeKey: node.logical_key, outcome: 'PASS', evidenceHash: evidence.evidence_hash, verificationHash: null, rationale: { verified: true } });
    expect(repeated.id).toBe(firstRecorded.id);
    const historyAfterRecord = await pool.query('SELECT * FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2 AND decision_id=$3', [organizationId, executionId, firstRecorded.id]);
    expect(historyAfterRecord.rows).toHaveLength(1);
    const first = await finalizeExecutionDecision({ organizationId, executionId });
    expect(first.outcome).toBe('PASS');
    expect(first.decision_hash).toMatch(/^[a-f0-9]{64}$/);
    const second = await finalizeExecutionDecision({ organizationId, executionId });
    expect(second.decision_hash).toBe(first.decision_hash);
    const history = await pool.query('SELECT * FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2 AND decision_id=$3', [organizationId, executionId, firstRecorded.id]);
    expect(history.rows).toHaveLength(1);
    await pool.query("UPDATE execution_final_decisions SET decision_hash=$1 WHERE organization_id=$2 AND execution_id=$3", ['f'.repeat(64), organizationId, executionId]);
    await expect(finalizeExecutionDecision({ organizationId, executionId })).rejects.toThrow('FINAL_DECISION_IMMUTABLE');
  });
});
