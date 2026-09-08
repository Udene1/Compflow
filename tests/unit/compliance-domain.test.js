import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import pool from '../../core/db.js';
import { normalizeIntent, persistIntent, ensureIntentSchema } from '../../core/intent.js';
import { recordEvidence, getEvidenceForNode, verifyEvidenceIntegrity, getEvidenceFreshness, ensureEvidenceSchema } from '../../core/evidence.js';
import { recordVerification, ensureVerificationSchema } from '../../core/compliance_verification.js';
import { recordControlDecision, finalizeExecutionDecision, ensureDecisionSchema } from '../../core/compliance_decision.js';

const organizationId = 'org_compliance_domain_test';
const executionId = 'exec_compliance_domain_test';
const intent = {
  id: 'intent_domain_test', version: '1', objective: 'Evaluate cloud compliance and remediate approved failures', mode: 'REMEDIATE', frameworks: ['soc2'],
  rules: [{ id: 'rule-domain-1', controlId: 'CC6.1', action: 'REMEDIATE', requiresApproval: true }],
  targets: [{ connectionId: 'conn_domain_test', provider: 'aws', resourceId: 'resource-1' }]
};

describe('durable compliance domain', () => {
  beforeAll(async () => {
    await ensureIntentSchema(); await ensureEvidenceSchema(); await ensureVerificationSchema(); await ensureDecisionSchema();
    await pool.query('DELETE FROM compliance_intents WHERE organization_id=$1 AND intent_id IN ($2,$3)', [organizationId, intent.id, 'intent_domain_race']);
    await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  });
  afterAll(async () => {
    await pool.query('DELETE FROM compliance_intents WHERE organization_id=$1 AND intent_id IN ($2,$3)', [organizationId, intent.id, 'intent_domain_race']);
    await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  });

  it('normalizes and immutably persists intent', async () => {
    const normalized = normalizeIntent({ organizationId, intent, targets: intent.targets });
    expect(normalized.intentHash).toMatch(/^[a-f0-9]{64}$/);
    const stored = await persistIntent({ organizationId, intent: normalized });
    expect(stored.intent_hash).toBe(normalized.intentHash);
    await expect(persistIntent({ organizationId, intent: { ...normalized, objective: 'changed' } })).rejects.toThrow('INTENT_IMMUTABLE');
  });

  it('collapses concurrent persistence of the same immutable intent', async () => {
    const raceIntent = normalizeIntent({ organizationId, intent: { ...intent, id: 'intent_domain_race' }, targets: intent.targets });
    const [first, second] = await Promise.all([
      persistIntent({ organizationId, intent: raceIntent }),
      persistIntent({ organizationId, intent: raceIntent })
    ]);
    expect(first.id).toBe(second.id);
    const rows = await pool.query('SELECT * FROM compliance_intents WHERE organization_id=$1 AND intent_id=$2 AND intent_version=$3', [organizationId, raceIntent.id, raceIntent.version]);
    expect(rows.rows).toHaveLength(1);
  });

  it('stores immutable evidence with provenance, lineage and freshness', async () => {
    const expires = new Date(Date.now() + 60_000).toISOString();
    const row = await recordEvidence({ organizationId, executionId, nodeId: 'node_evidence_domain', attemptId: 'attempt_evidence_domain', controlId: 'CC6.1', provider: 'aws', connectionId: 'conn_domain_test', resourceId: 'resource-1', sourceType: 'aws_config', sourceRef: 'scan:resource-1', evidenceKind: 'observation', observedAt: new Date().toISOString(), freshnessExpiresAt: expires, lineage: [{ type: 'scan', id: 'scan-domain-1' }, { type: 'resource', id: 'resource-1' }], evidence: { resources: [{ id: 'resource-1', status: 'pass' }] } });
    expect(verifyEvidenceIntegrity(row)).toBe(true);
    expect(row.evidence_kind).toBe('observation');
    expect(row.lineage).toHaveLength(2);
    expect(getEvidenceFreshness(row).state).toBe('FRESH');
    const fetched = await getEvidenceForNode({ organizationId, executionId, nodeId: 'node_evidence_domain', attemptId: 'attempt_evidence_domain' });
    expect(fetched.evidence_hash).toBe(row.evidence_hash);
  });

  it('requires evidence for positive verification and final decision', async () => {
    const verificationEvidence = await recordEvidence({ organizationId, executionId, nodeId: 'node_verify_domain', attemptId: 'attempt_verify_domain', controlId: 'CC6.1', provider: 'aws', connectionId: 'conn_domain_test', resourceId: 'resource-1', sourceType: 'aws_config', sourceRef: 'scan:resource-1:verify', evidenceKind: 'verification', evidence: { resources: [{ id: 'resource-1', status: 'verified' }] } });
    const verification = await recordVerification({ organizationId, executionId, nodeId: 'node_verify_domain', attemptId: 'attempt_verify_domain', controlId: 'CC6.1', outcome: 'PASS', evidence: verificationEvidence, details: { verifiedResources: 1 } });
    await recordControlDecision({ organizationId, executionId, controlId: 'CC6.1', scopeKey: 'scope-domain-1', outcome: 'PASS', evidenceHash: verificationEvidence.evidence_hash, verificationHash: verification.verification_hash, rationale: { verified: true } });
    const finalDecision = await finalizeExecutionDecision({ organizationId, executionId });
    expect(finalDecision.outcome).toBe('PASS');
    expect(finalDecision.decision_hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('downgrades stale evidence to insufficient evidence', async () => {
    const staleEvidence = await recordEvidence({ organizationId, executionId: 'exec_compliance_stale_evidence', nodeId: 'node_stale_evidence', attemptId: 'attempt_stale_evidence', controlId: 'CC6.1', provider: 'aws', connectionId: 'conn_domain_test', evidence: { resources: [{ id: 'resource-stale', status: 'pass' }] }, freshnessExpiresAt: new Date(Date.now() - 1000).toISOString() });
    expect(getEvidenceFreshness(staleEvidence).state).toBe('STALE');
    const result = await pool.query(`SELECT * FROM execution_graph_nodes WHERE 1=0`);
    expect(result.rows).toHaveLength(0);
  });
});
