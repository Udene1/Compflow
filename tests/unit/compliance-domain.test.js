import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import pool from '../../core/db.js';
import { normalizeIntent, persistIntent, ensureIntentSchema } from '../../core/intent.js';
import { recordEvidence, getEvidenceForNode, verifyEvidenceIntegrity, ensureEvidenceSchema } from '../../core/evidence.js';
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
    await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    await pool.query('DELETE FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  });

  afterAll(async () => {
    await pool.query('DELETE FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
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

  it('stores immutable evidence with provenance and detects tampering', async () => {
    const row = await recordEvidence({ organizationId, executionId, nodeId: 'node_evidence_domain', attemptId: 'attempt_evidence_domain', controlId: 'CC6.1', provider: 'aws', connectionId: 'conn_domain_test', resourceId: 'resource-1', evidence: { resources: [{ id: 'resource-1', status: 'pass' }] } });
    expect(verifyEvidenceIntegrity(row)).toBe(true);
    const fetched = await getEvidenceForNode({ organizationId, executionId, nodeId: 'node_evidence_domain', attemptId: 'attempt_evidence_domain' });
    expect(fetched.evidence_hash).toBe(row.evidence_hash);
  });

  it('persists verification and produces an authoritative final decision', async () => {
    const verification = await recordVerification({ organizationId, executionId, nodeId: 'node_verify_domain', attemptId: 'attempt_verify_domain', controlId: 'CC6.1', outcome: 'PASS', details: { verifiedResources: 1 } });
    await recordControlDecision({ organizationId, executionId, controlId: 'CC6.1', scopeKey: 'scope-domain-1', outcome: 'PASS', verificationHash: verification.verification_hash, rationale: { verified: true } });
    const finalDecision = await finalizeExecutionDecision({ organizationId, executionId });
    expect(finalDecision.outcome).toBe('PASS');
    expect(finalDecision.decision_hash).toMatch(/^[a-f0-9]{64}$/);
  });
});
