import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import pool from '../../core/db.js';
import { ensureEvidenceSchema, recordEvidence } from '../../core/evidence.js';
import { ensureVerificationSchema, recordVerification } from '../../core/compliance_verification.js';
import { ensureDecisionSchema, recordControlDecision } from '../../core/compliance_decision.js';
import { getComplianceTrace } from '../../core/compliance_trace.js';

const organizationId = 'org_compliance_trace_test';
const executionId = 'exec_compliance_trace_test';

beforeAll(async () => {
  await ensureEvidenceSchema();
  await ensureVerificationSchema();
  await ensureDecisionSchema();
  await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
});

afterAll(async () => {
  await pool.query('DELETE FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  await pool.query('DELETE FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
});

describe('authoritative compliance trace', () => {
  it('joins durable evidence, verification and decision records by immutable hashes', async () => {
    const evidence = await recordEvidence({
      organizationId,
      executionId,
      nodeId: 'node_trace_evidence',
      attemptId: 'attempt_trace_evidence',
      controlId: 'CC6.1',
      provider: 'aws',
      connectionId: 'conn_trace',
      resourceId: 'resource-trace',
      sourceType: 'aws_config',
      sourceRef: 'scan:trace',
      evidenceKind: 'observation',
      lineage: [{ type: 'scan', id: 'scan-trace' }],
      evidence: { resources: [{ id: 'resource-trace', status: 'pass' }] }
    });
    const verification = await recordVerification({
      organizationId,
      executionId,
      nodeId: 'node_trace_verify',
      attemptId: 'attempt_trace_verify',
      controlId: 'CC6.1',
      outcome: 'PASS',
      evidence,
      details: { verifiedResources: 1 }
    });
    await recordControlDecision({
      organizationId,
      executionId,
      controlId: 'CC6.1',
      scopeKey: 'scope-trace',
      outcome: 'PASS',
      evidenceHash: evidence.evidence_hash,
      verificationHash: verification.verification_hash,
      rationale: { traceTest: true }
    });

    const trace = await getComplianceTrace({ organizationId, executionId });
    expect(trace).toHaveLength(1);
    expect(trace[0].decision.outcome).toBe('PASS');
    expect(trace[0].evidence.hash).toBe(evidence.evidence_hash);
    expect(trace[0].evidence.integrityValid).toBe(true);
    expect(trace[0].evidence.freshness.state).toBe('UNBOUNDED');
    expect(trace[0].evidence.lineage).toEqual([{ type: 'scan', id: 'scan-trace' }]);
    expect(trace[0].verification.hash).toBe(verification.verification_hash);
    expect(trace[0].verification.evidenceHash).toBe(evidence.evidence_hash);
  });
});
