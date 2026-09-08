import pool from './db.js';
import { getEvidenceFreshness, verifyEvidenceIntegrity } from './evidence.js';

const LIMIT = 200;

function boundedLimit(value) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? Math.max(1, Math.min(parsed, LIMIT)) : 100;
}

/**
 * Build the authoritative compliance trace for an execution.
 *
 * The trace deliberately joins durable records rather than reconstructing
 * state from worker payloads. Evidence is linked to its control decision by
 * the persisted evidence hash; verification is linked through its persisted
 * evidence hash as well. This gives API/UI consumers one explainable chain:
 * source evidence -> verification -> control decision.
 */
export async function getComplianceTrace({ organizationId, executionId, limit = 100 } = {}) {
  if (!organizationId || !executionId) throw new Error('COMPLIANCE_TRACE_INPUT_INVALID');
  const bounded = boundedLimit(limit);

  const result = await pool.query(`
    SELECT
      d.id AS decision_id,
      d.control_id,
      d.scope_key,
      d.outcome AS decision_outcome,
      d.evidence_hash AS decision_evidence_hash,
      d.verification_hash AS decision_verification_hash,
      d.rationale AS decision_rationale,
      d.decided_at AS decision_at,
      e.id AS evidence_id,
      e.node_id AS evidence_node_id,
      e.attempt_id AS evidence_attempt_id,
      e.provider AS evidence_provider,
      e.connection_id AS evidence_connection_id,
      e.resource_id AS evidence_resource_id,
      e.source_type,
      e.source_ref,
      e.collected_at,
      e.observed_at,
      e.freshness_expires_at,
      e.evidence_kind,
      e.evidence_hash,
      e.lineage,
      e.evidence,
      v.id AS verification_id,
      v.node_id AS verification_node_id,
      v.attempt_id AS verification_attempt_id,
      v.outcome AS verification_outcome,
      v.evidence_hash AS verification_evidence_hash,
      v.verification_hash,
      v.details AS verification_details,
      v.verified_at
    FROM compliance_decisions d
    LEFT JOIN LATERAL (
      SELECT * FROM execution_evidence_records e0
      WHERE e0.organization_id=d.organization_id
        AND e0.execution_id=d.execution_id
        AND e0.evidence_hash=d.evidence_hash
      ORDER BY e0.collected_at DESC
      LIMIT 1
    ) e ON TRUE
    LEFT JOIN LATERAL (
      SELECT * FROM execution_verifications v0
      WHERE v0.organization_id=d.organization_id
        AND v0.execution_id=d.execution_id
        AND v0.verification_hash=d.verification_hash
      ORDER BY v0.created_at DESC
      LIMIT 1
    ) v ON TRUE
    WHERE d.organization_id=$1 AND d.execution_id=$2
    ORDER BY d.control_id, d.scope_key
    LIMIT $3
  `, [organizationId, executionId, bounded]);

  return result.rows.map(row => ({
    decision: {
      id: row.decision_id,
      controlId: row.control_id,
      scopeKey: row.scope_key,
      outcome: row.decision_outcome,
      evidenceHash: row.decision_evidence_hash,
      verificationHash: row.decision_verification_hash,
      rationale: row.decision_rationale,
      decidedAt: row.decision_at
    },
    evidence: row.evidence_id ? {
      id: row.evidence_id,
      nodeId: row.evidence_node_id,
      attemptId: row.evidence_attempt_id,
      provider: row.evidence_provider,
      connectionId: row.evidence_connection_id,
      resourceId: row.evidence_resource_id,
      sourceType: row.source_type,
      sourceRef: row.source_ref,
      collectedAt: row.collected_at,
      observedAt: row.observed_at,
      freshnessExpiresAt: row.freshness_expires_at,
      kind: row.evidence_kind,
      hash: row.evidence_hash,
      lineage: row.lineage || [],
      integrityValid: verifyEvidenceIntegrity(row),
      freshness: getEvidenceFreshness(row),
      payload: row.evidence
    } : null,
    verification: row.verification_id ? {
      id: row.verification_id,
      nodeId: row.verification_node_id,
      attemptId: row.verification_attempt_id,
      outcome: row.verification_outcome,
      evidenceHash: row.verification_evidence_hash,
      hash: row.verification_hash,
      details: row.verification_details,
      verifiedAt: row.verified_at
    } : null
  }));
}
