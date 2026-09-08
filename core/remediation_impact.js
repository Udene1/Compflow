import { listRemediations } from './remediation_verification.js';
import { getExecutionExposurePaths } from './exposure_paths.js';
import { aggregateSecurityRisk } from './security_risk.js';
import { deriveRemediationSecurityEffect } from './remediation_security_effect.js';
import { deriveRemediationSecurityProof } from './remediation_security_proof.js';
import pool from './db.js';

/**
 * Security impact is deliberately fail-closed. This endpoint may expose the
 * current observation, but it cannot manufacture a before/after comparison.
 * A reduction claim requires fresh verification plus a complete reanalysis
 * lineage supplied by the remediation proof contract.
 */
export async function getRemediationSecurityImpact({ organizationId, executionId, remediationId }) {
  if (!organizationId || !executionId || !remediationId) throw new Error('REMEDIATION_IMPACT_INPUT_INVALID');
  const remediation = (await listRemediations({ organizationId, executionId })).find(item => item.id === remediationId);
  if (!remediation) throw new Error('REMEDIATION_NOT_FOUND');

  const paths = await getExecutionExposurePaths({ organizationId, executionId, limit: 100 });
  const affectedPaths = paths.filter(path => (path.nodes || []).some(node => (node.finding_ids || []).includes(remediation.findingId)));
  const execution = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
  const metadata = execution.rows[0]?.metadata || {};
  const scanId = metadata.scanId || metadata.scan_id || null;

  let risk = null;
  if (scanId) {
    const findings = await pool.query(
      'SELECT id,code,severity,resource_id FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT 1000',
      [organizationId, scanId]
    );
    risk = aggregateSecurityRisk({ findings: findings.rows, paths });
  }

  const latest = await pool.query(
    `SELECT id,collected_at,evidence_hash,evidence,evidence_kind,observed_at,freshness_expires_at
       FROM execution_evidence_records
      WHERE organization_id=$1 AND execution_id=$2 AND resource_id=$3
        AND source_type='post_remediation_targeted_check' AND source_ref=$4
      ORDER BY collected_at DESC LIMIT 1`,
    [organizationId, executionId, remediation.resourceId, remediationId]
  );
  const freshEvidence = latest.rows[0] || null;
  const effect = deriveRemediationSecurityEffect({
    code: remediation.code,
    remediationState: remediation.state,
    evidence: freshEvidence,
    affectedPathCount: affectedPaths.length
  });

  // Until a complete fresh reanalysis is persisted, the current graph is not
  // treated as an "after" graph. This makes the absence of a proof explicit.
  const reanalysis = metadata.remediationReanalysis?.[remediationId] || null;
  const proof = deriveRemediationSecurityProof({
    remediationId,
    executionId,
    findingId: remediation.findingId,
    evidenceId: freshEvidence?.id || null,
    evidenceHash: freshEvidence?.evidence_hash || null,
    verification: remediation.verification || null,
    beforePaths: reanalysis?.beforePaths || [],
    afterPaths: reanalysis?.afterPaths || [],
    afterComplete: reanalysis?.afterComplete === true,
    riskBefore: reanalysis?.riskBefore || null,
    riskAfter: reanalysis?.riskAfter || null,
    reanalysisEventId: reanalysis?.eventId || null
  });

  return {
    remediationId,
    findingId: remediation.findingId,
    code: remediation.code,
    state: remediation.state,
    verified: effect.verified,
    affectedPathCount: affectedPaths.length,
    affectedPathIds: affectedPaths.map(path => path.id),
    currentRiskObservation: risk,
    riskDelta: proof.risk.delta,
    securityEffect: effect,
    securityProof: proof,
    claimSafe: proof.claimSafe
      ? 'Fresh evidence and complete reanalysis support the recorded security-effect claim.'
      : 'Compflow does not claim exposure-path or aggregate-risk reduction until fresh exposure reanalysis is complete and auditable.'
  };
}
