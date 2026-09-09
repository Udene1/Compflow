import { listRemediations } from './remediation_verification.js';
import { getExecutionExposurePaths } from './exposure_paths.js';
import { aggregateSecurityRisk } from './security_risk.js';
import { deriveRemediationSecurityEffect } from './remediation_security_effect.js';
import { deriveRemediationSecurityProof } from './remediation_security_proof.js';
import { listExecutionEvents } from './execution_events.js';
import pool from './db.js';

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
    const findings = await pool.query('SELECT id,code,severity,resource_id,control_id,status FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT 1000', [organizationId, scanId]);
    risk = aggregateSecurityRisk({ findings: findings.rows, paths });
  }
  const latest = await pool.query(`SELECT id,collected_at,evidence_hash,evidence,evidence_kind,observed_at,freshness_expires_at FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 AND resource_id=$3 AND source_type='post_remediation_targeted_check' AND source_ref=$4 ORDER BY collected_at DESC LIMIT 1`, [organizationId, executionId, remediation.resourceId, remediationId]);
  const freshEvidence = latest.rows[0] || null;
  const effect = deriveRemediationSecurityEffect({ code: remediation.code, remediationState: remediation.state, evidence: freshEvidence, affectedPathCount: affectedPaths.length });
  const reanalysisEvents = await listExecutionEvents({ organizationId, executionId, limit: 1000 });
  const event = reanalysisEvents.filter(item => item.event_type === 'REMEDIATION_REANALYSIS_COMPLETED' && item.result === 'completed' && item.payload?.remediationId === remediationId).at(-1) || null;
  const reanalysis = event?.payload || null;
  let reanalysisEvidence = null;
  if (reanalysis?.reanalysisEvidenceId) {
    const evidence = await pool.query(`SELECT id,evidence_hash,collected_at,observed_at,source_type,source_ref FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 AND id=$3 LIMIT 1`, [organizationId, executionId, reanalysis.reanalysisEvidenceId]);
    reanalysisEvidence = evidence.rows[0] || null;
  }
  const controlEvidenceId = freshEvidence?.id || null;
  const controlEvidenceHash = freshEvidence?.evidence_hash || null;
  const reanalysisEvidenceId = reanalysisEvidence?.id || null;
  const reanalysisEvidenceHash = reanalysisEvidence?.evidence_hash || null;
  const lineageMatchesEvent = Boolean(
    reanalysisEvidenceId && reanalysisEvidenceHash &&
    reanalysisEvidenceId === reanalysis?.reanalysisEvidenceId &&
    reanalysisEvidenceHash === reanalysis?.reanalysisEvidenceHash
  );
  const proof = deriveRemediationSecurityProof({
    remediationId, executionId, findingId: remediation.findingId,
    controlEvidenceId, controlEvidenceHash,
    reanalysisEvidenceId: lineageMatchesEvent ? reanalysisEvidenceId : null,
    reanalysisEvidenceHash: lineageMatchesEvent ? reanalysisEvidenceHash : null,
    verification: remediation.verification || null,
    baselineScanId: reanalysis?.baselineScanId || null,
    freshScanId: reanalysis?.freshScanId || null,
    beforePaths: reanalysis?.beforePaths || [], afterPaths: reanalysis?.afterPaths || [],
    afterComplete: reanalysis?.afterComplete === true, riskBefore: reanalysis?.riskBefore || null,
    riskAfter: reanalysis?.riskAfter || null, reanalysisEventId: event?.id || null
  });
  return {
    remediationId, findingId: remediation.findingId, code: remediation.code, state: remediation.state,
    verified: effect.verified, affectedPathCount: affectedPaths.length, affectedPathIds: affectedPaths.map(path => path.id),
    currentRiskObservation: risk, riskDelta: proof.risk.delta, securityEffect: effect, securityProof: proof,
    claimSafe: proof.claimSafe ? 'Fresh control evidence and complete reanalysis support the recorded security-effect claim.' : 'Compflow does not claim exposure-path or aggregate-risk reduction until fresh control evidence, fresh reanalysis evidence, distinct scan lineage, and complete reanalysis lineage are present.'
  };
}
