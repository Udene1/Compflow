import { listRemediations } from './remediation_verification.js';
import { getExecutionExposurePaths } from './exposure_paths.js';
import { aggregateSecurityRisk } from './security_risk.js';
import { deriveRemediationSecurityEffect } from './remediation_security_effect.js';
import pool from './db.js';

/**
 * Security effect remains conservative: verified control evidence is distinct from
 * proof that an exposure path or aggregate risk has disappeared.
 */
export async function getRemediationSecurityImpact({ organizationId, executionId, remediationId }) {
  if (!organizationId || !executionId || !remediationId) throw new Error('REMEDIATION_IMPACT_INPUT_INVALID');
  const remediation = (await listRemediations({ organizationId, executionId })).find(item => item.id === remediationId);
  if (!remediation) throw new Error('REMEDIATION_NOT_FOUND');
  const paths = await getExecutionExposurePaths({ organizationId, executionId, limit: 100 });
  const affectedPaths = paths.filter(path => (path.nodes || []).some(node => (node.finding_ids || []).includes(remediation.findingId)));
  const execution = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
  const scanId = execution.rows[0]?.metadata?.scanId || execution.rows[0]?.metadata?.scan_id || null;
  let risk = null;
  if (scanId) {
    const findings = await pool.query('SELECT id,code,severity,resource_id FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT 1000', [organizationId, scanId]);
    risk = aggregateSecurityRisk({ findings: findings.rows, paths });
  }
  const latest = await pool.query(`SELECT id,collected_at,evidence_hash,evidence,evidence_kind,observed_at,freshness_expires_at FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 AND resource_id=$3 AND source_type='post_remediation_targeted_check' AND source_ref=$4 ORDER BY collected_at DESC LIMIT 1`, [organizationId, executionId, remediation.resourceId, remediationId]);
  const freshEvidence = latest.rows[0] || null;
  const effect = deriveRemediationSecurityEffect({ code: remediation.code, remediationState: remediation.state, evidence: freshEvidence, affectedPathCount: affectedPaths.length });
  return {
    remediationId,
    findingId: remediation.findingId,
    code: remediation.code,
    state: remediation.state,
    verified: effect.verified,
    affectedPathCount: affectedPaths.length,
    affectedPathIds: affectedPaths.map(path => path.id),
    riskBeforeFreshReanalysis: risk,
    riskDelta: null,
    securityEffect: effect,
    claimSafe: effect.pathImpactClaimed ? 'Fresh exposure analysis confirms the affected path is removed.' : 'Compflow does not claim exposure-path or aggregate-risk reduction until fresh exposure analysis confirms the change.'
  };
}
