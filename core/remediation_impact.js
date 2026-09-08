import { listRemediations } from './remediation_verification.js';
import { getExecutionExposurePaths } from './exposure_paths.js';
import { aggregateSecurityRisk } from './security_risk.js';
import pool from './db.js';

/**
 * Security effect is deliberately conservative: a verified control change is not
 * converted into a lower risk score until a fresh finding/exposure analysis exists.
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
  const verified = remediation.state === 'VERIFIED';
  return {
    remediationId,
    findingId: remediation.findingId,
    code: remediation.code,
    state: remediation.state,
    verified,
    affectedPathCount: affectedPaths.length,
    affectedPathIds: affectedPaths.map(path => path.id),
    riskBeforeFreshReanalysis: risk,
    riskDelta: null,
    securityEffect: verified ? 'CONTROL_VERIFIED_FRESH_PATH_REANALYSIS_REQUIRED' : 'CONTROL_NOT_VERIFIED',
    claimSafe: verified ? 'The targeted control has been verified, but risk/exposure reduction is not claimed until a fresh scan and exposure analysis removes the finding/path.' : 'No verified security effect is claimed.'
  };
}
