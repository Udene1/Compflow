import pool from './db.js';
import { analyzeExecutionExposurePaths } from './exposure_paths.js';
import { aggregateSecurityRisk } from './security_risk.js';
import { appendExecutionEvent } from './execution_events.js';
import { stableExposurePathKey } from './remediation_path_diff.js';

const EVENT_TYPE = 'REMEDIATION_REANALYSIS_COMPLETED';
function clean(value, max = 255) { return String(value ?? '').trim().slice(0, max); }
async function snapshotPaths({ organizationId, executionId }) {
  const rows = await pool.query(`SELECT p.*, COALESCE(json_agg(DISTINCT pn ORDER BY pn.position) FILTER (WHERE pn.id IS NOT NULL), '[]') AS nodes, COALESCE(json_agg(DISTINCT pe ORDER BY pe.position) FILTER (WHERE pe.id IS NOT NULL), '[]') AS edges FROM exposure_paths p LEFT JOIN exposure_path_nodes pn ON pn.path_id=p.id LEFT JOIN exposure_path_edges pe ON pe.path_id=p.id WHERE p.organization_id=$1 AND p.execution_id=$2 GROUP BY p.id ORDER BY p.created_at ASC`, [organizationId, executionId]);
  return rows.rows;
}
async function riskSnapshot({ organizationId, executionId, paths }) {
  const execution = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
  const metadata = execution.rows[0]?.metadata || {}; const scanId = metadata.scanId || metadata.scan_id || null;
  if (!scanId) return null;
  const findings = await pool.query('SELECT id,code,severity,resource_id,control_id,status FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT 1000', [organizationId, scanId]);
  return aggregateSecurityRisk({ findings: findings.rows, paths });
}
/** Rebuilds the durable exposure graph from persisted provider evidence and records an auditable after snapshot. */
export async function runRemediationReanalysis({ organizationId, executionId, remediationId, findingId, evidenceId, beforePaths = [], riskBefore = null }) {
  if (!organizationId || !executionId || !remediationId || !findingId || !evidenceId) throw new Error('REMEDIATION_REANALYSIS_INPUT_INVALID');
  const evidence = await pool.query(`SELECT id,evidence_hash FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 AND id=$3 AND source_type='post_remediation_targeted_check' AND evidence_hash IS NOT NULL LIMIT 1`, [organizationId, executionId, evidenceId]);
  if (!evidence.rows[0]) throw new Error('REMEDIATION_REANALYSIS_EVIDENCE_UNAVAILABLE');
  await analyzeExecutionExposurePaths({ organizationId, executionId });
  const afterPaths = await snapshotPaths({ organizationId, executionId });
  if (!Array.isArray(afterPaths)) throw new Error('REMEDIATION_REANALYSIS_INCOMPLETE');
  const riskAfter = await riskSnapshot({ organizationId, executionId, paths: afterPaths });
  const payload = { remediationId: clean(remediationId, 128), findingId: clean(findingId, 128), evidenceId: clean(evidenceId, 128), evidenceHash: evidence.rows[0].evidence_hash, beforePaths: beforePaths.map(path => ({ ...path, comparisonKey: stableExposurePathKey(path) })), afterPaths: afterPaths.map(path => ({ ...path, comparisonKey: stableExposurePathKey(path) })), afterComplete: true, riskBefore, riskAfter, completedAt: new Date().toISOString() };
  const event = await appendExecutionEvent({ organizationId, executionId, eventType: EVENT_TYPE, actorType: 'SYSTEM', result: 'completed', payload });
  return { ...payload, eventId: event.id };
}
export { EVENT_TYPE as REMEDIATION_REANALYSIS_EVENT };
