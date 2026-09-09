import crypto from 'crypto';
import pool from './db.js';
import { runScan } from './scanner.js';
import { aggregateSecurityRisk } from './security_risk.js';
import { analyzeExecutionExposurePaths, getExecutionExposurePaths } from './exposure_paths.js';
import { appendExecutionEvent } from './execution_events.js';
import { defaultSecretStore } from './secret_store.js';
import { getProvider } from './provider_registry.js';
import { recordEvidence } from './evidence.js';
import { upsertGraphNode, startNodeAttempt, finishNodeAttempt } from './execution_engine.js';
import { stableExposurePathKey, compareExposurePathSets } from './remediation_path_diff.js';
import { validateFreshReanalysis } from './reanalysis_contract.js';

const EVENT_TYPE = 'REMEDIATION_REANALYSIS_COMPLETED';
const START_EVENT = 'REMEDIATION_REANALYSIS_STARTED';
const MAX_FINDINGS = 5000;
function clean(value, max = 255) { return String(value ?? '').trim().slice(0, max); }
function findingCode(resource, fallback = null) { return clean(resource?.findingCode || resource?.code || resource?.technicalId || resource?.controlCode || fallback, 64).toUpperCase() || null; }
function severity(resource) { const value = clean(resource?.severity || resource?.status || 'LOW', 32).toUpperCase(); return ['LOW','MEDIUM','HIGH','CRITICAL'].includes(value) ? value : 'LOW'; }
function resourceId(resource) { return clean(resource?.resourceId || resource?.id || resource?.name, 255); }
function controlId(resource, fallback = null) { return clean(resource?.controlId || resource?.control || resource?.controls?.soc2?.[0] || fallback || '', 64) || null; }
async function snapshotPaths({ organizationId, executionId }) { return getExecutionExposurePaths({ organizationId, executionId, limit: 100 }); }
async function riskSnapshot({ organizationId, executionId, paths, scanId }) { const selectedScanId = scanId || (await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId])).rows[0]?.metadata?.scanId; if (!selectedScanId) return null; const findings = await pool.query('SELECT id,code,severity,resource_id,control_id,status FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT $3', [organizationId, selectedScanId, MAX_FINDINGS]); return aggregateSecurityRisk({ findings: findings.rows, paths }); }
async function createReanalysisScan({ organizationId, connection, resources, fallbackCode, fallbackControlId, targetResourceId }) {
  const scanId = `reanalysis_scan_${crypto.randomUUID()}`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let findingCount = 0;
    await client.query(`INSERT INTO scans (id,organization_id,connection_id,scan_type,status,started_at,completed_at,resources_discovered,findings_count,evidence_count) VALUES ($1,$2,$3,'remediation_reanalysis','RUNNING',NOW(),NULL,$4,0,0)`, [scanId, organizationId, connection.id, resources.length]);
    for (const resource of resources.slice(0, MAX_FINDINGS)) {
      if (clean(resource?.severity || resource?.status).toLowerCase() === 'pass') continue;
      const id = `finding_${crypto.randomUUID()}`;
      const targetFallback = resourceId(resource) === targetResourceId ? fallbackCode : null;
      const controlFallback = resourceId(resource) === targetResourceId ? fallbackControlId : null;
      await client.query('INSERT INTO findings (id,organization_id,scan_id,resource_id,control_id,severity,status,code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [id, organizationId, scanId, resourceId(resource), controlId(resource, controlFallback), severity(resource), 'FAIL', findingCode(resource, targetFallback)]);
      findingCount += 1;
    }
    await client.query('UPDATE scans SET findings_count=$1 WHERE organization_id=$2 AND id=$3', [findingCount, organizationId, scanId]);
    await client.query('COMMIT');
    return { scanId, findingCount };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    await pool.query(`UPDATE scans SET status='FAILED',completed_at=NOW() WHERE organization_id=$1 AND id=$2 AND status='RUNNING'`, [organizationId, scanId]).catch(() => {});
    throw error;
  } finally { client.release(); }
}

/** Performs a real provider rescan after remediation. The previous scan remains the baseline. */
export async function runRemediationReanalysis({ organizationId, executionId, remediationId, findingId, evidenceId = null, beforePaths = [], riskBefore = null, actorId = null, req = null } = {}) {
  if (!organizationId || !executionId || !remediationId || !findingId) throw new Error('REMEDIATION_REANALYSIS_INPUT_INVALID');
  const executionResult = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]); const execution = executionResult.rows[0]; if (!execution) throw new Error('EXECUTION_NOT_FOUND');
  const previousMetadata = execution.metadata || {}; const baselineScanId = previousMetadata.baselineScanId || previousMetadata.scanId || previousMetadata.scan_id || null; if (!baselineScanId) throw new Error('REMEDIATION_REANALYSIS_BASELINE_UNAVAILABLE');
  const baselineFinding = await pool.query('SELECT code,control_id,resource_id FROM findings WHERE organization_id=$1 AND id=$2 AND scan_id=$3 LIMIT 1', [organizationId, findingId, baselineScanId]); if (!baselineFinding.rows[0]?.resource_id) throw new Error('REMEDIATION_REANALYSIS_BASELINE_FINDING_UNAVAILABLE'); const fallbackCode = baselineFinding.rows[0]?.code || null; const fallbackControlId = baselineFinding.rows[0]?.control_id || null; const targetResourceId = baselineFinding.rows[0]?.resource_id || null;
  const scan = await pool.query('SELECT c.id,c.provider,c.region FROM scans s JOIN cloud_connections c ON c.id=s.connection_id WHERE s.organization_id=$1 AND s.id=$2', [organizationId, baselineScanId]); if (!scan.rows[0]) throw new Error('REMEDIATION_CONNECTION_UNAVAILABLE');
  const connection = scan.rows[0]; const definition = getProvider(connection.provider); const credentials = await defaultSecretStore.getSecret(organizationId, connection.id, 'remediation_reanalysis', actorId, req); if (!credentials) throw new Error('REMEDIATION_CREDENTIALS_UNAVAILABLE');
  const providerCredentials = { ...credentials, ...(connection.region ? { region: credentials.region || connection.region } : {}) }; const baselinePaths = Array.isArray(beforePaths) && beforePaths.length ? beforePaths : (Array.isArray(previousMetadata.baselinePaths) ? previousMetadata.baselinePaths : await snapshotPaths({ organizationId, executionId })); const baselineRisk = riskBefore || previousMetadata.baselineRisk || await riskSnapshot({ organizationId, executionId, paths: baselinePaths, scanId: baselineScanId });
  if (!baselineRisk || !Number.isFinite(Number(baselineRisk.score))) throw new Error('REMEDIATION_REANALYSIS_BASELINE_RISK_UNAVAILABLE');

  let controlEvidence = null;
  if (evidenceId) {
    const controlEvidenceResult = await pool.query(`SELECT id,evidence_hash FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 AND id=$3 LIMIT 1`, [organizationId, executionId, evidenceId]);
    controlEvidence = controlEvidenceResult.rows[0] || null;
    if (!controlEvidence?.id || !controlEvidence.evidence_hash) throw new Error('REMEDIATION_CONTROL_EVIDENCE_UNAVAILABLE');
  }

  const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'REMEDIATION_REANALYSIS', logicalKey: remediationId, status: 'PENDING', label: `Fresh remediation reanalysis — ${remediationId}`, metadata: { provider: definition.id, connectionId: connection.id, remediationId, baselineScanId } }); const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id, metadata: { provider: definition.id, remediationId, baselineScanId } }); await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: START_EVENT, actorType: 'SYSTEM', actorId, result: 'started', payload: { remediationId, provider: definition.id, baselineScanId, controlEvidenceId: controlEvidence?.id || null, controlEvidenceHash: controlEvidence?.evidence_hash || null } });
  let switchedToFreshScan = false;
  let freshScanId = null;
  try {
    const result = await runScan(definition.id, providerCredentials); if (!result || !Array.isArray(result.resources) || result.resources.length < 1) throw new Error('REMEDIATION_REANALYSIS_SCAN_INCOMPLETE'); const fresh = await createReanalysisScan({ organizationId, connection, resources: result.resources, fallbackCode, fallbackControlId, targetResourceId }); freshScanId = fresh.scanId;
    const findingsCheck = await pool.query('SELECT COUNT(*)::int AS count FROM findings WHERE organization_id=$1 AND scan_id=$2', [organizationId, fresh.scanId]); if (Number(findingsCheck.rows[0]?.count) !== fresh.findingCount) throw new Error('REMEDIATION_REANALYSIS_FINDINGS_INCOMPLETE');
    const evidenceRow = await recordEvidence({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, controlId: fallbackControlId || fallbackCode || clean(remediationId, 64), provider: definition.id, connectionId: connection.id, resourceId: targetResourceId, sourceType: 'remediation_reanalysis_scan', sourceRef: fresh.scanId, evidenceKind: 'full_provider_rescan', observedAt: new Date().toISOString(), evidence: { scanId: fresh.scanId, provider: definition.id, resources: result.resources } });
    if (!evidenceRow?.id || !evidenceRow?.evidence_hash) throw new Error('REMEDIATION_REANALYSIS_EVIDENCE_INCOMPLETE');
    const finalized = await pool.query(`UPDATE scans SET status='COMPLETED',completed_at=NOW(),evidence_count=$1 WHERE organization_id=$2 AND id=$3 AND status='RUNNING' RETURNING status,resources_discovered,findings_count,evidence_count`, [1, organizationId, fresh.scanId]);
    const scanState = finalized.rows[0]; if (!scanState || scanState.status !== 'COMPLETED' || Number(scanState.resources_discovered) < 1 || Number(scanState.findings_count) !== fresh.findingCount || Number(scanState.evidence_count) < 1) throw new Error('REMEDIATION_REANALYSIS_SCAN_INCOMPLETE');
    await pool.query(`UPDATE execution_runs SET metadata = metadata || $1::jsonb, updated_at=NOW() WHERE organization_id=$2 AND id=$3`, [JSON.stringify({ baselineScanId, scanId: fresh.scanId, remediationReanalysisScanId: fresh.scanId }), organizationId, executionId]); switchedToFreshScan = true;
    const afterPaths = await analyzeExecutionExposurePaths({ organizationId, executionId, evidenceIds: [evidenceRow.id] }); if (!Array.isArray(afterPaths)) throw new Error('REMEDIATION_REANALYSIS_INCOMPLETE'); const persistedAfterPaths = await snapshotPaths({ organizationId, executionId }); const riskAfter = await riskSnapshot({ organizationId, executionId, paths: persistedAfterPaths, scanId: fresh.scanId });
    const completeness = validateFreshReanalysis({ baselineScanId, freshScanId: fresh.scanId, scanStatus: scanState.status, resourcesObserved: result.resources.length, freshFindingCount: fresh.findingCount, evidenceId: evidenceRow.id, evidenceHash: evidenceRow.evidence_hash, evidenceCount: scanState.evidence_count, afterPaths: persistedAfterPaths, riskAfter }); const beforeComparable = baselinePaths.map(path => ({ ...path, comparisonKey: stableExposurePathKey(path) })); const afterComparable = persistedAfterPaths.map(path => ({ ...path, comparisonKey: stableExposurePathKey(path) })); const diff = compareExposurePathSets({ before: beforeComparable, after: afterComparable, afterComplete: completeness.complete }); const riskDelta = Number(riskAfter.score) - Number(baselineRisk.score); const measurableReduction = diff.removed.length > 0 || riskDelta < 0; const claimSafe = completeness.complete && Boolean(controlEvidence?.id && controlEvidence?.evidence_hash) && measurableReduction;
    const payload = { contractVersion: completeness.version, remediationId: clean(remediationId, 128), findingId: clean(findingId, 128), evidenceId: evidenceRow.id, evidenceHash: evidenceRow.evidence_hash, controlEvidenceId: controlEvidence?.id || null, controlEvidenceHash: controlEvidence?.evidence_hash || null, reanalysisEvidenceId: evidenceRow.id, reanalysisEvidenceHash: evidenceRow.evidence_hash, freshScanId: fresh.scanId, baselineScanId, baselineEvidenceId: evidenceId || null, beforePaths: beforeComparable, afterPaths: afterComparable, afterComplete: completeness.complete, riskBefore: baselineRisk, riskAfter, pathRemoved: diff.removed.length, pathAdded: diff.added.length, pathUnchanged: diff.unchanged.length, riskDelta, claimSafe, provider: definition.id, resourcesObserved: result.resources.length, freshFindingCount: fresh.findingCount, completedAt: new Date().toISOString() };
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED', metadata: { freshScanId: fresh.scanId, evidenceId: evidenceRow.id, freshFindingCount: fresh.findingCount, afterPathCount: persistedAfterPaths.length, claimSafe } }); const event = await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: EVENT_TYPE, actorType: 'SYSTEM', actorId, result: 'completed', payload }); return { ...payload, eventId: event.id };
  } catch (error) {
    if (freshScanId) await pool.query(`UPDATE scans SET status='FAILED',completed_at=NOW() WHERE organization_id=$1 AND id=$2 AND status IN ('RUNNING','COMPLETED')`, [organizationId, freshScanId]).catch(() => {});
    if (switchedToFreshScan) { await pool.query('UPDATE execution_runs SET metadata=$1::jsonb,updated_at=NOW() WHERE organization_id=$2 AND id=$3', [JSON.stringify(previousMetadata), organizationId, executionId]).catch(() => {}); await analyzeExecutionExposurePaths({ organizationId, executionId }).catch(() => {}); }
    await finishNodeAttempt({ attemptId: attempt.id, status: 'FAILED', errorCode: clean(error.code || error.message || 'REMEDIATION_REANALYSIS_FAILED', 64), errorMessage: clean(error.message, 500) }).catch(() => {});
    await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: EVENT_TYPE, actorType: 'SYSTEM', actorId, result: 'incomplete', payload: { remediationId, findingId, baselineScanId, freshScanId, afterComplete: false, claimSafe: false, errorCode: clean(error.code || 'REMEDIATION_REANALYSIS_FAILED', 64), reason: clean(error.message, 500) } }).catch(() => {});
    throw error;
  }
}
export { EVENT_TYPE as REMEDIATION_REANALYSIS_EVENT };