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
import { stableExposurePathKey } from './remediation_path_diff.js';
import { validateFreshReanalysis } from './reanalysis_contract.js';

const EVENT_TYPE = 'REMEDIATION_REANALYSIS_COMPLETED';
const START_EVENT = 'REMEDIATION_REANALYSIS_STARTED';
const MAX_FINDINGS = 5000;
function clean(value, max = 255) { return String(value ?? '').trim().slice(0, max); }
function findingCode(resource) { return clean(resource?.findingCode || resource?.code || resource?.technicalId || resource?.controlCode, 64).toUpperCase() || null; }
function severity(resource) { const value = clean(resource?.severity || resource?.status || 'LOW', 32).toUpperCase(); return ['LOW','MEDIUM','HIGH','CRITICAL'].includes(value) ? value : 'LOW'; }
function resourceId(resource) { return clean(resource?.resourceId || resource?.id || resource?.name, 255); }
function controlId(resource) { return clean(resource?.controlId || resource?.control || resource?.controls?.soc2?.[0] || '', 64) || null; }
async function snapshotPaths({ organizationId, executionId }) { return getExecutionExposurePaths({ organizationId, executionId, limit: 100 }); }
async function riskSnapshot({ organizationId, executionId, paths, scanId }) { const selectedScanId = scanId || (await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId])).rows[0]?.metadata?.scanId; if (!selectedScanId) return null; const findings = await pool.query('SELECT id,code,severity,resource_id,control_id,status FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT $3', [organizationId, selectedScanId, MAX_FINDINGS]); return aggregateSecurityRisk({ findings: findings.rows, paths }); }
async function createReanalysisScan({ organizationId, connection, resources }) { const scanId = `reanalysis_scan_${crypto.randomUUID()}`; const client = await pool.connect(); try { await client.query('BEGIN'); await client.query(`INSERT INTO scans (id,organization_id,connection_id,scan_type,status,started_at,completed_at,resources_discovered,findings_count,evidence_count) VALUES ($1,$2,$3,'remediation_reanalysis','COMPLETED',NOW(),NOW(),$4,$5,1)`, [scanId, organizationId, connection.id, resources.length, resources.filter(resource => clean(resource?.severity || resource?.status).toLowerCase() !== 'pass').length]); const findings = []; for (const resource of resources.slice(0, MAX_FINDINGS)) { if (clean(resource?.severity || resource?.status).toLowerCase() === 'pass') continue; const id = `finding_${crypto.randomUUID()}`; const finding = { id, organizationId, scanId, resourceId: resourceId(resource), controlId: controlId(resource), severity: severity(resource), status: 'FAIL', code: findingCode(resource) }; await client.query('INSERT INTO findings (id,organization_id,scan_id,resource_id,control_id,severity,status,code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [id, organizationId, scanId, finding.resourceId, finding.controlId, finding.severity, finding.status, finding.code]); findings.push(finding); } await client.query('COMMIT'); return { scanId, findings }; } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); } }

/** Performs a real provider rescan after remediation. The previous scan remains the baseline. */
export async function runRemediationReanalysis({ organizationId, executionId, remediationId, findingId, evidenceId = null, beforePaths = [], riskBefore = null, actorId = null, req = null } = {}) {
  if (!organizationId || !executionId || !remediationId || !findingId) throw new Error('REMEDIATION_REANALYSIS_INPUT_INVALID');
  const executionResult = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]); const execution = executionResult.rows[0]; if (!execution) throw new Error('EXECUTION_NOT_FOUND');
  const metadata = execution.metadata || {}; const baselineScanId = metadata.baselineScanId || metadata.scanId || metadata.scan_id || null; if (!baselineScanId) throw new Error('REMEDIATION_REANALYSIS_BASELINE_UNAVAILABLE');
  const scan = await pool.query(`SELECT c.id,c.provider,c.region FROM scans s JOIN cloud_connections c ON c.id=s.connection_id WHERE s.organization_id=$1 AND s.id=$2`, [organizationId, baselineScanId]); if (!scan.rows[0]) throw new Error('REMEDIATION_CONNECTION_UNAVAILABLE');
  const connection = scan.rows[0]; const definition = getProvider(connection.provider); const credentials = await defaultSecretStore.getSecret(organizationId, connection.id, 'remediation_reanalysis', actorId, req); if (!credentials) throw new Error('REMEDIATION_CREDENTIALS_UNAVAILABLE');
  const providerCredentials = { ...credentials, ...(connection.region ? { region: credentials.region || connection.region } : {}) };
  const baselinePaths = Array.isArray(beforePaths) && beforePaths.length ? beforePaths : await snapshotPaths({ organizationId, executionId }); const baselineRisk = riskBefore || await riskSnapshot({ organizationId, executionId, paths: baselinePaths, scanId: baselineScanId });
  const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'REMEDIATION_REANALYSIS', logicalKey: remediationId, status: 'PENDING', label: `Fresh remediation reanalysis — ${remediationId}`, metadata: { provider: definition.id, connectionId: connection.id, remediationId, baselineScanId } });
  const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id, metadata: { provider: definition.id, remediationId, baselineScanId } });
  await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: START_EVENT, actorType: 'SYSTEM', actorId, result: 'started', payload: { remediationId, provider: definition.id, baselineScanId } });
  try {
    const result = await runScan(definition.id, providerCredentials); if (!result || !Array.isArray(result.resources)) throw new Error('REMEDIATION_REANALYSIS_SCAN_INCOMPLETE');
    const { scanId: freshScanId } = await createReanalysisScan({ organizationId, connection, resources: result.resources });
    const evidenceRow = await recordEvidence({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, controlId: clean(remediationId, 64), provider: definition.id, connectionId: connection.id, resourceId: null, sourceType: 'remediation_reanalysis_scan', sourceRef: remediationId, evidenceKind: 'full_provider_rescan', observedAt: new Date().toISOString(), evidence: { scanId: freshScanId, provider: definition.id, resources: result.resources } });
    await pool.query(`UPDATE execution_runs SET metadata = metadata || $1::jsonb, updated_at=NOW() WHERE organization_id=$2 AND id=$3`, [JSON.stringify({ baselineScanId, scanId: freshScanId, remediationReanalysisScanId: freshScanId }), organizationId, executionId]);
    const afterPaths = await analyzeExecutionExposurePaths({ organizationId, executionId }); if (!Array.isArray(afterPaths)) throw new Error('REMEDIATION_REANALYSIS_INCOMPLETE');
    const persistedAfterPaths = await snapshotPaths({ organizationId, executionId }); const riskAfter = await riskSnapshot({ organizationId, executionId, paths: persistedAfterPaths, scanId: freshScanId });
    const completeness = validateFreshReanalysis({ baselineScanId, freshScanId, resourcesObserved: result.resources.length, evidenceId: evidenceRow.id, evidenceHash: evidenceRow.evidence_hash, afterPaths: persistedAfterPaths, riskAfter });
    const payload = { contractVersion: completeness.version, remediationId: clean(remediationId, 128), findingId: clean(findingId, 128), evidenceId: evidenceRow.id, evidenceHash: evidenceRow.evidence_hash, freshScanId, baselineScanId, baselineEvidenceId: evidenceId || null, beforePaths: baselinePaths.map(path => ({ ...path, comparisonKey: stableExposurePathKey(path) })), afterPaths: persistedAfterPaths.map(path => ({ ...path, comparisonKey: stableExposurePathKey(path) })), afterComplete: completeness.complete, riskBefore: baselineRisk, riskAfter, provider: definition.id, resourcesObserved: result.resources.length, completedAt: new Date().toISOString() };
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED', metadata: { freshScanId, evidenceId: evidenceRow.id, afterPathCount: persistedAfterPaths.length } });
    const event = await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: EVENT_TYPE, actorType: 'SYSTEM', actorId, result: 'completed', payload }); return { ...payload, eventId: event.id };
  } catch (error) {
    await finishNodeAttempt({ attemptId: attempt.id, status: 'FAILED', errorCode: clean(error.code || error.message || 'REMEDIATION_REANALYSIS_FAILED', 64), errorMessage: clean(error.message, 500) }).catch(() => {});
    await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: EVENT_TYPE, actorType: 'SYSTEM', actorId, result: 'incomplete', payload: { remediationId, findingId, baselineScanId, afterComplete: false, errorCode: clean(error.code || 'REMEDIATION_REANALYSIS_FAILED', 64), reason: clean(error.message, 500) } }).catch(() => {}); throw error;
  }
}
export { EVENT_TYPE as REMEDIATION_REANALYSIS_EVENT };
