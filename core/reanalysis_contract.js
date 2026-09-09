const VERSION = 'remediation-reanalysis-v2';

function clean(value, max = 255) { return String(value ?? '').trim().slice(0, max); }

export function validateFreshReanalysis({ baselineScanId, freshScanId, scanStatus, resourcesObserved, freshFindingCount, evidenceId, evidenceHash, evidenceCount, afterPaths, riskAfter } = {}) {
  const baseline = clean(baselineScanId, 128);
  const fresh = clean(freshScanId, 128);
  const status = clean(scanStatus, 32).toUpperCase();
  const resources = Number(resourcesObserved);
  const findings = Number(freshFindingCount);
  const evidence = clean(evidenceId, 128);
  const hash = clean(evidenceHash, 128);
  const evidenceRows = Number(evidenceCount);
  if (!baseline || !fresh || baseline === fresh) throw new Error('REMEDIATION_REANALYSIS_SCAN_NOT_FRESH');
  if (status !== 'COMPLETED') throw new Error('REMEDIATION_REANALYSIS_SCAN_NOT_COMPLETED');
  if (!Number.isInteger(resources) || resources < 1) throw new Error('REMEDIATION_REANALYSIS_NO_PROVIDER_RESOURCES');
  if (!Number.isInteger(findings) || findings < 0) throw new Error('REMEDIATION_REANALYSIS_FINDINGS_INCOMPLETE');
  if (!evidence || !hash || !Number.isInteger(evidenceRows) || evidenceRows < 1) throw new Error('REMEDIATION_REANALYSIS_EVIDENCE_INCOMPLETE');
  if (!Array.isArray(afterPaths)) throw new Error('REMEDIATION_REANALYSIS_GRAPH_INCOMPLETE');
  if (!riskAfter || typeof riskAfter !== 'object' || !Number.isFinite(Number(riskAfter.score))) throw new Error('REMEDIATION_REANALYSIS_RISK_INCOMPLETE');
  return Object.freeze({ version: VERSION, complete: true, baselineScanId: baseline, freshScanId: fresh, scanStatus: status, resourcesObserved: resources, freshFindingCount: findings, evidenceId: evidence, evidenceHash: hash, evidenceCount: evidenceRows, afterPathCount: afterPaths.length, riskScore: Number(riskAfter.score) });
}

export { VERSION as REMEDIATION_REANALYSIS_CONTRACT_VERSION };
