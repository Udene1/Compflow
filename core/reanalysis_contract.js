const VERSION = 'remediation-reanalysis-v1';

function clean(value, max = 255) { return String(value ?? '').trim().slice(0, max); }

export function validateFreshReanalysis({ baselineScanId, freshScanId, resourcesObserved, evidenceId, evidenceHash, afterPaths, riskAfter } = {}) {
  const baseline = clean(baselineScanId, 128);
  const fresh = clean(freshScanId, 128);
  const resources = Number(resourcesObserved);
  const evidence = clean(evidenceId, 128);
  const hash = clean(evidenceHash, 128);
  if (!baseline || !fresh || baseline === fresh) throw new Error('REMEDIATION_REANALYSIS_SCAN_NOT_FRESH');
  if (!Number.isInteger(resources) || resources < 1) throw new Error('REMEDIATION_REANALYSIS_NO_PROVIDER_RESOURCES');
  if (!evidence || !hash) throw new Error('REMEDIATION_REANALYSIS_EVIDENCE_INCOMPLETE');
  if (!Array.isArray(afterPaths)) throw new Error('REMEDIATION_REANALYSIS_GRAPH_INCOMPLETE');
  if (!riskAfter || typeof riskAfter !== 'object' || !Number.isFinite(Number(riskAfter.score))) throw new Error('REMEDIATION_REANALYSIS_RISK_INCOMPLETE');
  return Object.freeze({ version: VERSION, complete: true, baselineScanId: baseline, freshScanId: fresh, resourcesObserved: resources, evidenceId: evidence, evidenceHash: hash, afterPathCount: afterPaths.length, riskScore: Number(riskAfter.score) });
}

export { VERSION as REMEDIATION_REANALYSIS_CONTRACT_VERSION };
