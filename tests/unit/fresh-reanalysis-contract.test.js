import { describe, expect, it } from 'vitest';
import { validateFreshReanalysis } from '../../core/reanalysis_contract.js';

describe('fresh remediation reanalysis contract', () => {
  const complete = {
    baselineScanId: 'baseline-scan', freshScanId: 'fresh-scan', scanStatus: 'COMPLETED',
    resourcesObserved: 12, freshFindingCount: 2, evidenceId: 'evidence-1', evidenceHash: 'hash-1', evidenceCount: 1,
    afterPaths: [], riskAfter: { score: 3 }
  };
  it('accepts only a completed distinct provider scan with durable evidence, graph and risk', () => {
    const result = validateFreshReanalysis(complete);
    expect(result.complete).toBe(true); expect(result.baselineScanId).toBe('baseline-scan'); expect(result.freshScanId).toBe('fresh-scan');
    expect(result.evidenceId).toBe('evidence-1'); expect(result.freshFindingCount).toBe(2); expect(result.riskScore).toBe(3);
  });
  it('fails closed when the fresh scan identity is reused as the baseline', () => {
    expect(() => validateFreshReanalysis({ ...complete, freshScanId: 'baseline-scan' })).toThrow('REMEDIATION_REANALYSIS_SCAN_NOT_FRESH');
  });
  it('fails closed when provider resources are absent', () => {
    expect(() => validateFreshReanalysis({ ...complete, resourcesObserved: 0 })).toThrow('REMEDIATION_REANALYSIS_NO_PROVIDER_RESOURCES');
  });
  it('fails closed when evidence lineage is incomplete', () => {
    expect(() => validateFreshReanalysis({ ...complete, evidenceHash: '' })).toThrow('REMEDIATION_REANALYSIS_EVIDENCE_INCOMPLETE');
    expect(() => validateFreshReanalysis({ ...complete, evidenceCount: 0 })).toThrow('REMEDIATION_REANALYSIS_EVIDENCE_INCOMPLETE');
  });
  it('fails closed when the rebuilt graph or deterministic risk is missing', () => {
    expect(() => validateFreshReanalysis({ ...complete, afterPaths: null })).toThrow('REMEDIATION_REANALYSIS_GRAPH_INCOMPLETE');
    expect(() => validateFreshReanalysis({ ...complete, riskAfter: null })).toThrow('REMEDIATION_REANALYSIS_RISK_INCOMPLETE');
  });
  it('fails closed when persisted scan is not completed', () => {
    expect(() => validateFreshReanalysis({ ...complete, scanStatus: 'RUNNING' })).toThrow('REMEDIATION_REANALYSIS_SCAN_NOT_COMPLETED');
  });
});
