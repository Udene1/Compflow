import { describe, expect, it } from 'vitest';
import { validateFreshReanalysis } from '../../core/reanalysis_contract.js';

describe('fresh remediation reanalysis contract', () => {
  it('rejects reuse of the baseline scan', () => {
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-old', freshScanId: 'scan-old', resourcesObserved: 10,
      evidenceId: 'e1', evidenceHash: 'hash', afterPaths: [], riskAfter: { score: 50 }
    })).toThrow('REMEDIATION_REANALYSIS_SCAN_NOT_FRESH');
  });

  it('rejects incomplete provider collection', () => {
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-old', freshScanId: 'scan-new', resourcesObserved: 0,
      evidenceId: 'e1', evidenceHash: 'hash', afterPaths: [], riskAfter: { score: 50 }
    })).toThrow('REMEDIATION_REANALYSIS_NO_PROVIDER_RESOURCES');
  });

  it('accepts only complete fresh evidence, graph and risk', () => {
    const result = validateFreshReanalysis({
      baselineScanId: 'scan-old', freshScanId: 'scan-new', resourcesObserved: 10,
      evidenceId: 'e1', evidenceHash: 'hash', afterPaths: [], riskAfter: { score: 50 }
    });
    expect(result.complete).toBe(true);
    expect(result.baselineScanId).toBe('scan-old');
    expect(result.freshScanId).toBe('scan-new');
    expect(result.riskScore).toBe(50);
  });
});
