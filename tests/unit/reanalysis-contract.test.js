import { describe, expect, it } from 'vitest';
import { validateFreshReanalysis } from '../../core/reanalysis_contract.js';

const complete = {
  baselineScanId: 'scan-old', freshScanId: 'scan-new', scanStatus: 'COMPLETED', resourcesObserved: 10,
  freshFindingCount: 1, evidenceId: 'e1', evidenceHash: 'hash', evidenceCount: 1, afterPaths: [], riskAfter: { score: 50 }
};

describe('fresh remediation reanalysis contract', () => {
  it('rejects reuse of the baseline scan', () => expect(() => validateFreshReanalysis({ ...complete, freshScanId: 'scan-old' })).toThrow('REMEDIATION_REANALYSIS_SCAN_NOT_FRESH'));
  it('rejects incomplete provider collection', () => expect(() => validateFreshReanalysis({ ...complete, resourcesObserved: 0 })).toThrow('REMEDIATION_REANALYSIS_NO_PROVIDER_RESOURCES'));
  it('accepts only complete fresh evidence, graph and risk', () => {
    const result = validateFreshReanalysis(complete); expect(result.complete).toBe(true); expect(result.baselineScanId).toBe('scan-old');
    expect(result.freshScanId).toBe('scan-new'); expect(result.riskScore).toBe(50); expect(result.freshFindingCount).toBe(1);
  });
  it('rejects an incomplete evidence ledger', () => expect(() => validateFreshReanalysis({ ...complete, evidenceCount: 0 })).toThrow('REMEDIATION_REANALYSIS_EVIDENCE_INCOMPLETE'));
});
