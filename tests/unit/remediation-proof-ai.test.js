import { describe, expect, it } from 'vitest';
import { buildAnalystContext } from '../../core/ai_analyst.js';
import { validateFreshReanalysis } from '../../core/reanalysis_contract.js';

describe('deterministic remediation proof boundary', () => {
  it('does not promote an incomplete remediation proof', () => {
    const context = buildAnalystContext({
      remediationProofs: [{
        remediationId: 'r1', findingId: 'f1', baselineScanId: 'old', freshScanId: 'new',
        evidenceId: 'ev1', evidenceHash: 'hash', afterComplete: false, claimSafe: true,
        riskBefore: { score: 10 }, riskAfter: { score: 1 }, pathRemoved: 1
      }]
    });
    expect(context.remediationProofs[0].claimSafe).toBe(true);
    expect(context.remediationProofs[0].afterComplete).toBe(false);
  });

  it('rejects a reanalysis that reuses the baseline scan', () => {
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-1', freshScanId: 'scan-1', resourcesObserved: 1,
      evidenceId: 'ev1', evidenceHash: 'hash', afterPaths: [], riskAfter: { score: 1 }
    })).toThrow('REMEDIATION_REANALYSIS_SCAN_NOT_FRESH');
  });

  it('requires actual provider evidence and a complete graph/risk snapshot', () => {
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-1', freshScanId: 'scan-2', resourcesObserved: 0,
      evidenceId: 'ev1', evidenceHash: 'hash', afterPaths: [], riskAfter: { score: 1 }
    })).toThrow('REMEDIATION_REANALYSIS_NO_PROVIDER_RESOURCES');
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-1', freshScanId: 'scan-2', resourcesObserved: 1,
      evidenceId: null, evidenceHash: null, afterPaths: [], riskAfter: { score: 1 }
    })).toThrow('REMEDIATION_REANALYSIS_EVIDENCE_INCOMPLETE');
  });
});
