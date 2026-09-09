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
    expect(context.remediationProofs[0].claimSafe).toBe(false);
    expect(context.remediationProofs[0].afterComplete).toBe(false);
  });

  it('allows only a complete proof with both evidence lineages to remain claim-safe', () => {
    const context = buildAnalystContext({
      remediationProofs: [{
        remediationId: 'r1', findingId: 'f1', baselineScanId: 'old', freshScanId: 'new',
        controlEvidenceId: 'control-ev1', controlEvidenceHash: 'control-hash',
        reanalysisEvidenceId: 'reanalysis-ev1', reanalysisEvidenceHash: 'reanalysis-hash',
        afterComplete: true, claimSafe: true, riskBefore: { score: 10 }, riskAfter: { score: 1 }, pathRemoved: 1
      }]
    });
    expect(context.remediationProofs[0].claimSafe).toBe(true);
    expect(context.remediationProofs[0].reanalysisEvidenceId).toBe('reanalysis-ev1');
  });

  it('rejects a reanalysis that reuses the baseline scan', () => {
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-1', freshScanId: 'scan-1', scanStatus: 'COMPLETED', resourcesObserved: 1,
      freshFindingCount: 0, evidenceId: 'ev1', evidenceHash: 'hash', evidenceCount: 1,
      afterPaths: [], riskAfter: { score: 1 }
    })).toThrow('REMEDIATION_REANALYSIS_SCAN_NOT_FRESH');
  });

  it('requires a completed persisted fresh scan', () => {
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-1', freshScanId: 'scan-2', scanStatus: 'RUNNING', resourcesObserved: 1,
      freshFindingCount: 0, evidenceId: 'ev1', evidenceHash: 'hash', evidenceCount: 1,
      afterPaths: [], riskAfter: { score: 1 }
    })).toThrow('REMEDIATION_REANALYSIS_SCAN_NOT_COMPLETED');

    const result = validateFreshReanalysis({
      baselineScanId: 'scan-1', freshScanId: 'scan-2', scanStatus: 'COMPLETED', resourcesObserved: 1,
      freshFindingCount: 0, evidenceId: 'ev1', evidenceHash: 'hash', evidenceCount: 1,
      afterPaths: [], riskAfter: { score: 1 }
    });
    expect(result.complete).toBe(true);
    expect(result.version).toBe('remediation-reanalysis-v2');
  });

  it('requires actual provider evidence and a complete graph/risk snapshot', () => {
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-1', freshScanId: 'scan-2', scanStatus: 'COMPLETED', resourcesObserved: 0,
      freshFindingCount: 0, evidenceId: 'ev1', evidenceHash: 'hash', evidenceCount: 1,
      afterPaths: [], riskAfter: { score: 1 }
    })).toThrow('REMEDIATION_REANALYSIS_NO_PROVIDER_RESOURCES');
    expect(() => validateFreshReanalysis({
      baselineScanId: 'scan-1', freshScanId: 'scan-2', scanStatus: 'COMPLETED', resourcesObserved: 1,
      freshFindingCount: 0, evidenceId: null, evidenceHash: null, evidenceCount: 0,
      afterPaths: [], riskAfter: { score: 1 }
    })).toThrow('REMEDIATION_REANALYSIS_EVIDENCE_INCOMPLETE');
  });
});
