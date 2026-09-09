import { describe, expect, it } from 'vitest';
import { compareExposurePathSets } from '../../core/remediation_path_diff.js';
import { deriveRemediationSecurityProof } from '../../core/remediation_security_proof.js';

const lineage = { baselineScanId: 'scan-before', freshScanId: 'scan-after' };

describe('remediation reanalysis proof boundary', () => {
  it('never calls a missing after graph a removed path', () => {
    const before = [{ id: 'p1', nodes: [{ id: 'internet' }, { id: 'db' }], edges: [] }];
    const result = compareExposurePathSets({ before, after: [], afterComplete: false });
    expect(result.complete).toBe(false); expect(result.removed).toHaveLength(0); expect(result.claimSafe).toBe(false);
  });

  it('proves removal only after complete fresh graph analysis and dual evidence lineage', () => {
    const before = [{ id: 'p1', path_key: 'internet>db', nodes: [{ id: 'internet' }, { id: 'db' }], edges: [] }];
    const result = deriveRemediationSecurityProof({
      remediationId: 'r1', executionId: 'e1', findingId: 'f1', ...lineage,
      controlEvidenceId: 'control-ev1', controlEvidenceHash: 'control-hash', reanalysisEvidenceId: 'reanalysis-ev1', reanalysisEvidenceHash: 'reanalysis-hash',
      verification: { outcome: 'VERIFIED' }, beforePaths: before, afterPaths: [], afterComplete: true, riskBefore: { score: 100 }, riskAfter: { score: 50 }, reanalysisEventId: 'event1'
    });
    expect(result.proofComplete).toBe(true); expect(result.pathImpactClaimed).toBe(true); expect(result.risk.delta).toBe(-50);
    expect(result.controlEvidence.id).toBe('control-ev1'); expect(result.reanalysisEvidence.id).toBe('reanalysis-ev1'); expect(result.claimSafe).toBe(true);
  });

  it('does not claim a reduction without reanalysis evidence lineage', () => {
    const result = deriveRemediationSecurityProof({ remediationId: 'r1', executionId: 'e1', findingId: 'f1', ...lineage, controlEvidenceId: 'control-ev1', controlEvidenceHash: 'control-hash', verification: { outcome: 'VERIFIED' }, beforePaths: [], afterPaths: [], afterComplete: true, riskBefore: { score: 40 }, riskAfter: { score: 10 }, reanalysisEventId: 'event1' });
    expect(result.proofComplete).toBe(false); expect(result.claimSafe).toBe(false);
  });

  it('does not claim a reduction when complete reanalysis shows equal or higher risk', () => {
    const result = deriveRemediationSecurityProof({ remediationId: 'r1', executionId: 'e1', findingId: 'f1', ...lineage, controlEvidenceId: 'control-ev1', controlEvidenceHash: 'control-hash', reanalysisEvidenceId: 'reanalysis-ev1', reanalysisEvidenceHash: 'reanalysis-hash', verification: { outcome: 'VERIFIED' }, beforePaths: [], afterPaths: [], afterComplete: true, riskBefore: { score: 40 }, riskAfter: { score: 40 }, reanalysisEventId: 'event1' });
    expect(result.proofComplete).toBe(true); expect(result.risk.comparable).toBe(true); expect(result.risk.delta).toBe(0); expect(result.claimSafe).toBe(false);
    const increased = deriveRemediationSecurityProof({ remediationId: 'r1', executionId: 'e1', findingId: 'f1', ...lineage, controlEvidenceId: 'control-ev1', controlEvidenceHash: 'control-hash', reanalysisEvidenceId: 'reanalysis-ev1', reanalysisEvidenceHash: 'reanalysis-hash', verification: { outcome: 'VERIFIED' }, beforePaths: [], afterPaths: [], afterComplete: true, riskBefore: { score: 40 }, riskAfter: { score: 50 }, reanalysisEventId: 'event1' });
    expect(increased.claimSafe).toBe(false);
  });
});
