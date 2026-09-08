import { describe, expect, it } from 'vitest';
import { compareExposurePathSets } from '../../core/remediation_path_diff.js';
import { deriveRemediationSecurityProof } from '../../core/remediation_security_proof.js';

describe('remediation reanalysis proof boundary', () => {
  it('never calls a missing after graph a removed path', () => {
    const before = [{ id: 'p1', nodes: [{ id: 'internet' }, { id: 'db' }], edges: [] }];
    const result = compareExposurePathSets({ before, after: [], afterComplete: false });
    expect(result.complete).toBe(false);
    expect(result.removed).toHaveLength(0);
    expect(result.claimSafe).toBe(false);
  });

  it('proves removal only after complete fresh graph analysis', () => {
    const before = [{ id: 'p1', path_key: 'internet>db', nodes: [{ id: 'internet' }, { id: 'db' }], edges: [] }];
    const result = deriveRemediationSecurityProof({
      remediationId: 'r1', executionId: 'e1', findingId: 'f1', evidenceId: 'ev1', evidenceHash: 'hash',
      verification: { outcome: 'VERIFIED' }, beforePaths: before, afterPaths: [], afterComplete: true,
      riskBefore: { score: 100 }, riskAfter: { score: 50 }, reanalysisEventId: 'event1'
    });
    expect(result.proofComplete).toBe(true);
    expect(result.pathImpactClaimed).toBe(true);
    expect(result.risk.delta).toBe(-50);
    expect(result.claimSafe).toBe(true);
  });
});
