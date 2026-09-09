import { describe, it, expect } from 'vitest';
import { deriveRemediationSecurityProof } from '../../core/remediation_security_proof.js';

describe('remediation security impact claim boundary', () => {
  const verification = { outcome: 'VERIFIED', evidenceId: 'ev-1', evidenceHash: 'hash-1' };
  const before = [{ id: 'old', pathKey: 'internet>workload>rds', nodes: [{ id: 'internet', type: 'NETWORK', findingIds: ['f-1'] }, { id: 'rds', type: 'RDS', findingIds: ['f-1'] }], edges: [{ fromResourceId: 'internet', toResourceId: 'rds', relationship: 'REACHES' }] }];
  const lineage = { baselineScanId: 'scan-before', freshScanId: 'scan-after' };
  it('never treats the current graph as a completed after-state', () => {
    const proof = deriveRemediationSecurityProof({ remediationId: 'rem-1', executionId: 'exec-1', findingId: 'f-1', ...lineage, controlEvidenceId: 'ev-control', controlEvidenceHash: 'control-hash', verification, beforePaths: before, afterPaths: [], afterComplete: false });
    expect(proof.pathImpactClaimed).toBe(false); expect(proof.risk.comparable).toBe(false); expect(proof.risk.delta).toBeNull(); expect(proof.claimSafe).toBe(false);
  });
  it('only emits a security reduction claim with complete fresh reanalysis lineage', () => {
    const proof = deriveRemediationSecurityProof({ remediationId: 'rem-1', executionId: 'exec-1', findingId: 'f-1', ...lineage, controlEvidenceId: 'ev-control', controlEvidenceHash: 'control-hash', reanalysisEvidenceId: 'ev-reanalysis', reanalysisEvidenceHash: 'reanalysis-hash', verification, beforePaths: before, afterPaths: [], afterComplete: true, riskBefore: { score: 100 }, riskAfter: { score: 50 }, reanalysisEventId: 'evt-1' });
    expect(proof.pathImpactClaimed).toBe(true); expect(proof.risk.comparable).toBe(true); expect(proof.risk.delta).toBe(-50); expect(proof.proofComplete).toBe(true); expect(proof.claimSafe).toBe(true);
  });
});
