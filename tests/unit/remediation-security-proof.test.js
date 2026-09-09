import { describe, expect, it } from 'vitest';
import { deriveRemediationSecurityProof } from '../../core/remediation_security_proof.js';

const before = [{ path_key: 'internet->workload->s3', nodes: [{ resource_id: 'bucket-1', type: 'S3', finding_ids: ['finding-1'] }], edges: [] }];
const after = [];
const verified = { outcome: 'VERIFIED', reason: 'fresh provider evidence verified the control' };

describe('remediation security proof', () => {
  it('refuses path and risk claims when reanalysis is incomplete', () => {
    const proof = deriveRemediationSecurityProof({ remediationId: 'r1', executionId: 'e1', findingId: 'finding-1', evidenceId: 'ev-control', evidenceHash: 'control-hash', verification: verified, beforePaths: before, afterPaths: after, afterComplete: false, riskBefore: { score: 100 }, riskAfter: { score: 25 }, reanalysisEventId: null });
    expect(proof.pathImpactClaimed).toBe(false); expect(proof.risk.delta).toBeNull(); expect(proof.claimSafe).toBe(false);
  });
  it('only claims path removal after complete fresh analysis with dual lineage', () => {
    const proof = deriveRemediationSecurityProof({ remediationId: 'r1', executionId: 'e1', findingId: 'finding-1', controlEvidenceId: 'ev-control', controlEvidenceHash: 'control-hash', reanalysisEvidenceId: 'ev-reanalysis', reanalysisEvidenceHash: 'reanalysis-hash', verification: verified, beforePaths: before, afterPaths: after, afterComplete: true, riskBefore: { score: 100 }, riskAfter: { score: 25 }, reanalysisEventId: 'event-1' });
    expect(proof.pathDiff.removedCount).toBe(1); expect(proof.pathImpactClaimed).toBe(true); expect(proof.risk.delta).toBe(-75); expect(proof.proofComplete).toBe(true); expect(proof.claimSafe).toBe(true);
  });
  it('does not claim security reduction when provider verification fails', () => {
    const proof = deriveRemediationSecurityProof({ remediationId: 'r1', executionId: 'e1', findingId: 'finding-1', controlEvidenceId: 'ev-control', controlEvidenceHash: 'control-hash', reanalysisEvidenceId: 'ev-reanalysis', reanalysisEvidenceHash: 'reanalysis-hash', verification: { outcome: 'VERIFICATION_FAILED' }, beforePaths: before, afterPaths: [], afterComplete: true, riskBefore: { score: 100 }, riskAfter: { score: 25 }, reanalysisEventId: 'event-1' });
    expect(proof.pathImpactClaimed).toBe(false); expect(proof.risk.delta).toBeNull(); expect(proof.claimSafe).toBe(false);
  });
});
