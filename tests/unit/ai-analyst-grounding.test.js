import { describe, expect, it } from 'vitest';
import { buildAnalystContext } from '../../core/ai_analyst.js';

describe('AI analyst deterministic grounding', () => {
  it('exposes remediation proof as advisory evidence without granting compromise claims', () => {
    const context = buildAnalystContext({
      findings: [{ id: 'f1', code: 'S3_PUBLIC_ACCESS', resource_id: 'bucket-a', control_id: 'CC6.1', severity: 'HIGH', status: 'FAIL' }],
      paths: [],
      evidence: [{ id: 'e1', control_id: 'S3_PUBLIC_ACCESS', provider: 'aws', resource_id: 'bucket-a', source_type: 'remediation_reanalysis_scan', evidence_hash: 'hash' }],
      remediationProofs: [{ remediationId: 'r1', findingId: 'f1', baselineScanId: 'scan-old', freshScanId: 'scan-new', controlEvidenceId: 'control-e1', controlEvidenceHash: 'control-hash', reanalysisEvidenceId: 'e1', reanalysisEvidenceHash: 'hash', afterComplete: true, riskBefore: { score: 75 }, riskAfter: { score: 25 }, pathRemoved: 1, pathAdded: 0, claimSafe: true }]
    });
    expect(context.remediationProofs[0].freshScanId).toBe('scan-new');
    expect(context.remediationProofs[0].claimSafe).toBe(true);
    expect(context.risk.compromiseConfirmed).toBe(false);
  });

  it('rejects a proof that tries to reuse one evidence row as both verification stages', () => {
    const context = buildAnalystContext({
      remediationProofs: [{ remediationId: 'r1', findingId: 'f1', baselineScanId: 'scan-old', freshScanId: 'scan-new', controlEvidenceId: 'e1', controlEvidenceHash: 'hash', reanalysisEvidenceId: 'e1', reanalysisEvidenceHash: 'hash', afterComplete: true, claimSafe: true }]
    });
    expect(context.remediationProofs[0].claimSafe).toBe(false);
  });

  it('does not promote legacy alias fields into independent control evidence', () => {
    const context = buildAnalystContext({
      remediationProofs: [{ remediationId: 'r1', findingId: 'f1', baselineScanId: 'scan-old', freshScanId: 'scan-new', evidenceId: 'e1', evidenceHash: 'hash', reanalysisEvidenceId: 'e1', reanalysisEvidenceHash: 'hash', afterComplete: true, claimSafe: true }]
    });
    expect(context.remediationProofs[0].controlEvidenceId).toBe('');
    expect(context.remediationProofs[0].claimSafe).toBe(false);
  });
});
