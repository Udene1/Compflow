import { describe, expect, it } from 'vitest';
import { canClaimSecurityReduction, REANALYSIS_STAGES, validateRemediationReanalysis } from '../../core/remediation_reanalysis_contract.js';

describe('remediation reanalysis contract', () => {
  it('does not claim security reduction before complete fresh reanalysis', () => {
    const result = validateRemediationReanalysis({
      executionId: 'exec-1', remediationId: 'rem-1',
      evidenceIds: ['ev-1'], evidenceCollected: true,
      findingsRebuilt: true, exposureRebuilt: false,
      exposureComplete: false
    });
    expect(result.stage).toBe(REANALYSIS_STAGES.FINDINGS_REBUILT);
    expect(result.complete).toBe(false);
    expect(result.claimSafe).toBe(false);
    expect(canClaimSecurityReduction(result)).toBe(false);
  });

  it('requires an evidence lineage and a complete exposure rebuild', () => {
    const missingEvidence = validateRemediationReanalysis({
      executionId: 'exec-1', remediationId: 'rem-1',
      evidenceCollected: true, findingsRebuilt: true,
      exposureRebuilt: true, exposureComplete: true,
      reanalysisEventId: 'event-1'
    });
    expect(missingEvidence.complete).toBe(false);
    expect(canClaimSecurityReduction(missingEvidence)).toBe(false);
  });

  it('allows a security-effect claim only after every required stage is complete', () => {
    const result = validateRemediationReanalysis({
      executionId: 'exec-1', remediationId: 'rem-1',
      evidenceIds: ['ev-1', 'ev-2'], evidenceCollected: true,
      findingsRebuilt: true, exposureRebuilt: true,
      exposureComplete: true, reanalysisEventId: 'event-1'
    });
    expect(result.stage).toBe(REANALYSIS_STAGES.COMPLETED);
    expect(result.complete).toBe(true);
    expect(result.claimSafe).toBe(true);
    expect(canClaimSecurityReduction(result)).toBe(true);
  });

  it('fails closed for missing execution or remediation identity', () => {
    const result = validateRemediationReanalysis({
      evidenceIds: ['ev-1'], evidenceCollected: true,
      findingsRebuilt: true, exposureRebuilt: true,
      exposureComplete: true, reanalysisEventId: 'event-1'
    });
    expect(result.stage).toBe(REANALYSIS_STAGES.INCOMPLETE);
    expect(result.complete).toBe(false);
    expect(canClaimSecurityReduction(result)).toBe(false);
  });
});
