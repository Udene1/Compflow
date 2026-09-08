import { describe, expect, it } from 'vitest';
import crypto from 'crypto';
import { deriveRemediationSecurityEffect } from '../../core/remediation_security_effect.js';

function evidence(value) {
  return { evidence: value, evidence_hash: crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex') };
}

describe('remediation security effect', () => {
  it('does not claim risk reduction before verification', () => {
    const result = deriveRemediationSecurityEffect({ code: 'S3_PUBLIC_ACCESS', remediationState: 'VERIFICATION_PENDING', affectedPathCount: 2 });
    expect(result.status).toBe('NOT_VERIFIED');
    expect(result.pathImpactClaimed).toBe(false);
    expect(result.riskDeltaClaimed).toBe(false);
  });

  it('accepts verified fresh control evidence without claiming path reduction', () => {
    const result = deriveRemediationSecurityEffect({
      code: 'S3_PUBLIC_ACCESS',
      remediationState: 'VERIFIED',
      affectedPathCount: 1,
      evidence: evidence({ PublicAccess: false, PublicAccessBlockConfiguration: { BlockPublicPolicy: true, RestrictPublicBuckets: true } })
    });
    expect(result.status).toBe('CONTROL_VERIFIED');
    expect(result.verified).toBe(true);
    expect(result.pathImpactClaimed).toBe(false);
    expect(result.riskDeltaClaimed).toBe(false);
  });

  it('fails closed when evidence integrity does not match', () => {
    const result = deriveRemediationSecurityEffect({
      code: 'S3_PUBLIC_ACCESS',
      remediationState: 'VERIFIED',
      evidence: { evidence: { PublicAccess: false }, evidence_hash: 'invalid' }
    });
    expect(result.status).toBe('INTEGRITY_FAILURE');
    expect(result.verified).toBe(false);
  });
});
