import { describe, expect, it } from 'vitest';
import { evaluateFreshEvidence } from '../../core/remediation_verification.js';

describe('deterministic remediation verification', () => {
  it('S3 public-access remediation verifies from explicit fresh evidence', () => {
    const result = evaluateFreshEvidence({
      code: 'S3_PUBLIC_ACCESS',
      evidence: { PublicAccess: false, PublicAccessBlockConfiguration: { BlockPublicPolicy: true, RestrictPublicBuckets: true } }
    });
    expect(result.outcome).toBe('VERIFIED');
  });

  it('public database remediation verifies only from an explicit false state', () => {
    expect(evaluateFreshEvidence({ code: 'RDS_PUBLICLY_ACCESSIBLE', evidence: { PubliclyAccessible: false } }).outcome).toBe('VERIFIED');
    expect(evaluateFreshEvidence({ code: 'RDS_PUBLICLY_ACCESSIBLE', evidence: { endpoint: 'db.example' } }).outcome).toBe('INCONCLUSIVE');
  });

  it('world-open ingress remains failed when fresh evidence still contains it', () => {
    const result = evaluateFreshEvidence({ code: 'SG_OPEN_SSH_WORLD', evidence: { IpPermissions: [{ CidrIp: '0.0.0.0/0', FromPort: 22, ToPort: 22 }] } });
    expect(result.outcome).toBe('VERIFICATION_FAILED');
  });

  it('unknown evidence never becomes a false verification', () => {
    const result = evaluateFreshEvidence({ code: 'UNKNOWN_CODE', evidence: { healthy: true } });
    expect(result.outcome).toBe('INCONCLUSIVE');
  });
});
