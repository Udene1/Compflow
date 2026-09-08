import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateFreshEvidence } from '../../core/remediation_verification.js';

test('S3 public-access remediation verifies from explicit fresh evidence', () => {
  const result = evaluateFreshEvidence({
    code: 'S3_PUBLIC_ACCESS',
    evidence: { PublicAccess: false, PublicAccessBlockConfiguration: { BlockPublicPolicy: true, RestrictPublicBuckets: true } }
  });
  assert.equal(result.outcome, 'VERIFIED');
});

test('public database remediation verifies only from an explicit false state', () => {
  assert.equal(evaluateFreshEvidence({ code: 'RDS_PUBLICLY_ACCESSIBLE', evidence: { PubliclyAccessible: false } }).outcome, 'VERIFIED');
  assert.equal(evaluateFreshEvidence({ code: 'RDS_PUBLICLY_ACCESSIBLE', evidence: { endpoint: 'db.example' } }).outcome, 'INCONCLUSIVE');
});

test('world-open ingress remains failed when fresh evidence still contains it', () => {
  const result = evaluateFreshEvidence({ code: 'SG_OPEN_SSH_WORLD', evidence: { IpPermissions: [{ CidrIp: '0.0.0.0/0', FromPort: 22, ToPort: 22 }] } });
  assert.equal(result.outcome, 'VERIFICATION_FAILED');
});

test('unknown evidence never becomes a false verification', () => {
  const result = evaluateFreshEvidence({ code: 'UNKNOWN_CODE', evidence: { healthy: true } });
  assert.equal(result.outcome, 'INCONCLUSIVE');
});
