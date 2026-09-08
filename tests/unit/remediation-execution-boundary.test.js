import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRemediationExecutionContract } from '../../core/remediation_execution_contract.js';
import { evaluateFreshEvidence } from '../../core/remediation_verification.js';

test('remediation execution rejects action tampering', () => {
  assert.throws(
    () => validateRemediationExecutionContract({
      code: 'S3_PUBLIC_ACCESS',
      resourceType: 'S3 Bucket',
      action: 'Delete every object in the bucket'
    }),
    /REMEDIATION_ACTION_MISMATCH/
  );
});

test('remediation execution rejects resource-type confusion', () => {
  assert.throws(
    () => validateRemediationExecutionContract({
      code: 'S3_PUBLIC_ACCESS',
      resourceType: 'RDS Database',
      action: 'Remove public bucket access and require authenticated access.'
    }),
    /REMEDIATION_RESOURCE_TYPE_MISMATCH/
  );
});

test('fresh IAM verification fails closed without complete inspection', () => {
  assert.deepEqual(
    evaluateFreshEvidence({
      code: 'IAM_WILDCARD_PERMISSION',
      evidence: { inspectionComplete: false, policies: [] }
    }),
    {
      outcome: 'INCONCLUSIVE',
      reason: 'Fresh evidence does not prove that all IAM permission policies were inspected.'
    }
  );
});

test('fresh IAM verification detects wildcard permission from provider evidence', () => {
  const result = evaluateFreshEvidence({
    code: 'IAM_WILDCARD_PERMISSION',
    evidence: {
      inspectionComplete: true,
      policyCount: 1,
      policies: [{ name: 'example', wildcard: true }]
    }
  });
  assert.equal(result.outcome, 'VERIFICATION_FAILED');
});

test('fresh network verification cannot turn missing ingress evidence into success', () => {
  assert.equal(
    evaluateFreshEvidence({ code: 'SG_OPEN_SSH_WORLD', evidence: { groupId: 'sg-123' } }).outcome,
    'INCONCLUSIVE'
  );
});
