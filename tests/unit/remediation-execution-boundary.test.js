import { describe, expect, it } from 'vitest';
import { validateRemediationExecutionContract } from '../../core/remediation_execution_contract.js';
import { evaluateFreshEvidence } from '../../core/remediation_verification.js';

describe('remediation execution boundary', () => {
  it('rejects action tampering', () => {
    expect(() => validateRemediationExecutionContract({ code: 'S3_PUBLIC_ACCESS', resourceType: 'S3 Bucket', action: 'Delete every object in the bucket' })).toThrow('REMEDIATION_ACTION_MISMATCH');
  });

  it('rejects resource-type confusion', () => {
    expect(() => validateRemediationExecutionContract({ code: 'S3_PUBLIC_ACCESS', resourceType: 'RDS Database', action: 'Remove public bucket access and require authenticated access.' })).toThrow('REMEDIATION_RESOURCE_TYPE_MISMATCH');
  });

  it('fails closed for incomplete IAM inspection', () => {
    expect(evaluateFreshEvidence({ code: 'IAM_WILDCARD_PERMISSION', evidence: { inspectionComplete: false, policies: [] } })).toEqual({ outcome: 'INCONCLUSIVE', reason: 'Fresh evidence does not prove that all IAM permission policies were inspected.' });
  });

  it('detects wildcard permission from provider evidence', () => {
    expect(evaluateFreshEvidence({ code: 'IAM_WILDCARD_PERMISSION', evidence: { inspectionComplete: true, policyCount: 1, policies: [{ name: 'example', wildcard: true }] } }).outcome).toBe('VERIFICATION_FAILED');
  });

  it('does not turn missing ingress evidence into verification success', () => {
    expect(evaluateFreshEvidence({ code: 'SG_OPEN_SSH_WORLD', evidence: { groupId: 'sg-123' } }).outcome).toBe('INCONCLUSIVE');
  });
});
