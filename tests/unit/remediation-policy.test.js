import { describe, expect, it } from 'vitest';
import { getRemediationPolicy, listRemediationPolicies, canApproveRemediation } from '../../core/remediation_policy.js';

describe('remediation authority policy', () => {
  it('requires explicit high-impact approval for network and database changes', () => {
    expect(getRemediationPolicy('SG_OPEN_SSH_WORLD').authority).toBe('HIGH_IMPACT_APPROVAL');
    expect(getRemediationPolicy('RDS_PUBLICLY_ACCESSIBLE').authority).toBe('HIGH_IMPACT_APPROVAL');
  });

  it('exposes blast radius and reversibility', () => {
    expect(getRemediationPolicy('S3_PUBLIC_ACCESS').blastRadius).toBe('LOW');
    expect(getRemediationPolicy('S3_PUBLIC_ACCESS').reversible).toBe(true);
  });

  it('fails closed for unsupported remediation codes', () => {
    expect(() => getRemediationPolicy('MADE_UP_REMEDIATION')).toThrow(/REMEDIATION_POLICY_UNDEFINED/);
  });

  it('requires admin or owner approval for high-impact mutations', () => {
    expect(canApproveRemediation({ code: 'SG_OPEN_SSH_WORLD', role: 'ENGINEER' })).toBe(false);
    expect(canApproveRemediation({ code: 'SG_OPEN_SSH_WORLD', role: 'ADMIN' })).toBe(true);
    expect(canApproveRemediation({ code: 'RDS_PUBLICLY_ACCESSIBLE', role: 'OWNER' })).toBe(true);
  });

  it('allows engineer approval for ordinary bounded remediation', () => {
    expect(canApproveRemediation({ code: 'S3_PUBLIC_ACCESS', role: 'ENGINEER' })).toBe(true);
  });

  it('returns a deterministic non-empty policy catalog', () => {
    const policies = listRemediationPolicies();
    expect(policies.length).toBeGreaterThanOrEqual(10);
    expect(new Set(policies.map((policy) => policy.code)).size).toBe(policies.length);
  });
});
