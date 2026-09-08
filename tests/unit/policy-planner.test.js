import { describe, expect, it } from 'vitest';
import { compilePolicyPlan, validatePolicyPlan } from '../../core/policy_planner.js';

const base = {
  id: 'soc2-baseline',
  version: '1',
  frameworks: ['soc2'],
  mode: 'REMEDIATE',
  rules: [
    { id: 'public-storage', controlId: 'S3_PUBLIC', action: 'REMEDIATE', requiresApproval: true },
    { id: 'encryption', controlId: 'DISK_ENCRYPTION', action: 'EVALUATE' }
  ]
};
const targets = [{ connectionId: 'conn-1', provider: 'aws', resourceId: 'bucket-1' }];

function compile() {
  return compilePolicyPlan({ organizationId: 'org-1', executionId: 'exec-1', policy: base, targets });
}

describe('policy planner', () => {
  it('builds a deterministic dependency graph from policy to verification', () => {
    const first = compile();
    const second = compile();
    expect(first.planHash).toBe(second.planHash);
    expect(first.nodes.map(n => n.id)).toEqual(second.nodes.map(n => n.id));
    expect(first.edges.map(e => e.id)).toEqual(second.edges.map(e => e.id));
    expect(first.counts).toEqual({ nodes: 8, edges: 7, evidence: 2, evaluations: 2, approvals: 1, remediations: 1, verifications: 1 });
    expect(first.nodes.find(n => n.nodeType === 'REMEDIATION')).toBeTruthy();
    expect(first.nodes.find(n => n.nodeType === 'VERIFICATION')).toBeTruthy();
    expect(validatePolicyPlan(first)).toBe(true);
  });

  it('deduplicates evidence collection for the same target and control', () => {
    const plan = compilePolicyPlan({
      organizationId: 'org-1', executionId: 'exec-2',
      policy: { ...base, rules: [base.rules[0], { ...base.rules[0], id: 'public-storage-copy' }] },
      targets
    });
    expect(plan.counts.evidence).toBe(1);
    expect(plan.counts.evaluations).toBe(2);
  });

  it('rejects unknown controls and invalid framework input', () => {
    expect(() => compilePolicyPlan({ organizationId: 'org-1', executionId: 'exec-3', policy: { ...base, rules: [{ id: 'x', controlId: 'DOES_NOT_EXIST' }] }, targets })).toThrow('POLICY_CONTROL_UNKNOWN:DOES_NOT_EXIST');
    expect(() => compilePolicyPlan({ organizationId: 'org-1', executionId: 'exec-3', policy: { ...base, frameworks: ['soc2', 'soc2'] }, targets })).toThrow('POLICY_FRAMEWORKS_INVALID');
  });

  it('does not create remediation nodes in audit mode', () => {
    const plan = compilePolicyPlan({
      organizationId: 'org-1', executionId: 'exec-4',
      policy: { ...base, mode: 'AUDIT' }, targets
    });
    expect(plan.counts.remediations).toBe(0);
    expect(plan.counts.verifications).toBe(0);
    expect(plan.counts.approvals).toBe(0);
    expect(plan.nodes.every(node => !['REMEDIATION', 'VERIFICATION', 'APPROVAL'].includes(node.nodeType))).toBe(true);
  });
});
