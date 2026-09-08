import test from 'node:test';
import assert from 'node:assert/strict';
import { getRemediationPolicy, listRemediationPolicies } from '../../core/remediation_policy.js';

test('high-impact network and database changes require explicit high-impact approval', () => {
  assert.equal(getRemediationPolicy('SG_OPEN_SSH_WORLD').authority, 'HIGH_IMPACT_APPROVAL');
  assert.equal(getRemediationPolicy('RDS_PUBLICLY_ACCESSIBLE').authority, 'HIGH_IMPACT_APPROVAL');
});

test('policy exposes blast radius and reversibility', () => {
  const policy = getRemediationPolicy('S3_PUBLIC_ACCESS');
  assert.equal(policy.blastRadius, 'LOW');
  assert.equal(policy.reversible, true);
});

test('unsupported remediation codes fail closed', () => {
  assert.throws(() => getRemediationPolicy('MADE_UP_REMEDIATION'), /REMEDIATION_POLICY_UNDEFINED/);
});

test('policy catalog is deterministic and non-empty', () => {
  const policies = listRemediationPolicies();
  assert.ok(policies.length >= 10);
  assert.equal(new Set(policies.map(policy => policy.code)).size, policies.length);
});
