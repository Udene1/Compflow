import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveRemediationBreakpoints, deriveExecutionRemediationBreakpoints } from '../../core/remediation_breakpoints.js';

test('derives a conservative breakpoint only for findings actually on the path', () => {
  const path = {
    id: 'p1', status: 'POTENTIAL', severity: 'HIGH',
    nodes: [
      { resource_id: 'role-a', finding_ids: ['f2'] },
      { resource_id: 'bucket-a', finding_ids: ['f1'] }
    ]
  };
  const breakpoints = deriveRemediationBreakpoints({
    path,
    findings: [
      { id: 'f1', code: 'S3_PUBLIC_ACCESS', resource_id: 'bucket-a', severity: 'HIGH' },
      { id: 'unrelated', code: 'S3_PUBLIC_ACCESS', resource_id: 'other', severity: 'CRITICAL' },
      { id: 'f2', code: 'IAM_WILDCARD_PERMISSION', resource_id: 'role-a', severity: 'CRITICAL' }
    ]
  });
  assert.equal(breakpoints.length, 2);
  assert.deepEqual(breakpoints.map(item => item.findingId), ['f1', 'f2']);
  assert.equal(breakpoints.every(item => item.executed === false && item.verified === false), true);
  assert.equal(breakpoints[1].breaks.includes('PRIVILEGE_ESCALATION'), true);
});

test('unknown finding codes are not given invented remediation', () => {
  const result = deriveExecutionRemediationBreakpoints({
    paths: [{ id: 'p1', nodes: [{ finding_ids: ['f1'] }] }],
    findings: [{ id: 'f1', code: 'MADE_UP_CONTROL', resource_id: 'x', severity: 'HIGH' }]
  });
  assert.deepEqual(result, []);
});
