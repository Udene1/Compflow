import { describe, expect, it } from 'vitest';
import { deriveRemediationBreakpoints, deriveExecutionRemediationBreakpoints } from '../../core/remediation_breakpoints.js';

describe('deterministic remediation breakpoints', () => {
  it('derives a conservative breakpoint only for findings actually on the path', () => {
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
    expect(breakpoints).toHaveLength(2);
    expect(breakpoints.map(item => item.findingId)).toEqual(['f1', 'f2']);
    expect(breakpoints.every(item => item.executed === false && item.verified === false)).toBe(true);
    expect(breakpoints[1].breaks).toContain('PRIVILEGE_ESCALATION');
  });

  it('unknown finding codes are not given invented remediation', () => {
    const result = deriveExecutionRemediationBreakpoints({
      paths: [{ id: 'p1', nodes: [{ finding_ids: ['f1'] }] }],
      findings: [{ id: 'f1', code: 'MADE_UP_CONTROL', resource_id: 'x', severity: 'HIGH' }]
    });
    expect(result).toEqual([]);
  });
});
