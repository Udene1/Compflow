import { describe, it, expect } from 'vitest';
import { validateRemediationExecutionContract } from '../../core/remediation_execution_contract.js';
import { getRemediationBreakpointDefinition } from '../../core/remediation_breakpoints.js';
import { compareExposurePathSets, stableExposurePathKey } from '../../core/remediation_path_diff.js';

describe('canonical remediation execution contract', () => {
  it('binds mutation semantics to the deterministic candidate', () => {
    const candidate = getRemediationBreakpointDefinition('S3_PUBLIC_ACCESS');
    expect(validateRemediationExecutionContract({ code: 'S3_PUBLIC_ACCESS', resourceType: 'S3 Bucket', action: candidate.action })).toMatchObject({
      code: 'S3_PUBLIC_ACCESS', authority: 'APPROVAL_REQUIRED', action: candidate.action
    });
  });

  it('rejects action tampering before provider execution', () => {
    expect(() => validateRemediationExecutionContract({ code: 'S3_PUBLIC_ACCESS', resourceType: 'S3 Bucket', action: 'Delete the bucket' })).toThrow('REMEDIATION_ACTION_MISMATCH');
  });

  it('rejects resource-type substitution for a valid finding code', () => {
    const candidate = getRemediationBreakpointDefinition('RDS_PUBLICLY_ACCESSIBLE');
    expect(() => validateRemediationExecutionContract({ code: 'RDS_PUBLICLY_ACCESSIBLE', resourceType: 'S3 Bucket', action: candidate.action })).toThrow('REMEDIATION_RESOURCE_TYPE_MISMATCH');
  });

  it('rejects unsupported finding codes instead of falling back to issue text', () => {
    expect(() => validateRemediationExecutionContract({ code: 'NOT_A_REAL_CODE', resourceType: 'S3 Bucket', action: 'Public access enabled' })).toThrow('REMEDIATION_POLICY_UNDEFINED');
  });
});

describe('conservative exposure path diff', () => {
  const path = { id: 'old-row', pathKey: 'internet>workload>rds', nodes: [
    { id: 'internet', type: 'NETWORK', findingIds: ['f1'] },
    { id: 'workload', type: 'COMPUTE', findingIds: [] },
    { id: 'rds', type: 'RDS', findingIds: ['f2'] }
  ], edges: [{ fromResourceId: 'internet', toResourceId: 'workload', relationship: 'REACHES' }, { fromResourceId: 'workload', toResourceId: 'rds', relationship: 'CONNECTS_TO' }] };

  it('uses graph identity rather than persistence row ids', () => {
    const same = { ...path, id: 'new-row' };
    expect(stableExposurePathKey(path)).toBe(stableExposurePathKey(same));
    expect(compareExposurePathSets({ before: [path], after: [same], afterComplete: true }).unchanged).toHaveLength(1);
  });

  it('does not claim removal when fresh analysis is incomplete', () => {
    const diff = compareExposurePathSets({ before: [path], after: [], afterComplete: false });
    expect(diff.removed).toHaveLength(0);
    expect(diff.claimSafe).toBe(false);
  });

  it('claims removal only after complete fresh analysis', () => {
    const diff = compareExposurePathSets({ before: [path], after: [], afterComplete: true });
    expect(diff.removed).toHaveLength(1);
    expect(diff.claimSafe).toBe(true);
  });
});
