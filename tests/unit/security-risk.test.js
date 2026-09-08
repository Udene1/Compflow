import { describe, expect, it } from 'vitest';
import { deriveWeaknesses, aggregateSecurityRisk } from '../../core/security_risk.js';

describe('deterministic security risk', () => {
  it('groups the same underlying weakness across affected resources', () => {
    const weaknesses = deriveWeaknesses([
      { id: 'f1', code: 'S3_PUBLIC_ACCESS', control_id: 'C1', resource_id: 'bucket-a', severity: 'HIGH' },
      { id: 'f2', code: 'S3_PUBLIC_ACCESS', control_id: 'C1', resource_id: 'bucket-a', severity: 'CRITICAL' },
      { id: 'f3', code: 'S3_PUBLIC_ACCESS', control_id: 'C1', resource_id: 'bucket-b', severity: 'HIGH' }
    ]);
    expect(weaknesses).toHaveLength(1);
    expect(weaknesses[0].findingCount).toBe(3);
    expect(weaknesses[0].affectedResourceCount).toBe(2);
    expect(weaknesses[0].resourceIds.sort()).toEqual(['bucket-a', 'bucket-b']);
    expect(weaknesses[0].severity).toBe('CRITICAL');
    expect(weaknesses[0].findingIds.sort()).toEqual(['f1', 'f2', 'f3']);
  });

  it('risk aggregation links paths to weaknesses without claiming compromise', () => {
    const result = aggregateSecurityRisk({
      findings: [
        { id: 'f1', code: 'S3_PUBLIC_ACCESS', control_id: 'C1', resource_id: 'bucket-a', severity: 'HIGH' },
        { id: 'f2', code: 'IAM_WILDCARD_PERMISSION', control_id: 'C2', resource_id: 'role-a', severity: 'CRITICAL' }
      ],
      paths: [{
        id: 'p1', title: 'Workload → IAM → S3', status: 'POTENTIAL', severity: 'HIGH', confidence: 0.75, evidence_complete: true,
        nodes: [
          { resource_id: 'workload-a', finding_ids: [], evidence_ids: ['e1'] },
          { resource_id: 'role-a', finding_ids: ['f2'], evidence_ids: ['e2'] },
          { resource_id: 'bucket-a', finding_ids: ['f1'], evidence_ids: ['e3'] }
        ]
      }]
    });
    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.pathCount).toBe(1);
    expect(result.weaknessCount).toBe(2);
    expect(result.correlatedFindingCount).toBe(2);
    expect(result.paths[0].weaknessIds).toHaveLength(2);
    expect(result.compromiseConfirmed).toBe(false);
  });

  it('unrelated findings do not become path correlations', () => {
    const result = aggregateSecurityRisk({
      findings: [{ id: 'unrelated', code: 'RDS_PUBLICLY_ACCESSIBLE', control_id: 'C9', resource_id: 'db-9', severity: 'HIGH' }],
      paths: [{ id: 'p1', status: 'POTENTIAL', severity: 'MEDIUM', confidence: 0.5, nodes: [{ resource_id: 'bucket-a', finding_ids: [] }] }]
    });
    expect(result.paths[0].weaknessIds).toHaveLength(0);
    expect(result.correlatedFindingCount).toBe(0);
  });
});
