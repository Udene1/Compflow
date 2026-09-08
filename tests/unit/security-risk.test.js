import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveWeaknesses, aggregateSecurityRisk } from '../../core/security_risk.js';

test('groups duplicate findings into deterministic weaknesses', () => {
  const weaknesses = deriveWeaknesses([
    { id: 'f1', code: 'S3_PUBLIC_ACCESS', control_id: 'C1', resource_id: 'bucket-a', severity: 'HIGH' },
    { id: 'f2', code: 'S3_PUBLIC_ACCESS', control_id: 'C1', resource_id: 'bucket-a', severity: 'CRITICAL' },
    { id: 'f3', code: 'S3_PUBLIC_ACCESS', control_id: 'C1', resource_id: 'bucket-b', severity: 'HIGH' }
  ]);
  assert.equal(weaknesses.length, 2);
  const bucketA = weaknesses.find(item => item.resourceId === 'bucket-a');
  assert.equal(bucketA.findingCount, 2);
  assert.equal(bucketA.severity, 'CRITICAL');
  assert.deepEqual(bucketA.findingIds.sort(), ['f1', 'f2']);
});

test('risk aggregation links paths to weaknesses without claiming compromise', () => {
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
  assert.equal(result.riskLevel, 'CRITICAL');
  assert.equal(result.pathCount, 1);
  assert.equal(result.weaknessCount, 2);
  assert.equal(result.correlatedFindingCount, 2);
  assert.deepEqual(result.paths[0].weaknessIds.length, 2);
  assert.equal(result.compromiseConfirmed, false);
});

test('unrelated findings do not become path correlations', () => {
  const result = aggregateSecurityRisk({
    findings: [{ id: 'unrelated', code: 'RDS_PUBLICLY_ACCESSIBLE', control_id: 'C9', resource_id: 'db-9', severity: 'HIGH' }],
    paths: [{ id: 'p1', status: 'POTENTIAL', severity: 'MEDIUM', confidence: 0.5, nodes: [{ resource_id: 'bucket-a', finding_ids: [] }] }]
  });
  assert.equal(result.paths[0].weaknessIds.length, 0);
  assert.equal(result.correlatedFindingCount, 0);
});
