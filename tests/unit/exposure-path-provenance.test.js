import { describe, expect, it } from 'vitest';
import { analyzeExposurePaths } from '../../core/exposure_paths.js';

const finding = (id, code, resource_id, severity = 'HIGH') => ({ id, code, resource_id, severity });

const evidence = [
  {
    id: 'ev-edge', provider: 'aws', observed_at: '2026-09-09T00:00:00.000Z',
    evidence: { resources: [
      { id: 'public-sg', type: 'Security Group', relationships: [{ from: 'public-sg', to: 'workload', relation: 'ROUTES_TO', verified: true }] },
      { id: 'workload', type: 'EC2 Instance', relationships: [{ from: 'workload', to: 'bucket', relation: 'READS_FROM', verified: true }] },
      { id: 'bucket', type: 'S3 Bucket' }
    ] }
  }
];

describe('exposure relationship provenance', () => {
  it('requires provider-observed lineage before an exposure path can be VERIFIED', () => {
    const paths = analyzeExposurePaths({
      evidenceRows: evidence,
      findingRows: [finding('f1', 'SG_OPEN_HTTP_WORLD', 'public-sg'), finding('f2', 'S3_PUBLIC_ACCESS', 'bucket')]
    });
    expect(paths).toHaveLength(1);
    expect(paths[0].status).toBe('VERIFIED');
    expect(paths[0].edges.every(edge => edge.observed === true)).toBe(true);
    expect(paths[0].edges.every(edge => edge.inferred === false)).toBe(true);
    expect(paths[0].edges.every(edge => edge.evidenceId === 'ev-edge')).toBe(true);
    expect(paths[0].edges.every(edge => edge.version === 'relationship-provenance-v1')).toBe(true);
  });

  it('never upgrades an inferred relationship to VERIFIED', () => {
    const inferredEvidence = [{
      ...evidence[0],
      evidence: { resources: evidence[0].evidence.resources.map(resource => ({
        ...resource,
        relationships: (resource.relationships || []).map(relation => ({ ...relation, relationSource: 'correlation', verified: true }))
      })) }
    }];
    const paths = analyzeExposurePaths({
      evidenceRows: inferredEvidence,
      findingRows: [finding('f1', 'SG_OPEN_HTTP_WORLD', 'public-sg'), finding('f2', 'S3_PUBLIC_ACCESS', 'bucket')]
    });
    expect(paths).toHaveLength(1);
    expect(paths[0].status).toBe('POTENTIAL');
    expect(paths[0].edges.some(edge => edge.inferred === true && edge.verified === false)).toBe(true);
  });
});
