import { describe, expect, it } from 'vitest';
import { analyzeExposurePaths } from '../../core/exposure_paths.js';

describe('evidence-backed exposure paths', () => {
  it('finds a potential path from an exposed workload to a sensitive resource', () => {
    const findingRows = [
      { id: 'finding-edge', resource_id: 'internet-edge', code: 'SG_OPEN_HTTP_WORLD', severity: 'HIGH' },
      { id: 'finding-bucket', resource_id: 'customer-data', code: 'S3_ENCRYPTION_DISABLED', severity: 'CRITICAL' }
    ];
    const evidenceRows = [
      { id: 'evidence-edge', provider: 'aws', observed_at: '2026-09-09T00:00:00.000Z', source_ref: 'scan-1', evidence: { resources: [{ id: 'internet-edge', type: 'EC2', name: 'web' }], relationships: [{ fromResourceId: 'internet-edge', toResourceId: 'customer-data', type: 'CAN_ACCESS', verified: false }] } },
      { id: 'evidence-data', provider: 'aws', observed_at: '2026-09-09T00:00:00.000Z', source_ref: 'scan-1', evidence: { resources: [{ id: 'customer-data', type: 'S3', name: 'customer-data' }] } }
    ];
    const paths = analyzeExposurePaths({ findingRows, evidenceRows });
    expect(paths).toHaveLength(1);
    expect(paths[0].status).toBe('POTENTIAL');
    expect(paths[0].evidenceComplete).toBe(true);
    expect(paths[0].severity).toBe('CRITICAL');
    expect(paths[0].nodes.map(node => node.id)).toEqual(['internet-edge', 'customer-data']);
    expect(paths[0].edges[0].relationship).toBe('CAN_ACCESS');
    expect(paths[0].summary).toContain('not a claim of compromise');
  });

  it('does not invent a path when no evidence-backed relationship exists', () => {
    const paths = analyzeExposurePaths({
      findingRows: [
        { id: 'finding-edge', resource_id: 'web', code: 'SG_OPEN_HTTP_WORLD', severity: 'HIGH' },
        { id: 'finding-data', resource_id: 'bucket', code: 'S3_PUBLIC_ACCESS', severity: 'HIGH' }
      ],
      evidenceRows: [
        { id: 'evidence-web', evidence: { resources: [{ id: 'web', type: 'EC2' }] } },
        { id: 'evidence-bucket', evidence: { resources: [{ id: 'bucket', type: 'S3' }] } }
      ]
    });
    expect(paths).toEqual([]);
  });

  it('marks a fully verified relationship as verified only when provenance has evidence lineage', () => {
    const paths = analyzeExposurePaths({
      findingRows: [{ id: 'finding-edge', resource_id: 'edge', code: 'SG_OPEN_HTTP_WORLD', severity: 'HIGH' }],
      evidenceRows: [{ id: 'e1', provider: 'aws', observed_at: '2026-09-09T00:00:00.000Z', source_ref: 'scan-1', evidence: { resources: [{ id: 'edge', type: 'EC2' }, { id: 'db', type: 'RDS' }], relationships: [{ fromResourceId: 'edge', toResourceId: 'db', type: 'CAN_REACH', status: 'verified' }] } }]
    });
    const pathsWithoutLineage = analyzeExposurePaths({
      findingRows: [{ id: 'finding-edge', resource_id: 'edge', code: 'SG_OPEN_HTTP_WORLD', severity: 'HIGH' }],
      evidenceRows: [{ id: 'e1', evidence: { resources: [{ id: 'edge', type: 'EC2' }, { id: 'db', type: 'RDS' }], relationships: [{ fromResourceId: 'edge', toResourceId: 'db', type: 'CAN_REACH', status: 'verified' }] } }]
    });
    expect(paths).toHaveLength(1);
    expect(paths[0].status).toBe('VERIFIED');
    expect(paths[0].confidence).toBe(1);
    expect(pathsWithoutLineage[0].status).toBe('POTENTIAL');
  });
});
