import { describe, it, expect } from 'vitest';
import { exposurePathCriticality, scoreExposurePath } from '../../core/exposure_risk.js';

describe('deterministic exposure risk', () => {
  it('keeps potential paths below the verified-equivalent path score', () => {
    const potential = { status: 'POTENTIAL', severity: 'HIGH', confidence: 0.8, evidenceComplete: true, nodes: [{ type: 'COMPUTE' }, { type: 'RDS' }] };
    const verified = { ...potential, status: 'VERIFIED' };
    expect(scoreExposurePath(verified)).toBeGreaterThan(scoreExposurePath(potential));
  });

  it('uses sensitive terminal resources as a deterministic criticality signal', () => {
    const publicCompute = { status: 'POTENTIAL', severity: 'MEDIUM', confidence: 0.5, evidenceComplete: false, nodes: [{ type: 'COMPUTE' }, { type: 'RESOURCE' }] };
    const dataStore = { ...publicCompute, nodes: [{ type: 'COMPUTE' }, { type: 'RDS' }] };
    expect(exposurePathCriticality(dataStore).sensitivity).toBeGreaterThan(exposurePathCriticality(publicCompute).sensitivity);
    expect(scoreExposurePath(dataStore)).toBeGreaterThan(scoreExposurePath(publicCompute));
  });

  it('uses explicit data classification without overriding deterministic evidence state', () => {
    const restricted = { status: 'POTENTIAL', severity: 'HIGH', confidence: 0.5, evidenceComplete: true, nodes: [{ type: 'RESOURCE', dataClassification: 'RESTRICTED' }] };
    const publicData = { ...restricted, nodes: [{ type: 'RESOURCE', dataClassification: 'PUBLIC' }] };
    expect(exposurePathCriticality(restricted).sensitivity).toBe(4);
    expect(exposurePathCriticality(publicData).sensitivity).toBe(2);
    expect(exposurePathCriticality(restricted).verified).toBe(false);
  });

  it('weights explicit high-impact relationships deterministically', () => {
    const ordinary = { status: 'POTENTIAL', severity: 'HIGH', confidence: 0.8, evidenceComplete: true, nodes: [{ type: 'COMPUTE' }, { type: 'IAM' }], edges: [{ relationship: 'RELATED_TO' }] };
    const privilege = { ...ordinary, edges: [{ relationship: 'ASSUMES_ROLE' }] };
    expect(exposurePathCriticality(privilege).relationshipMultiplier).toBeGreaterThan(exposurePathCriticality(ordinary).relationshipMultiplier);
    expect(scoreExposurePath(privilege)).toBeGreaterThan(scoreExposurePath(ordinary));
  });

  it('never turns incomplete evidence into a verified signal', () => {
    const result = exposurePathCriticality({ status: 'POTENTIAL', confidence: 1, evidenceComplete: false, nodes: [{ type: 'RDS' }] });
    expect(result.verified).toBe(false);
    expect(result.evidenceComplete).toBe(false);
  });
});
