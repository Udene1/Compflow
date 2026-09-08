import { describe, expect, it } from 'vitest';
import { canCountAsVerifiedRelationship, normalizeRelationshipProvenance, PROVENANCE_VERSION } from '../../core/exposure_provenance.js';

describe('exposure relationship provenance', () => {
  it('keeps provider-observed verified relationships verifiable only with evidence lineage', () => {
    const provenance = normalizeRelationshipProvenance({ provider: 'aws', evidenceId: 'ev-1', observedAt: '2026-09-09T00:00:00Z', verified: true, confidence: 0.9 });
    expect(provenance.version).toBe(PROVENANCE_VERSION);
    expect(provenance.observed).toBe(true);
    expect(provenance.inferred).toBe(false);
    expect(canCountAsVerifiedRelationship(provenance)).toBe(true);
  });

  it('cannot promote inferred relationships to verified truth', () => {
    const provenance = normalizeRelationshipProvenance({ provider: 'aws', evidenceId: 'ev-1', observedAt: '2026-09-09T00:00:00Z', relationSource: 'correlation', verified: true, confidence: 1 });
    expect(provenance.inferred).toBe(true);
    expect(provenance.verified).toBe(false);
    expect(canCountAsVerifiedRelationship(provenance)).toBe(false);
  });

  it('fails closed when evidence lineage is incomplete', () => {
    const provenance = normalizeRelationshipProvenance({ provider: 'aws', verified: true });
    expect(provenance.verified).toBe(false);
    expect(provenance.observed).toBe(false);
    expect(canCountAsVerifiedRelationship(provenance)).toBe(false);
  });
});
