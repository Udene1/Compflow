const PROVENANCE_VERSION = 'relationship-provenance-v1';
const MAX_SOURCE_REF = 512;

function clean(value, max = 255) { return String(value ?? '').trim().slice(0, max); }

/**
 * Normalizes relationship provenance without upgrading inferred/correlated data
 * into observed truth. `verified` can only remain true when the source evidence
 * is explicitly identified and the relationship itself was provider-observed.
 */
export function normalizeRelationshipProvenance({
  provider,
  evidenceId,
  observedAt,
  sourceRef = null,
  relationSource = 'provider_observation',
  verified = false,
  confidence = 0
} = {}) {
  const source = clean(relationSource, 64).toLowerCase();
  const providerName = clean(provider, 64).toLowerCase();
  const evidence = clean(evidenceId, 128);
  const observationTime = clean(observedAt, 64);
  const sourceReference = clean(sourceRef, MAX_SOURCE_REF);
  const providerObserved = source === 'provider_observation';
  const hasEvidenceLineage = Boolean(evidence && observationTime && providerName);
  const normalizedConfidence = Math.max(0, Math.min(1, Number(confidence) || 0));
  return Object.freeze({
    version: PROVENANCE_VERSION,
    provider: providerName || null,
    evidenceId: evidence || null,
    observedAt: observationTime || null,
    sourceRef: sourceReference || null,
    source: source || 'provider_observation',
    verified: Boolean(verified) && providerObserved && hasEvidenceLineage,
    observed: providerObserved && hasEvidenceLineage,
    inferred: !providerObserved,
    confidence: normalizedConfidence
  });
}

export function canCountAsVerifiedRelationship(provenance) {
  return Boolean(
    provenance?.version === PROVENANCE_VERSION &&
    provenance?.observed === true &&
    provenance?.inferred === false &&
    provenance?.verified === true &&
    provenance?.evidenceId &&
    provenance?.observedAt &&
    provenance?.provider
  );
}

export { PROVENANCE_VERSION };
