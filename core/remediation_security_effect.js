import { getEvidenceFreshness, verifyEvidenceIntegrity } from './evidence.js';
import { evaluateFreshEvidence } from './remediation_verification.js';

export function deriveRemediationSecurityEffect({ code, remediationState, evidence = null, affectedPathCount = 0 } = {}) {
  const normalizedCode = String(code || '').trim().toUpperCase();
  if (remediationState !== 'VERIFIED') {
    return { status: 'NOT_VERIFIED', verified: false, pathImpactClaimed: false, riskDeltaClaimed: false, reason: 'The remediation has not been verified from fresh provider evidence.' };
  }
  if (!evidence) {
    return { status: 'REANALYSIS_REQUIRED', verified: true, pathImpactClaimed: false, riskDeltaClaimed: false, reason: 'Control verification exists, but the latest fresh evidence is unavailable for security-effect attribution.' };
  }
  if (!verifyEvidenceIntegrity(evidence)) {
    return { status: 'INTEGRITY_FAILURE', verified: false, pathImpactClaimed: false, riskDeltaClaimed: false, reason: 'The latest evidence failed integrity verification.' };
  }
  const freshness = getEvidenceFreshness(evidence);
  if (freshness.state === 'STALE' || freshness.state === 'INVALID') {
    return { status: 'REANALYSIS_REQUIRED', verified: false, pathImpactClaimed: false, riskDeltaClaimed: false, freshness: freshness.state, reason: 'Evidence is no longer fresh enough to attribute a security effect.' };
  }
  const evaluation = evaluateFreshEvidence({ code: normalizedCode, evidence: evidence.evidence });
  if (evaluation.outcome !== 'VERIFIED') {
    return { status: 'VERIFICATION_CONFLICT', verified: false, pathImpactClaimed: false, riskDeltaClaimed: false, verificationOutcome: evaluation.outcome, reason: evaluation.reason };
  }
  return {
    status: 'CONTROL_VERIFIED',
    verified: true,
    pathImpactClaimed: false,
    riskDeltaClaimed: false,
    affectedPathCount,
    verificationOutcome: evaluation.outcome,
    freshness: freshness.state,
    reason: 'The targeted control is verified. Fresh exposure-path analysis is still required before claiming that an exposure path or aggregate risk was reduced.'
  };
}
