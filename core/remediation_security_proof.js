import { compareExposurePathSets } from './remediation_path_diff.js';

/**
 * Produces a conservative, serializable proof record from independently observed
 * remediation stages. It never infers a path/risk reduction from a successful
 * provider mutation alone.
 */
export function deriveRemediationSecurityProof({
  remediationId,
  executionId,
  findingId,
  evidenceId = null,
  evidenceHash = null,
  verification = null,
  beforePaths = [],
  afterPaths = [],
  afterComplete = false,
  riskBefore = null,
  riskAfter = null,
  reanalysisEventId = null
} = {}) {
  const diff = compareExposurePathSets({ before: beforePaths, after: afterPaths, afterComplete });
  const controlVerified = verification?.outcome === 'VERIFIED';
  const riskComparable = Boolean(
    diff.complete &&
    controlVerified &&
    Number.isFinite(Number(riskBefore?.score)) &&
    Number.isFinite(Number(riskAfter?.score))
  );
  const riskDelta = riskComparable ? Number(riskAfter.score) - Number(riskBefore.score) : null;
  const pathImpactClaimed = controlVerified && diff.complete && diff.removed.length > 0;
  const measurableReduction = pathImpactClaimed || (riskComparable && riskDelta < 0);
  const proofComplete = Boolean(
    remediationId && executionId && findingId && evidenceId && evidenceHash &&
    controlVerified && reanalysisEventId && diff.complete
  );
  return {
    version: 'remediation-security-proof-v1',
    remediationId: remediationId || null,
    executionId: executionId || null,
    findingId: findingId || null,
    evidence: evidenceId ? { id: evidenceId, hash: evidenceHash || null } : null,
    verification: verification || null,
    reanalysisEventId: reanalysisEventId || null,
    pathDiff: {
      complete: diff.complete,
      removedCount: diff.removed.length,
      unchangedCount: diff.unchanged.length,
      addedCount: diff.added.length,
      claimSafe: diff.claimSafe
    },
    pathImpactClaimed,
    risk: {
      comparable: riskComparable,
      beforeScore: riskComparable ? Number(riskBefore.score) : null,
      afterScore: riskComparable ? Number(riskAfter.score) : null,
      delta: riskDelta
    },
    proofComplete,
    claimSafe: proofComplete && measurableReduction,
    reason: !diff.complete
      ? 'Fresh exposure analysis is incomplete; no path removal or risk delta is claimed.'
      : !controlVerified
        ? 'The targeted control is not verified from fresh provider evidence; no security reduction is claimed.'
        : !proofComplete
          ? 'Verification exists, but the complete evidence and reanalysis lineage required for an auditable security-effect claim is incomplete.'
          : !measurableReduction
            ? 'Verification and reanalysis are complete, but no measurable exposure-path removal or aggregate-risk reduction was demonstrated.'
            : 'Security-effect claims are grounded in fresh evidence, verification, complete exposure reanalysis, and explicit lineage.'
  };
}
