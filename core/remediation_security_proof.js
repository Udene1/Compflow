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
  controlEvidenceId = null,
  controlEvidenceHash = null,
  reanalysisEvidenceId = null,
  reanalysisEvidenceHash = null,
  verification = null,
  baselineScanId = null,
  freshScanId = null,
  beforePaths = [],
  afterPaths = [],
  afterComplete = false,
  riskBefore = null,
  riskAfter = null,
  reanalysisEventId = null
} = {}) {
  const diff = compareExposurePathSets({ before: beforePaths, after: afterPaths, afterComplete });
  const controlVerified = verification?.outcome === 'VERIFIED';
  const normalizedControlEvidenceId = controlEvidenceId || evidenceId;
  const normalizedControlEvidenceHash = controlEvidenceHash || evidenceHash;
  const hasControlEvidence = Boolean(normalizedControlEvidenceId && normalizedControlEvidenceHash);
  const hasReanalysisEvidence = Boolean(reanalysisEvidenceId && reanalysisEvidenceHash);
  const hasFreshScanLineage = Boolean(
    baselineScanId && freshScanId && baselineScanId !== freshScanId
  );
  const riskComparable = Boolean(
    diff.complete &&
    controlVerified &&
    hasFreshScanLineage &&
    Number.isFinite(Number(riskBefore?.score)) &&
    Number.isFinite(Number(riskAfter?.score))
  );
  const riskDelta = riskComparable ? Number(riskAfter.score) - Number(riskBefore.score) : null;
  const pathImpactClaimed = controlVerified && diff.complete && hasFreshScanLineage && diff.removed.length > 0;
  const measurableReduction = pathImpactClaimed || (riskComparable && riskDelta < 0);
  const proofComplete = Boolean(
    remediationId && executionId && findingId &&
    hasControlEvidence && hasReanalysisEvidence &&
    controlVerified && reanalysisEventId && hasFreshScanLineage && diff.complete
  );
  return {
    version: 'remediation-security-proof-v3',
    remediationId: remediationId || null,
    executionId: executionId || null,
    findingId: findingId || null,
    baselineScanId: baselineScanId || null,
    freshScanId: freshScanId || null,
    evidence: hasControlEvidence ? { id: normalizedControlEvidenceId, hash: normalizedControlEvidenceHash } : null,
    controlEvidence: hasControlEvidence ? { id: normalizedControlEvidenceId, hash: normalizedControlEvidenceHash } : null,
    reanalysisEvidence: hasReanalysisEvidence ? { id: reanalysisEvidenceId, hash: reanalysisEvidenceHash } : null,
    verification: verification || null,
    reanalysisEventId: reanalysisEventId || null,
    pathDiff: { complete: diff.complete, removedCount: diff.removed.length, unchangedCount: diff.unchanged.length, addedCount: diff.added.length, claimSafe: diff.claimSafe },
    pathImpactClaimed,
    risk: { comparable: riskComparable, beforeScore: riskComparable ? Number(riskBefore.score) : null, afterScore: riskComparable ? Number(riskAfter.score) : null, delta: riskDelta },
    proofComplete,
    claimSafe: proofComplete && measurableReduction,
    reason: !hasFreshScanLineage
      ? 'A security-effect proof requires explicit distinct baseline and fresh reanalysis scan lineage.'
      : !diff.complete
        ? 'Fresh exposure analysis is incomplete; no path removal or risk delta is claimed.'
        : !controlVerified
          ? 'The targeted control is not verified from fresh provider evidence; no security reduction is claimed.'
          : !hasControlEvidence || !hasReanalysisEvidence
            ? 'Control verification and fresh reanalysis evidence must both be cryptographically linked before a security-effect claim is made.'
            : !proofComplete
              ? 'Verification exists, but the complete evidence and reanalysis lineage required for an auditable security-effect claim is incomplete.'
              : !measurableReduction
                ? 'Verification and reanalysis are complete, but no measurable exposure-path removal or aggregate-risk reduction was demonstrated.'
                : 'Security-effect claims are grounded in fresh control evidence, fresh reanalysis evidence, distinct scan lineage, verification, complete exposure reanalysis, and explicit lineage.'
  };
}
