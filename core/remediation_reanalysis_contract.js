export const REMEDIATION_REANALYSIS_VERSION = 'remediation-reanalysis-v1';

export const REANALYSIS_STAGES = Object.freeze({
  REQUESTED: 'REQUESTED',
  EVIDENCE_COLLECTED: 'EVIDENCE_COLLECTED',
  FINDINGS_REBUILT: 'FINDINGS_REBUILT',
  EXPOSURE_REBUILT: 'EXPOSURE_REBUILT',
  COMPLETED: 'COMPLETED',
  INCOMPLETE: 'INCOMPLETE'
});

function clean(value, max = 256) {
  return String(value ?? '').trim().slice(0, max);
}

function nonEmpty(value) {
  return Boolean(clean(value));
}

/**
 * Contract for the post-remediation reanalysis boundary. A provider mutation or
 * targeted verification is never sufficient to claim graph/risk improvement.
 * Completion requires fresh evidence, deterministic finding reconstruction and
 * a complete exposure-graph rebuild tied to the same execution.
 */
export function validateRemediationReanalysis({
  executionId,
  remediationId,
  evidenceIds = [],
  evidenceCollected = false,
  findingsRebuilt = false,
  exposureRebuilt = false,
  exposureComplete = false,
  reanalysisEventId = null
} = {}) {
  const evidence = [...new Set((Array.isArray(evidenceIds) ? evidenceIds : []).map(id => clean(id, 128)).filter(Boolean))];
  const validExecution = nonEmpty(executionId);
  const validRemediation = nonEmpty(remediationId);
  const complete = Boolean(
    validExecution &&
    validRemediation &&
    evidenceCollected &&
    evidence.length > 0 &&
    findingsRebuilt &&
    exposureRebuilt &&
    exposureComplete &&
    nonEmpty(reanalysisEventId)
  );

  let stage = REANALYSIS_STAGES.REQUESTED;
  if (evidenceCollected && evidence.length > 0) stage = REANALYSIS_STAGES.EVIDENCE_COLLECTED;
  if (findingsRebuilt) stage = REANALYSIS_STAGES.FINDINGS_REBUILT;
  if (exposureRebuilt) stage = REANALYSIS_STAGES.EXPOSURE_REBUILT;
  if (complete) stage = REANALYSIS_STAGES.COMPLETED;
  else if (!validExecution || !validRemediation) stage = REANALYSIS_STAGES.INCOMPLETE;

  return Object.freeze({
    version: REMEDIATION_REANALYSIS_VERSION,
    executionId: validExecution ? clean(executionId) : null,
    remediationId: validRemediation ? clean(remediationId) : null,
    evidenceIds: evidence,
    evidenceCollected: Boolean(evidenceCollected && evidence.length > 0),
    findingsRebuilt: Boolean(findingsRebuilt),
    exposureRebuilt: Boolean(exposureRebuilt),
    exposureComplete: Boolean(exposureComplete),
    reanalysisEventId: nonEmpty(reanalysisEventId) ? clean(reanalysisEventId, 128) : null,
    stage,
    complete,
    claimSafe: complete,
    reason: complete
      ? 'Fresh evidence, deterministic findings, and a complete exposure graph are tied to an auditable reanalysis event.'
      : 'Reanalysis is incomplete; Compflow must not claim that an exposure path or aggregate risk was reduced.'
  });
}

export function canClaimSecurityReduction(reanalysis) {
  return Boolean(
    reanalysis?.version === REMEDIATION_REANALYSIS_VERSION &&
    reanalysis.complete === true &&
    reanalysis.claimSafe === true &&
    reanalysis.exposureComplete === true &&
    Array.isArray(reanalysis.evidenceIds) &&
    reanalysis.evidenceIds.length > 0 &&
    reanalysis.findingsRebuilt === true &&
    reanalysis.exposureRebuilt === true &&
    reanalysis.reanalysisEventId
  );
}
