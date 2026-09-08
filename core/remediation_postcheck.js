import { getProvider } from './provider_registry.js';
import { recordEvidence } from './evidence.js';
import { appendExecutionEvent } from './execution_events.js';
import { stableUsageId, upsertGraphNode, startNodeAttempt, finishNodeAttempt } from './execution_engine.js';

function clean(value, max = 256) { return String(value ?? '').slice(0, max); }
function resourceMatches(resource, resourceId) {
  const target = clean(resourceId);
  return [resource?.id, resource?.name, resource?.technicalId, resource?.resourceId, resource?.arn].some(value => clean(value) === target);
}

/**
 * Collects fresh provider state after a successful remediation.
 * This is intentionally a real provider scan: no synthetic success state is created.
 */
export async function collectRemediationPostcheck({ organizationId, executionId, remediationId, provider, credentials, connectionId, resourceId, code, region = null }) {
  if (!organizationId || !executionId || !remediationId || !provider || !credentials || !connectionId || !resourceId || !code) {
    throw new Error('REMEDIATION_POSTCHECK_INPUT_INVALID');
  }

  const definition = getProvider(provider);
  const node = await upsertGraphNode({
    organizationId,
    executionId,
    nodeType: 'REMEDIATION_POSTCHECK',
    logicalKey: remediationId,
    status: 'PENDING',
    label: `Post-remediation verification — ${resourceId}`,
    metadata: { provider: definition.id, connectionId, remediationId, findingCode: code, resourceId }
  });
  const attempt = await startNodeAttempt({
    organizationId,
    executionId,
    nodeId: node.id,
    metadata: { provider: definition.id, connectionId, remediationId, findingCode: code, resourceId }
  });
  await appendExecutionEvent({
    organizationId, executionId, nodeId: node.id, attemptId: attempt.id,
    eventType: 'REMEDIATION_POSTCHECK_STARTED', actorType: 'SYSTEM', result: 'started',
    payload: { remediationId, provider: definition.id, findingCode: code, resourceId }
  });

  try {
    const { runScan } = await definition.scan();
    const scanCredentials = { ...credentials, ...(region ? { region: credentials.region || region } : {}) };
    const result = await runScan(definition.id, scanCredentials);
    const resources = Array.isArray(result?.resources) ? result.resources : [];
    const matches = resources.filter(resource => resourceMatches(resource, resourceId));

    if (matches.length === 0) {
      await finishNodeAttempt({ attemptId: attempt.id, status: 'FAILED', errorCode: 'POSTCHECK_RESOURCE_NOT_OBSERVED' });
      await appendExecutionEvent({
        organizationId, executionId, nodeId: node.id, attemptId: attempt.id,
        eventType: 'REMEDIATION_POSTCHECK_FINISHED', actorType: 'SYSTEM', result: 'inconclusive',
        payload: { remediationId, findingCode: code, resourceId, observedResources: resources.length, evidenceRecorded: 0 }
      });
      return { status: 'INCONCLUSIVE', evidence: [], observedResources: resources.length };
    }

    const evidence = [];
    for (const resource of matches.slice(0, 10)) {
      const resourceKey = clean(resource.id || resource.name || resource.technicalId || resourceId);
      const evidenceRow = await recordEvidence({
        organizationId,
        executionId,
        nodeId: node.id,
        attemptId: attempt.id,
        controlId: code,
        provider: definition.id,
        connectionId,
        resourceId: resourceKey,
        sourceType: 'post_remediation_scan',
        sourceRef: remediationId,
        evidenceKind: 'post_remediation_observation',
        observedAt: new Date().toISOString(),
        evidence: { resource }
      });
      evidence.push({ id: evidenceRow.id, resourceId: evidenceRow.resource_id, collectedAt: evidenceRow.collected_at, evidenceHash: evidenceRow.evidence_hash });
    }

    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED', metadata: { evidenceCount: evidence.length } });
    await appendExecutionEvent({
      organizationId, executionId, nodeId: node.id, attemptId: attempt.id,
      eventType: 'REMEDIATION_POSTCHECK_FINISHED', actorType: 'SYSTEM', result: 'success',
      payload: { remediationId, findingCode: code, resourceId, observedResources: resources.length, evidenceRecorded: evidence.length }
    });
    return { status: 'COLLECTED', evidence, observedResources: resources.length };
  } catch (error) {
    await finishNodeAttempt({ attemptId: attempt.id, status: 'FAILED', errorCode: clean(error.code || 'POSTCHECK_FAILED'), errorMessage: clean(error.message, 500) }).catch(() => {});
    await appendExecutionEvent({
      organizationId, executionId, nodeId: node.id, attemptId: attempt.id,
      eventType: 'REMEDIATION_POSTCHECK_FINISHED', actorType: 'SYSTEM', result: 'failed',
      payload: { remediationId, findingCode: code, resourceId, error: clean(error.message, 500) }
    }).catch(() => {});
    throw error;
  }
}
