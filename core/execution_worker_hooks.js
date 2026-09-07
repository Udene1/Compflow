import {
  ensureExecutionGraph,
  stableUsageId,
  upsertGraphNode,
  addDependencyEdge,
  startNodeAttempt,
  finishNodeAttempt
} from './execution_engine.js';

function safeSeverity(resource) {
  const value = String(resource?.severity || resource?.status || '').toLowerCase();
  return value || 'unknown';
}

async function recordAttempt({ organizationId, executionId, node, metadata, failed, errorCode }) {
  if (['SUCCEEDED', 'SKIPPED'].includes(node.status)) return null;
  const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id, metadata });
  await finishNodeAttempt({
    attemptId: attempt.id,
    status: failed ? 'FAILED' : 'SUCCEEDED',
    errorCode: failed ? errorCode : null
  });
  return attempt;
}

export async function beginExecution({ organizationId, executionId, provider, clientId, jobId, connectionId = null, scanId = null }) {
  await ensureExecutionGraph();
  const node = await upsertGraphNode({
    organizationId, executionId, nodeType: 'EXECUTION', logicalKey: executionId,
    status: 'PENDING', label: `${String(provider).toUpperCase()} scan`,
    metadata: { provider, clientId, jobId: jobId || null, connectionId, scanId }
  });
  const attempt = await startNodeAttempt({
    organizationId, executionId, nodeId: node.id,
    metadata: { provider, clientId, jobId: jobId || null, connectionId, scanId }
  });
  const audit = await upsertGraphNode({
    organizationId, executionId, nodeType: 'AUDIT', logicalKey: `execution:${executionId}`,
    status: 'PENDING', label: 'Execution audit trail', metadata: { provider, executionId }
  });
  await addDependencyEdge({ organizationId, executionId, fromNodeId: node.id, toNodeId: audit.id, edgeType: 'DEPENDS_ON' });
  return { node, attempt, audit };
}

export async function persistScanGraph({ organizationId, executionId, provider, resources = [] }) {
  const executionNodeId = stableUsageId(organizationId, executionId, 'EXECUTION', executionId);

  for (const resource of resources) {
    const severity = safeSeverity(resource);
    const observationFailed = severity === 'error' || severity === 'failed';
    const observationKey = `${resource.technicalId || resource.type || 'resource'}:${resource.id || resource.name || 'unknown'}`;
    const observation = await upsertGraphNode({
      organizationId, executionId, nodeType: 'OBSERVATION', logicalKey: observationKey,
      status: 'PENDING', label: resource.name || resource.type || 'Cloud observation',
      metadata: {
        provider,
        technicalId: resource.technicalId || null,
        severity: resource.severity || null,
        status: resource.status || null,
        issue: resource.issue || null
      }
    });
    await addDependencyEdge({ organizationId, executionId, fromNodeId: executionNodeId, toNodeId: observation.id, edgeType: 'DEPENDS_ON' });
    await recordAttempt({
      organizationId,
      executionId,
      node: observation,
      metadata: { provider },
      failed: observationFailed,
      errorCode: 'OBSERVATION_ERROR'
    });

    const controls = resource.controls || {};
    for (const [frameworkId, controlIds] of Object.entries(controls)) {
      if (!Array.isArray(controlIds)) continue;
      for (const controlId of controlIds) {
        const controlFailed = severity !== 'pass';
        const control = await upsertGraphNode({
          organizationId, executionId, nodeType: 'CONTROL', logicalKey: `${frameworkId}:${controlId}:${observation.id}`,
          status: 'PENDING', label: `${String(frameworkId).toUpperCase()} ${controlId}`,
          metadata: { frameworkId, controlId, observationId: observation.id, assessment: controlFailed ? 'FAIL' : 'PASS' }
        });
        await addDependencyEdge({ organizationId, executionId, fromNodeId: observation.id, toNodeId: control.id, edgeType: 'DEPENDS_ON' });
        await recordAttempt({
          organizationId,
          executionId,
          node: control,
          metadata: { frameworkId, controlId, observationId: observation.id },
          failed: controlFailed,
          errorCode: 'CONTROL_ASSESSMENT_FAILED'
        });

        const evidence = await upsertGraphNode({
          organizationId, executionId, nodeType: 'EVIDENCE', logicalKey: `${frameworkId}:${controlId}:${observation.id}`,
          status: 'PENDING', label: `Evidence — ${String(frameworkId).toUpperCase()} ${controlId}`,
          metadata: { frameworkId, controlId, observationId: observation.id, source: 'cloud_scan', collectionStatus: controlFailed ? 'BLOCKED_BY_CONTROL' : 'PENDING' }
        });
        await addDependencyEdge({ organizationId, executionId, fromNodeId: control.id, toNodeId: evidence.id, edgeType: 'DEPENDS_ON' });
        if (!controlFailed) {
          await recordAttempt({
            organizationId,
            executionId,
            node: evidence,
            metadata: { frameworkId, controlId, observationId: observation.id, source: 'cloud_scan' },
            failed: false,
            errorCode: null
          });
        }

        if (controlFailed) {
          const risk = await upsertGraphNode({
            organizationId, executionId, nodeType: 'RISK', logicalKey: `${frameworkId}:${controlId}:${observation.id}`,
            status: 'PENDING', label: resource.issue || `Risk — ${String(frameworkId).toUpperCase()} ${controlId}`,
            metadata: { frameworkId, controlId, observationId: observation.id, severity: resource.severity || 'unknown', issue: resource.issue || null }
          });
          await addDependencyEdge({ organizationId, executionId, fromNodeId: control.id, toNodeId: risk.id, edgeType: 'DEPENDS_ON' });
          const remediation = await upsertGraphNode({
            organizationId, executionId, nodeType: 'REMEDIATION', logicalKey: `${frameworkId}:${controlId}:${observation.id}`,
            status: 'PENDING', label: `Remediation — ${resource.name || controlId}`,
            metadata: { frameworkId, controlId, observationId: observation.id, issue: resource.issue || null, requiresApproval: true }
          });
          await addDependencyEdge({ organizationId, executionId, fromNodeId: risk.id, toNodeId: remediation.id, edgeType: 'DEPENDS_ON' });
        }
      }
    }
  }
}

export async function finishExecution(attemptId, status, errorCode = null, errorMessage = null) {
  return finishNodeAttempt({ attemptId, status, errorCode, errorMessage });
}
