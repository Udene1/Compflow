import {
  ensureExecutionGraph,
  upsertGraphNode,
  addDependencyEdge,
  startNodeAttempt,
  finishNodeAttempt
} from './execution_engine.js';

function safeSeverity(resource) {
  const value = String(resource?.severity || resource?.status || '').toLowerCase();
  return value || 'unknown';
}

export async function beginExecution({ organizationId, executionId, provider, clientId, jobId }) {
  await ensureExecutionGraph();
  const node = await upsertGraphNode({
    organizationId,
    executionId,
    nodeType: 'EXECUTION',
    logicalKey: executionId,
    status: 'RUNNING',
    label: `${String(provider).toUpperCase()} scan`,
    metadata: { provider, clientId, jobId: jobId || null }
  });
  const attempt = await startNodeAttempt({
    organizationId,
    executionId,
    nodeId: node.id,
    metadata: { provider, clientId, jobId: jobId || null }
  });

  const audit = await upsertGraphNode({
    organizationId,
    executionId,
    nodeType: 'AUDIT',
    logicalKey: `execution:${executionId}`,
    status: 'PENDING',
    label: 'Execution audit trail',
    metadata: { provider, executionId }
  });
  await addDependencyEdge({
    organizationId,
    executionId,
    fromNodeId: node.id,
    toNodeId: audit.id,
    edgeType: 'DEPENDS_ON'
  });

  return { node, attempt, audit };
}

export async function persistScanGraph({ organizationId, executionId, provider, resources = [] }) {
  for (const resource of resources) {
    const severity = safeSeverity(resource);
    const observationFailed = severity === 'error' || severity === 'failed';
    const observationKey = `${resource.technicalId || resource.type || 'resource'}:${resource.id || resource.name || 'unknown'}`;

    const observation = await upsertGraphNode({
      organizationId,
      executionId,
      nodeType: 'OBSERVATION',
      logicalKey: observationKey,
      status: observationFailed ? 'FAILED' : 'SUCCEEDED',
      label: resource.name || resource.type || 'Cloud observation',
      metadata: {
        provider,
        technicalId: resource.technicalId || null,
        severity: resource.severity || null,
        status: resource.status || null,
        issue: resource.issue || null
      }
    });

    const observationAttempt = await startNodeAttempt({
      organizationId,
      executionId,
      nodeId: observation.id,
      metadata: { provider }
    });
    await finishNodeAttempt({
      attemptId: observationAttempt.id,
      status: observationFailed ? 'FAILED' : 'SUCCEEDED',
      errorCode: observationFailed ? 'OBSERVATION_ERROR' : null
    });

    const controls = resource.controls || {};
    for (const [frameworkId, controlIds] of Object.entries(controls)) {
      if (!Array.isArray(controlIds)) continue;
      for (const controlId of controlIds) {
        const controlFailed = severity !== 'pass';
        const control = await upsertGraphNode({
          organizationId,
          executionId,
          nodeType: 'CONTROL',
          logicalKey: `${frameworkId}:${controlId}`,
          status: controlFailed ? 'FAILED' : 'SUCCEEDED',
          label: `${String(frameworkId).toUpperCase()} ${controlId}`,
          metadata: { frameworkId, controlId, observationId: observation.id, assessment: controlFailed ? 'FAIL' : 'PASS' }
        });
        await addDependencyEdge({
          organizationId,
          executionId,
          fromNodeId: observation.id,
          toNodeId: control.id,
          edgeType: 'DEPENDS_ON'
        });

        const controlAttempt = await startNodeAttempt({
          organizationId,
          executionId,
          nodeId: control.id,
          metadata: { frameworkId, controlId, observationId: observation.id }
        });
        await finishNodeAttempt({
          attemptId: controlAttempt.id,
          status: controlFailed ? 'FAILED' : 'SUCCEEDED',
          errorCode: controlFailed ? 'CONTROL_ASSESSMENT_FAILED' : null
        });

        const evidence = await upsertGraphNode({
          organizationId,
          executionId,
          nodeType: 'EVIDENCE',
          logicalKey: `${frameworkId}:${controlId}:${observation.id}`,
          status: controlFailed ? 'PENDING' : 'SUCCEEDED',
          label: `Evidence — ${String(frameworkId).toUpperCase()} ${controlId}`,
          metadata: {
            frameworkId,
            controlId,
            observationId: observation.id,
            source: 'cloud_scan',
            collectionStatus: controlFailed ? 'BLOCKED_BY_CONTROL' : 'COLLECTED'
          }
        });
        await addDependencyEdge({
          organizationId,
          executionId,
          fromNodeId: control.id,
          toNodeId: evidence.id,
          edgeType: 'DEPENDS_ON'
        });

        if (controlFailed) {
          const risk = await upsertGraphNode({
            organizationId,
            executionId,
            nodeType: 'RISK',
            logicalKey: `${frameworkId}:${controlId}:${observation.id}`,
            status: 'PENDING',
            label: resource.issue || `Risk — ${String(frameworkId).toUpperCase()} ${controlId}`,
            metadata: {
              frameworkId,
              controlId,
              observationId: observation.id,
              severity: resource.severity || 'unknown',
              issue: resource.issue || null
            }
          });
          await addDependencyEdge({
            organizationId,
            executionId,
            fromNodeId: control.id,
            toNodeId: risk.id,
            edgeType: 'DEPENDS_ON'
          });

          const remediation = await upsertGraphNode({
            organizationId,
            executionId,
            nodeType: 'REMEDIATION',
            logicalKey: `${frameworkId}:${controlId}:${observation.id}`,
            status: 'PENDING',
            label: `Remediation — ${resource.name || controlId}`,
            metadata: {
              frameworkId,
              controlId,
              observationId: observation.id,
              issue: resource.issue || null,
              requiresApproval: true
            }
          });
          await addDependencyEdge({
            organizationId,
            executionId,
            fromNodeId: risk.id,
            toNodeId: remediation.id,
            edgeType: 'DEPENDS_ON'
          });
        }
      }
    }
  }
}

export async function finishExecution(attemptId, status, errorCode = null, errorMessage = null) {
  return finishNodeAttempt({ attemptId, status, errorCode, errorMessage });
}
