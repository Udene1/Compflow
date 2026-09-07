import {
  ensureExecutionGraph,
  upsertGraphNode,
  addDependencyEdge,
  startNodeAttempt,
  finishNodeAttempt
} from './execution_engine.js';

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
  return { node, attempt };
}

export async function persistScanGraph({ organizationId, executionId, provider, resources = [] }) {
  for (const resource of resources) {
    const observation = await upsertGraphNode({
      organizationId,
      executionId,
      nodeType: 'OBSERVATION',
      logicalKey: `${resource.technicalId || resource.type || 'resource'}:${resource.id || resource.name || 'unknown'}`,
      status: resource.severity === 'error' || resource.status === 'ERROR' ? 'FAILED' : 'SUCCEEDED',
      label: resource.name || resource.type || 'Cloud observation',
      metadata: {
        provider,
        technicalId: resource.technicalId || null,
        severity: resource.severity || null,
        status: resource.status || null
      }
    });

    const observationAttempt = await startNodeAttempt({
      organizationId,
      executionId,
      nodeId: observation.id,
      metadata: { provider }
    });
    const observationFailed = resource.severity === 'error' || resource.status === 'ERROR';
    await finishNodeAttempt({
      attemptId: observationAttempt.id,
      status: observationFailed ? 'FAILED' : 'SUCCEEDED',
      errorCode: observationFailed ? 'OBSERVATION_ERROR' : null
    });

    const controls = resource.controls || {};
    for (const [frameworkId, controlIds] of Object.entries(controls)) {
      if (!Array.isArray(controlIds)) continue;
      for (const controlId of controlIds) {
        const control = await upsertGraphNode({
          organizationId,
          executionId,
          nodeType: 'CONTROL',
          logicalKey: `${frameworkId}:${controlId}`,
          status: resource.severity === 'pass' ? 'SUCCEEDED' : 'FAILED',
          label: `${String(frameworkId).toUpperCase()} ${controlId}`,
          metadata: { frameworkId, controlId }
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
        const controlFailed = resource.severity !== 'pass';
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
          status: observationFailed ? 'FAILED' : 'SUCCEEDED',
          label: `Evidence — ${String(frameworkId).toUpperCase()} ${controlId}`,
          metadata: { frameworkId, controlId, observationId: observation.id, source: 'cloud_scan' }
        });
        await addDependencyEdge({
          organizationId,
          executionId,
          fromNodeId: control.id,
          toNodeId: evidence.id,
          edgeType: 'DEPENDS_ON'
        });
      }
    }
  }
}

export async function finishExecution(attemptId, status, errorCode = null, errorMessage = null) {
  return finishNodeAttempt({ attemptId, status, errorCode, errorMessage });
}
