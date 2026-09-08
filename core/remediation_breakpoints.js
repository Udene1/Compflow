const RULES = Object.freeze({
  S3_PUBLIC_ACCESS: {
    action: 'Remove public bucket access and require authenticated access.',
    rationale: 'The finding marks the storage resource as publicly exposed.',
    breaks: ['PUBLIC_ACCESS']
  },
  AZURE_STORAGE_PUBLIC_BLOB: {
    action: 'Disable anonymous blob access and require authenticated requests.',
    rationale: 'The finding marks blob storage as anonymously reachable.',
    breaks: ['PUBLIC_ACCESS']
  },
  RDS_PUBLICLY_ACCESSIBLE: {
    action: 'Disable public database accessibility and restrict inbound network access.',
    rationale: 'The finding marks the database as publicly reachable.',
    breaks: ['PUBLIC_ACCESS']
  },
  AZURE_SQL_PUBLIC_ACCESS: {
    action: 'Disable public SQL access and restrict the database firewall.',
    rationale: 'The finding marks the database endpoint as publicly reachable.',
    breaks: ['PUBLIC_ACCESS']
  },
  SG_OPEN_SSH_WORLD: {
    action: 'Restrict SSH ingress to an approved administrative network.',
    rationale: 'The finding permits SSH from the public internet.',
    breaks: ['PUBLIC_INGRESS']
  },
  SG_OPEN_RDP_WORLD: {
    action: 'Restrict RDP ingress to an approved administrative network.',
    rationale: 'The finding permits RDP from the public internet.',
    breaks: ['PUBLIC_INGRESS']
  },
  SG_OPEN_HTTP_WORLD: {
    action: 'Restrict or terminate unnecessary public HTTP ingress.',
    rationale: 'The finding permits HTTP from the public internet.',
    breaks: ['PUBLIC_INGRESS']
  },
  AZURE_NSG_OPEN_INBOUND: {
    action: 'Restrict the NSG inbound rule to the minimum required sources and ports.',
    rationale: 'The finding permits broader inbound network access than required.',
    breaks: ['PUBLIC_INGRESS']
  },
  IAM_WILDCARD_PERMISSION: {
    action: 'Replace wildcard IAM permissions with the smallest required actions and resources.',
    rationale: 'The finding indicates excessive privilege that can amplify a reachable workload.',
    breaks: ['PRIVILEGE_ESCALATION']
  },
  IAM_ROOT_KEYS: {
    action: 'Remove long-lived root credentials and use scoped workload or administrative identities.',
    rationale: 'The finding indicates credentials with unnecessarily broad authority.',
    breaks: ['PRIVILEGE_ESCALATION']
  }
});

function findingIdsForPath(path) {
  return new Set((path?.nodes || []).flatMap(node => Array.isArray(node.finding_ids)
    ? node.finding_ids
    : Array.isArray(node.findingIds) ? node.findingIds : []));
}

function normalizeFinding(finding) {
  return {
    id: String(finding?.id || '').trim(),
    code: String(finding?.code || '').trim().toUpperCase(),
    resourceId: String(finding?.resource_id || finding?.resourceId || '').trim(),
    severity: String(finding?.severity || 'LOW').trim().toUpperCase()
  };
}

/**
 * Produces conservative remediation candidates for a deterministic path.
 * It never executes a change and never claims that a path is already broken.
 */
export function deriveRemediationBreakpoints({ path, findings = [] } = {}) {
  const pathFindingIds = findingIdsForPath(path);
  return findings.map(normalizeFinding)
    .filter(finding => finding.id && pathFindingIds.has(finding.id) && RULES[finding.code])
    .map(finding => ({
      id: `breakpoint:${finding.id}`,
      findingId: finding.id,
      code: finding.code,
      resourceId: finding.resourceId,
      severity: finding.severity,
      action: RULES[finding.code].action,
      rationale: RULES[finding.code].rationale,
      breaks: RULES[finding.code].breaks,
      executed: false,
      verified: false
    }));
}

export function deriveExecutionRemediationBreakpoints({ paths = [], findings = [] } = {}) {
  return paths.flatMap(path => deriveRemediationBreakpoints({ path, findings }).map(breakpoint => ({
    ...breakpoint,
    pathId: path.id,
    pathStatus: path.status,
    pathSeverity: path.severity
  })));
}
