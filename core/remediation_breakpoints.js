import { getRemediationPolicy } from './remediation_policy.js';

const RULES = Object.freeze({
  S3_PUBLIC_ACCESS: { action: 'Remove public bucket access and require authenticated access.', rationale: 'The finding marks the storage resource as publicly exposed.', breaks: ['PUBLIC_ACCESS'] },
  S3_VERSIONING_DISABLED: { action: 'Enable object versioning on the storage bucket.', rationale: 'Versioning improves recovery from accidental or malicious object changes.', breaks: ['DATA_RECOVERY'] },
  S3_ENCRYPTION_DISABLED: { action: 'Enable default encryption for new objects in the storage bucket.', rationale: 'Default encryption protects newly written objects at rest.', breaks: ['DATA_EXPOSURE'] },
  S3_LIFECYCLE_MISSING: { action: 'Apply a bounded lifecycle policy for incomplete multipart uploads.', rationale: 'A bounded lifecycle policy reduces abandoned storage exposure and cost.', breaks: ['STORAGE_HYGIENE'] },
  AZURE_STORAGE_PUBLIC_BLOB: { action: 'Disable anonymous blob access and require authenticated requests.', rationale: 'The finding marks blob storage as anonymously reachable.', breaks: ['PUBLIC_ACCESS'] },
  RDS_PUBLICLY_ACCESSIBLE: { action: 'Disable public database accessibility and restrict inbound network access.', rationale: 'The finding marks the database as publicly reachable.', breaks: ['PUBLIC_ACCESS'] },
  RDS_BACKUP_DISABLED: { action: 'Increase database backup retention to the minimum approved recovery window.', rationale: 'Adequate retention provides recoverability after destructive events.', breaks: ['DATA_RECOVERY'] },
  AZURE_SQL_PUBLIC_ACCESS: { action: 'Disable public SQL access and restrict the database firewall.', rationale: 'The finding marks the database endpoint as publicly reachable.', breaks: ['PUBLIC_ACCESS'] },
  AZURE_APPSERVICE_HTTP_ALLOWED: { action: 'Enforce HTTPS-only traffic for the App Service.', rationale: 'HTTPS-only prevents cleartext application traffic.', breaks: ['CLEAR_TEXT_TRANSPORT'] },
  SG_OPEN_SSH_WORLD: { action: 'Restrict SSH ingress to an approved administrative network.', rationale: 'The finding permits SSH from the public internet.', breaks: ['PUBLIC_INGRESS'] },
  SG_OPEN_RDP_WORLD: { action: 'Restrict RDP ingress to an approved administrative network.', rationale: 'The finding permits RDP from the public internet.', breaks: ['PUBLIC_INGRESS'] },
  SG_OPEN_HTTP_WORLD: { action: 'Restrict or terminate unnecessary public HTTP ingress.', rationale: 'The finding permits HTTP from the public internet.', breaks: ['PUBLIC_INGRESS'] },
  AZURE_NSG_OPEN_INBOUND: { action: 'Restrict the NSG inbound rule to the minimum required sources and ports.', rationale: 'The finding permits broader inbound network access than required.', breaks: ['PUBLIC_INGRESS'] },
  IAM_WILDCARD_PERMISSION: { action: 'Replace wildcard IAM permissions with the smallest required actions and resources.', rationale: 'The finding indicates excessive privilege that can amplify a reachable workload.', breaks: ['PRIVILEGE_ESCALATION'] },
  IAM_ROOT_KEYS: { action: 'Remove long-lived root credentials and use scoped workload or administrative identities.', rationale: 'The finding indicates credentials with unnecessarily broad authority.', breaks: ['PRIVILEGE_ESCALATION'] },
  EC2_IMDSV1_ENABLED: { action: 'Require IMDSv2 for the EC2 instance metadata service.', rationale: 'Requiring session-oriented metadata access reduces credential exposure risk.', breaks: ['CREDENTIAL_EXPOSURE'] },
  EIP_UNASSOCIATED: { action: 'Release the unassociated Elastic IP after confirming it has no attachment.', rationale: 'An unused public address is unnecessary external attack surface.', breaks: ['PUBLIC_ATTACK_SURFACE'] },
  KMS_KEY_ROTATION_DISABLED: { action: 'Enable automatic rotation for the KMS key.', rationale: 'Automatic rotation reduces long-lived key material exposure.', breaks: ['KEY_LIFECYCLE'] },
  DYNAMODB_PITR_DISABLED: { action: 'Enable point-in-time recovery for the DynamoDB table.', rationale: 'PITR provides durable recovery from destructive data changes.', breaks: ['DATA_RECOVERY'] },
  CLOUDTRAIL_LOG_VALIDATION_DISABLED: { action: 'Enable CloudTrail log file validation.', rationale: 'Log validation provides integrity evidence for audit records.', breaks: ['AUDIT_INTEGRITY'] },
  CLOUDTRAIL_NOT_MULTI_REGION: { action: 'Enable the CloudTrail trail as a multi-region trail.', rationale: 'Multi-region coverage reduces audit blind spots.', breaks: ['AUDIT_BLIND_SPOT'] },
  GUARDDUTY_DISABLED: { action: 'Enable the GuardDuty detector in the target region.', rationale: 'Threat detection should be active for the monitored account and region.', breaks: ['DETECTION_GAP'] },
  APIGATEWAY_XRAY_DISABLED: { action: 'Enable tracing for the API Gateway stage.', rationale: 'Tracing improves request-level security observability.', breaks: ['OBSERVABILITY_GAP'] }
});

function findingIdsForPath(path) { return new Set((path?.nodes || []).flatMap(node => Array.isArray(node.finding_ids) ? node.finding_ids : Array.isArray(node.findingIds) ? node.findingIds : [])); }
function normalizeFinding(finding) { return { id: String(finding?.id || '').trim(), code: String(finding?.code || '').trim().toUpperCase(), resourceId: String(finding?.resource_id || finding?.resourceId || '').trim(), severity: String(finding?.severity || 'LOW').trim().toUpperCase() }; }

export function deriveRemediationBreakpoints({ path, findings = [] } = {}) {
  const pathFindingIds = findingIdsForPath(path);
  return findings.map(normalizeFinding).filter(finding => finding.id && pathFindingIds.has(finding.id) && RULES[finding.code] && (() => { try { getRemediationPolicy(finding.code); return true; } catch { return false; } })()).map(finding => {
    const policy = getRemediationPolicy(finding.code);
    return { id: `breakpoint:${finding.id}`, findingId: finding.id, code: finding.code, resourceId: finding.resourceId, severity: finding.severity, action: RULES[finding.code].action, rationale: RULES[finding.code].rationale, breaks: RULES[finding.code].breaks, authority: policy.authority, reversible: policy.reversible, blastRadius: policy.blastRadius, executed: false, verified: false };
  });
}

export function deriveExecutionRemediationBreakpoints({ paths = [], findings = [] } = {}) {
  return paths.flatMap(path => deriveRemediationBreakpoints({ path, findings }).map(breakpoint => ({ ...breakpoint, pathId: path.id, pathStatus: path.status, pathSeverity: path.severity })));
}
