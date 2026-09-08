import { getRemediationPolicy, REMEDIATION_AUTHORITY } from './remediation_policy.js';
import { getRemediationBreakpointDefinition } from './remediation_breakpoints.js';

export const EXECUTABLE_REMEDIATION_TYPES = Object.freeze({
  S3_PUBLIC_ACCESS: 'S3 Bucket', S3_VERSIONING_DISABLED: 'S3 Bucket', S3_ENCRYPTION_DISABLED: 'S3 Bucket', S3_LIFECYCLE_MISSING: 'S3 Bucket',
  SG_OPEN_SSH_WORLD: 'Security Group', SG_OPEN_RDP_WORLD: 'Security Group', SG_OPEN_HTTP_WORLD: 'Security Group',
  RDS_PUBLICLY_ACCESSIBLE: 'RDS Database', RDS_BACKUP_DISABLED: 'RDS Database',
  IAM_WILDCARD_PERMISSION: 'IAM Role', IAM_ROOT_KEYS: 'IAM Root Credentials',
  EC2_IMDSV1_ENABLED: 'EC2 Instance', EIP_UNASSOCIATED: 'Elastic IP', KMS_KEY_ROTATION_DISABLED: 'KMS Key',
  DYNAMODB_PITR_DISABLED: 'DynamoDB Table', CLOUDTRAIL_LOG_VALIDATION_DISABLED: 'CloudTrail Trail',
  CLOUDTRAIL_NOT_MULTI_REGION: 'CloudTrail Trail', GUARDDUTY_DISABLED: 'GuardDuty Detector', APIGATEWAY_XRAY_DISABLED: 'API Gateway Stage',
  AZURE_STORAGE_PUBLIC_BLOB: 'Azure Storage', AZURE_SQL_PUBLIC_ACCESS: 'Azure SQL', AZURE_APPSERVICE_HTTP_ALLOWED: 'Azure App Service', AZURE_NSG_OPEN_INBOUND: 'Azure NSG'
});

function normalize(value, max = 1000) { return String(value ?? '').trim().slice(0, max); }

/**
 * Security boundary for mutation semantics. A provider must receive the exact
 * canonical action associated with the finding code; free-form issue text cannot
 * select or alter the mutation. Approval authority is checked separately at the
 * approval boundary, but this contract also rejects non-executable authority.
 */
export function validateRemediationExecutionContract({ code, resourceType, action } = {}) {
  const normalizedCode = normalize(code, 64).toUpperCase();
  const policy = getRemediationPolicy(normalizedCode);
  const candidate = getRemediationBreakpointDefinition(normalizedCode);
  if (!candidate) throw new Error('REMEDIATION_CANDIDATE_UNDEFINED');
  const expectedType = EXECUTABLE_REMEDIATION_TYPES[normalizedCode];
  if (!expectedType) throw new Error('REMEDIATION_EXECUTION_UNSUPPORTED');
  if (normalize(resourceType, 128) !== expectedType) throw new Error('REMEDIATION_RESOURCE_TYPE_MISMATCH');
  if (normalize(action) !== candidate.action) throw new Error('REMEDIATION_ACTION_MISMATCH');
  if (policy.authority === REMEDIATION_AUTHORITY.OBSERVE || policy.authority === REMEDIATION_AUTHORITY.RECOMMEND) {
    throw new Error('REMEDIATION_EXECUTION_NOT_AUTHORIZED');
  }
  return Object.freeze({ code: normalizedCode, resourceType: expectedType, action: candidate.action, rationale: candidate.rationale, authority: policy.authority, reversible: policy.reversible, blastRadius: policy.blastRadius });
}
