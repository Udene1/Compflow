export const REMEDIATION_AUTHORITY = Object.freeze({ OBSERVE: 'OBSERVE', RECOMMEND: 'RECOMMEND', SAFE_AUTO: 'SAFE_AUTO', APPROVAL_REQUIRED: 'APPROVAL_REQUIRED', HIGH_IMPACT_APPROVAL: 'HIGH_IMPACT_APPROVAL' });

const POLICIES = Object.freeze({
  S3_PUBLIC_ACCESS: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  S3_VERSIONING_DISABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  S3_ENCRYPTION_DISABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'MEDIUM' },
  S3_LIFECYCLE_MISSING: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'MEDIUM' },
  SG_OPEN_SSH_WORLD: { authority: 'HIGH_IMPACT_APPROVAL', reversible: true, blastRadius: 'HIGH' },
  SG_OPEN_RDP_WORLD: { authority: 'HIGH_IMPACT_APPROVAL', reversible: true, blastRadius: 'HIGH' },
  SG_OPEN_HTTP_WORLD: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'MEDIUM' },
  RDS_PUBLICLY_ACCESSIBLE: { authority: 'HIGH_IMPACT_APPROVAL', reversible: true, blastRadius: 'HIGH' },
  RDS_BACKUP_DISABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  DYNAMODB_PITR_DISABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  KMS_KEY_ROTATION_DISABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  EC2_IMDSV1_ENABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'MEDIUM' },
  EIP_UNASSOCIATED: { authority: 'HIGH_IMPACT_APPROVAL', reversible: false, blastRadius: 'HIGH' },
  CLOUDTRAIL_LOG_VALIDATION_DISABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  CLOUDTRAIL_NOT_MULTI_REGION: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  GUARDDUTY_DISABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  APIGATEWAY_XRAY_DISABLED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  IAM_WILDCARD_PERMISSION: { authority: 'HIGH_IMPACT_APPROVAL', reversible: true, blastRadius: 'HIGH' },
  IAM_ROOT_KEYS: { authority: 'HIGH_IMPACT_APPROVAL', reversible: true, blastRadius: 'HIGH' },
  AZURE_STORAGE_PUBLIC_BLOB: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'LOW' },
  AZURE_SQL_PUBLIC_ACCESS: { authority: 'HIGH_IMPACT_APPROVAL', reversible: true, blastRadius: 'HIGH' },
  AZURE_APPSERVICE_HTTP_ALLOWED: { authority: 'APPROVAL_REQUIRED', reversible: true, blastRadius: 'MEDIUM' },
  AZURE_NSG_OPEN_INBOUND: { authority: 'HIGH_IMPACT_APPROVAL', reversible: true, blastRadius: 'HIGH' }
});

export function getRemediationPolicy(code) {
  const normalized = String(code || '').trim().toUpperCase();
  const policy = POLICIES[normalized];
  if (!policy) throw new Error('REMEDIATION_POLICY_UNDEFINED');
  return Object.freeze({ code: normalized, ...policy });
}

export function listRemediationPolicies() {
  return Object.entries(POLICIES).map(([code, policy]) => ({ code, ...policy }));
}

/**
 * Approval is a security boundary. High-impact mutations require an admin/owner
 * approval; ordinary remediation may be approved by an engineer or above.
 */
export function canApproveRemediation({ code, role } = {}) {
  const policy = getRemediationPolicy(code);
  const normalizedRole = String(role || '').trim().toUpperCase();
  if (policy.authority === REMEDIATION_AUTHORITY.HIGH_IMPACT_APPROVAL) {
    return normalizedRole === 'ADMIN' || normalizedRole === 'OWNER';
  }
  return normalizedRole === 'ENGINEER' || normalizedRole === 'ADMIN' || normalizedRole === 'OWNER';
}
