/**
 * ComplianceFlow AI — Standardized Structured Finding Codes
 * 
 * Canonical enum of finding codes across all cloud providers.
 * Replaces fragile free-text string matching with deterministic codes.
 */

export const FINDING_CODES = {
    // S3 Storage
    S3_PUBLIC_ACCESS: 'S3_PUBLIC_ACCESS',
    S3_VERSIONING_DISABLED: 'S3_VERSIONING_DISABLED',
    S3_ENCRYPTION_DISABLED: 'S3_ENCRYPTION_DISABLED',
    S3_LIFECYCLE_MISSING: 'S3_LIFECYCLE_MISSING',

    // Network & Security Groups
    SG_OPEN_SSH_WORLD: 'SG_OPEN_SSH_WORLD',
    SG_OPEN_RDP_WORLD: 'SG_OPEN_RDP_WORLD',
    SG_OPEN_HTTP_WORLD: 'SG_OPEN_HTTP_WORLD',
    SG_UNUSED: 'SG_UNUSED',
    AZURE_NSG_OPEN_INBOUND: 'AZURE_NSG_OPEN_INBOUND',

    // IAM & Access Management
    IAM_ROOT_KEYS: 'IAM_ROOT_KEYS',
    IAM_ROOT_MFA_DISABLED: 'IAM_ROOT_MFA_DISABLED',
    IAM_USER_MFA_DISABLED: 'IAM_USER_MFA_DISABLED',
    IAM_STALE_ACCESS: 'IAM_STALE_ACCESS',
    IAM_WILDCARD_PERMISSION: 'IAM_WILDCARD_PERMISSION',

    // Databases & Compute
    RDS_PUBLICLY_ACCESSIBLE: 'RDS_PUBLICLY_ACCESSIBLE',
    RDS_BACKUP_DISABLED: 'RDS_BACKUP_DISABLED',
    RDS_UNENCRYPTED: 'RDS_UNENCRYPTED',
    DYNAMODB_PITR_DISABLED: 'DYNAMODB_PITR_DISABLED',
    EC2_IMDSV1_ENABLED: 'EC2_IMDSV1_ENABLED',
    EIP_UNASSOCIATED: 'EIP_UNASSOCIATED',

    // Logging & Observability
    CLOUDTRAIL_NOT_MULTI_REGION: 'CLOUDTRAIL_NOT_MULTI_REGION',
    CLOUDTRAIL_LOG_VALIDATION_DISABLED: 'CLOUDTRAIL_LOG_VALIDATION_DISABLED',
    CLOUDWATCH_LOG_RETENTION_SHORT: 'CLOUDWATCH_LOG_RETENTION_SHORT',
    APIGATEWAY_XRAY_DISABLED: 'APIGATEWAY_XRAY_DISABLED',
    KMS_KEY_ROTATION_DISABLED: 'KMS_KEY_ROTATION_DISABLED',
    GUARDDUTY_DISABLED: 'GUARDDUTY_DISABLED',

    // Azure Specific
    AZURE_STORAGE_PUBLIC_BLOB: 'AZURE_STORAGE_PUBLIC_BLOB',
    AZURE_STORAGE_HTTP_ALLOWED: 'AZURE_STORAGE_HTTP_ALLOWED',
    AZURE_APPSERVICE_HTTP_ALLOWED: 'AZURE_APPSERVICE_HTTP_ALLOWED',
    AZURE_APPSERVICE_TLS_OLD: 'AZURE_APPSERVICE_TLS_OLD',
    AZURE_KEYVAULT_NO_SOFTDELETE: 'AZURE_KEYVAULT_NO_SOFTDELETE',
    AZURE_SQL_PUBLIC_ACCESS: 'AZURE_SQL_PUBLIC_ACCESS',

    // Custom Organization Policies
    ORG_POLICY_DISALLOWED_REGION: 'ORG_POLICY_DISALLOWED_REGION',
    ORG_POLICY_MISSING_TAGS: 'ORG_POLICY_MISSING_TAGS',
    ORG_POLICY_DISALLOWED_PORT: 'ORG_POLICY_DISALLOWED_PORT',
    ORG_POLICY_MANDATORY_BACKUPS: 'ORG_POLICY_MANDATORY_BACKUPS',

    // Generic / Fallback
    GENERIC_ADVISORY: 'GENERIC_ADVISORY'
};

/**
 * Resolves a finding to a canonical finding code based on resource type, issue text, or technical ID.
 * Provides backwards compatibility for legacy scanners while supporting structured codes.
 * 
 * @param {string} resourceType - Resource type (e.g. 'S3 Bucket', 'Security Group')
 * @param {string} issueText - Human readable issue text
 * @param {string} [technicalId] - Optional technical ID if already present
 * @returns {string} Standardized finding code
 */
export function resolveFindingCode(resourceType, issueText = '', technicalId = null) {
    if (technicalId && Object.values(FINDING_CODES).includes(technicalId)) {
        return technicalId;
    }

    const type = (resourceType || '').toLowerCase();
    const issue = (issueText || '').toLowerCase();

    // S3
    if (type.includes('s3')) {
        if (issue.includes('public')) return FINDING_CODES.S3_PUBLIC_ACCESS;
        if (issue.includes('versioning')) return FINDING_CODES.S3_VERSIONING_DISABLED;
        if (issue.includes('encryption')) return FINDING_CODES.S3_ENCRYPTION_DISABLED;
        if (issue.includes('lifecycle')) return FINDING_CODES.S3_LIFECYCLE_MISSING;
    }

    // Security Groups / Firewalls
    if (type.includes('security group') || type.includes('nsg') || type.includes('firewall')) {
        if (issue.includes('22') || issue.includes('ssh')) return FINDING_CODES.SG_OPEN_SSH_WORLD;
        if (issue.includes('3389') || issue.includes('rdp')) return FINDING_CODES.SG_OPEN_RDP_WORLD;
        if (issue.includes('80') || issue.includes('http')) return FINDING_CODES.SG_OPEN_HTTP_WORLD;
        if (issue.includes('unused')) return FINDING_CODES.SG_UNUSED;
        if (type.includes('azure')) return FINDING_CODES.AZURE_NSG_OPEN_INBOUND;
    }

    // Azure Specific
    if (type.includes('azure') || type.includes('app service') || type.includes('keyvault')) {
        if (type.includes('storage') && issue.includes('public')) return FINDING_CODES.AZURE_STORAGE_PUBLIC_BLOB;
        if (type.includes('storage') && issue.includes('http')) return FINDING_CODES.AZURE_STORAGE_HTTP_ALLOWED;
        if (type.includes('app service') && issue.includes('http')) return FINDING_CODES.AZURE_APPSERVICE_HTTP_ALLOWED;
        if (type.includes('app service') && issue.includes('tls')) return FINDING_CODES.AZURE_APPSERVICE_TLS_OLD;
        if (type.includes('keyvault') && issue.includes('soft delete')) return FINDING_CODES.AZURE_KEYVAULT_NO_SOFTDELETE;
        if (type.includes('sql') && issue.includes('public')) return FINDING_CODES.AZURE_SQL_PUBLIC_ACCESS;
    }

    // Databases
    if (type.includes('rds') || type.includes('database')) {
        if (issue.includes('public')) return FINDING_CODES.RDS_PUBLICLY_ACCESSIBLE;
        if (issue.includes('backup') || issue.includes('retention')) return FINDING_CODES.RDS_BACKUP_DISABLED;
        if (issue.includes('encryption')) return FINDING_CODES.RDS_UNENCRYPTED;
    }

    // DynamoDB
    if (type.includes('dynamodb') && issue.includes('pitr')) return FINDING_CODES.DYNAMODB_PITR_DISABLED;

    // CloudTrail
    if (type.includes('cloudtrail')) {
        if (issue.includes('validation')) return FINDING_CODES.CLOUDTRAIL_LOG_VALIDATION_DISABLED;
        if (issue.includes('multi-region') || issue.includes('single')) return FINDING_CODES.CLOUDTRAIL_NOT_MULTI_REGION;
    }

    // KMS
    if (type.includes('kms') && issue.includes('rotation')) return FINDING_CODES.KMS_KEY_ROTATION_DISABLED;

    // EC2
    if (type.includes('ec2') && (issue.includes('imdsv1') || issue.includes('metadata'))) return FINDING_CODES.EC2_IMDSV1_ENABLED;
    if (type.includes('elastic ip') && issue.includes('unassociated')) return FINDING_CODES.EIP_UNASSOCIATED;

    // Log Groups
    if (type.includes('log group') && (issue.includes('retention') || issue.includes('365'))) return FINDING_CODES.CLOUDWATCH_LOG_RETENTION_SHORT;

    // Custom Policies
    if (issue.includes('unauthorized region')) return FINDING_CODES.ORG_POLICY_DISALLOWED_REGION;
    if (issue.includes('missing required') && issue.includes('tag')) return FINDING_CODES.ORG_POLICY_MISSING_TAGS;
    if (issue.includes('violates organization port whitelist')) return FINDING_CODES.ORG_POLICY_DISALLOWED_PORT;

    return FINDING_CODES.GENERIC_ADVISORY;
}
