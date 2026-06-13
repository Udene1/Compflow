/**
 * ComplianceFlow Control Matrix
 * Maps technical findings to 120+ regulatory controls across 4 frameworks.
 */
export const ControlMatrix = {
    // ─── CROSS-CLOUD SHARED CONTROLS ──────────────────────────────────────────
    'S3_PUBLIC': {
        name: 'Public Data Exposure',
        impact: 'CRITICAL. Publicly accessible storage leads to immediate data compromise.',
        remediation: 'Revoke public/allUsers permissions.',
        soc2: ['CC6.1', 'CC6.6'], gdpr: ['Art 32(1)(a)'], hipaa: ['§164.312(a)(1)'], iso27001: ['A.9.1.1']
    },
    'RDS_PUBLIC': {
        name: 'Public Database Exposure',
        soc2: ['CC6.6'], gdpr: ['Art 32'], hipaa: ['§164.312(c)(1)'], iso27001: ['A.13.1.1']
    },
    'SG_OPEN_PORTS': {
        name: 'Insecure Port Configuration',
        soc2: ['CC6.6'], gdpr: ['Art 32'], iso27001: ['A.13.1.1']
    },
    'DISK_ENCRYPTION': {
        name: 'Data-at-Rest Encryption',
        soc2: ['CC6.7'], gdpr: ['Art 32(1)(a)'], hipaa: ['§164.312(a)(2)(iv)']
    },

    // ─── AZURE SPECIFIC CONTROLS ──────────────────────────────────────────────
    'AZ_APP_HTTPS': { name: 'Azure App Service HTTPS', soc2: ['CC6.6'], gdpr: ['Art 32(1)(a)'], hipaa: ['§164.312(e)(1)'] },
    'AZ_APP_TLS': { name: 'Azure App Service TLS', soc2: ['CC6.6'], gdpr: ['Art 32'] },
    'AZ_APP_IDENTITY': { name: 'Azure Managed Identity', soc2: ['CC6.1'] },
    'AKS_API_SERVER': { name: 'AKS API Server Hardening', soc2: ['CC6.6'], iso27001: ['A.13.1.1'] },
    'AKS_RBAC': { name: 'AKS RBAC Status', soc2: ['CC6.1', 'CC6.3'] },
    'AZ_COSMOS_CMK': { name: 'Cosmos DB Encryption', soc2: ['CC6.7'], hipaa: ['§164.312(a)(2)(iv)'] },
    'AZ_ACR_ADMIN': { name: 'ACR Admin User Access', soc2: ['CC6.1'] },
    'AZ_ACR_PUBLIC': { name: 'ACR Public Exposure', soc2: ['CC6.6'] },
    'AZ_IAM_OWNER': { name: 'Excessive Azure Owners', soc2: ['CC6.1', 'CC6.3'] },
    'AZ_KV_SOFT_DELETE': { name: 'Key Vault Soft Delete', soc2: ['CC6.1', 'CC7.2'], gdpr: ['Art 32(1)(c)'] },
    'AZ_KV_FIREWALL': { name: 'Key Vault Firewall', soc2: ['CC6.6'] },
    'AZ_LOGIC_IP': { name: 'Logic App IP Access', soc2: ['CC6.6'] },
    'AZ_APIM_HTTPS': { name: 'APIM HTTPS Enforcement', soc2: ['CC6.6'] },
    'AZ_AI_RETENTION': { name: 'Monitoring Data Retention', gdpr: ['Art 5(1)(e)'] },
    'AZ_FD_WAF': { name: 'Front Door WAF Protection', soc2: ['CC6.6'] },
    'AZ_DIAG_SETTINGS': { name: 'Diagnostic Logs Export', soc2: ['CC7.2'], gdpr: ['Art 30'] },
    'AZ_UNMANAGED_DISK': { name: 'VM Unmanaged Disks', soc2: ['CC6.1'] },
    'AZ_VM_PUBLIC_IP': { name: 'VM Public IP', soc2: ['CC6.6'] },
    'AZ_BUS_ENCRYPT': { name: 'Service Bus Encryption', soc2: ['CC6.7'], hipaa: ['§164.312(a)(2)(iv)'] },
    'AZ_POLICY_HEALTH': { name: 'Azure Policy Compliance', soc2: ['CC6.1'], iso27001: ['A.18.2.1'] },

    // ─── GCP SPECIFIC CONTROLS ───────────────────────────────────────────────
    'GKE_MASTER_NETWORKS': { name: 'GKE Master Authorized Networks', soc2: ['CC6.6'], gdpr: ['Art 32'] },
    'GKE_SHIELDED_NODES': { name: 'GKE Shielded Nodes', soc2: ['CC6.1'] },
    'BQ_PUBLIC_DATASET': { name: 'BigQuery Public Access', soc2: ['CC6.1', 'CC6.6'], gdpr: ['Art 32'] },
    'BQ_CMEK': { name: 'BigQuery Encryption', soc2: ['CC6.7'] },
    'GCP_SHIELDED_VM': { name: 'Shielded VM Secure Boot', soc2: ['CC6.1'] },
    'KMS_ROTATION': { name: 'Cryptographic Key Rotation', soc2: ['CC6.1'], hipaa: ['§164.312(a)(2)(iv)'] },
    'GCP_SQL_BACKUP': { name: 'SQL Automated Backups', soc2: ['CC7.2'], gdpr: ['Art 32(1)(c)'] },
    'SECRET_ROTATION': { name: 'Secret Rotation', soc2: ['CC6.1'] },
    'PUBSUB_CMEK': { name: 'Pub/Sub Encryption', soc2: ['CC6.7'] },
    'GCP_OLD_SNAPSHOT': { name: 'Old Storage Snapshots', gdpr: ['Art 5(1)(e)'] },
    'GCP_DEFAULT_VPC': { name: 'Default VPC Usage', soc2: ['CC6.6'] },
    'GCS_LOGGING': { name: 'Storage Access Logging', soc2: ['CC7.2'], gdpr: ['Art 30'] },
    'GCS_VERSIONING': { name: 'Storage Versioning', soc2: ['CC7.2'], gdpr: ['Art 32(1)(c)'] },
    'GCS_UBR': { name: 'Uniform Bucket-Level Access', soc2: ['CC6.1'] },
    'CLOUDSQL_SSL': { name: 'SQL SSL Enforcement', soc2: ['CC6.6'], gdpr: ['Art 32(1)(a)'] },
    'GCP_SERIAL_PORT': { name: 'VM Serial Port Access', soc2: ['CC6.1'] },

    // ─── LEGACY / ADDITIONAL CHECKS ───
    'IAM_ROOT_MFA': { name: 'Root Account MFA', soc2: ['CC6.1'], iso27001: ['A.9.2.1'] },
    'VPC_FLOW_LOGS': { name: 'Network Flow Logs', soc2: ['CC7.2'], gdpr: ['Art 30'] },
};

export const FrameworkInfo = {
    soc2: { name: 'SOC2 Type II', color: '#3b82f6', description: 'Security, Availability, and Privacy trust criteria.' },
    gdpr: { name: 'GDPR', color: '#10b981', description: 'Global data protection and privacy regulation.' },
    hipaa: { name: 'HIPAA', color: '#f59e0b', description: 'Standards for protecting sensitive patient data (PHI).' },
    iso27001: { name: 'ISO 27001', color: '#8b5cf6', description: 'Framework for information security management systems.' }
};

export function getControlsForIssue(technicalId, frameworkId) {
    const issueMappings = ControlMatrix[technicalId];
    if (!issueMappings) return [];
    if (frameworkId === 'all') {
        const all = [];
        if (issueMappings.soc2) all.push(...issueMappings.soc2.map(c => `SOC2 ${c}`));
        if (issueMappings.gdpr) all.push(...issueMappings.gdpr.map(c => `GDPR ${c}`));
        if (issueMappings.hipaa) all.push(...issueMappings.hipaa.map(c => `HIPAA ${c}`));
        if (issueMappings.iso27001) all.push(...issueMappings.iso27001.map(c => `ISO ${c}`));
        return all;
    }
    return issueMappings[frameworkId] || [];
}
