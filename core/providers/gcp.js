import { log } from '../logger.js';

/**
 * GCP Provider Adapter — Expanded v2
 * Audits 22 GCP service categories with detailed compliance checks.
 * 
 * Architecture: Simulated scans reflecting real-world GCP SDK patterns.
 * In production: swap push() calls with @google-cloud/* SDK calls.
 */
export async function runScan(provider, credentials) {
    log.info("➤ Starting GCP Hyperscale Scan (v2 - Expanded)...");

    const resources = [];
    const region = 'us-central1';

    try {
        // ─── 1. Firewall Rules ────────────────────────────────────────────
        resources.push({
            name: 'allow-all-ingress',
            type: 'GCP Firewall',
            icon: '🛡️',
            region: region,
            severity: 'critical',
            technicalId: 'SG_OPEN_SSH',
            issue: '0.0.0.0/0 allowed on port 22 (SSH) — global exposure',
            recommendation: 'Restrict SSH to 10.128.0.0/9 VPC CIDR or use Identity-Aware Proxy (IAP) for tunneled access.'
        });
        resources.push({
            name: 'allow-rdp-all',
            type: 'GCP Firewall',
            icon: '🛡️',
            region: region,
            severity: 'critical',
            technicalId: 'SG_OPEN_RDP',
            issue: 'RDP (port 3389) open to 0.0.0.0/0',
            recommendation: 'Remove open RDP rule. Use IAP for Windows VM access without public IPs.'
        });

        // ─── 2. Compute Instances ─────────────────────────────────────────
        resources.push({
            name: 'gpus-worker-01',
            type: 'GCP Instance',
            icon: '💻',
            region: region,
            severity: 'warning',
            technicalId: 'IAM_ACCESS',
            issue: 'External IP address assigned — VM directly reachable from internet',
            recommendation: 'Remove external IP. Use Cloud NAT for outbound traffic and IAP for SSH.'
        });
        resources.push({
            name: 'analytics-vm-02',
            type: 'GCP Instance',
            icon: '💻',
            region: region,
            severity: 'warning',
            technicalId: 'GCE_OS_LOGIN',
            issue: 'OS Login not enabled — SSH keys managed via metadata (less secure)',
            recommendation: 'Enable OS Login at project level to centralize SSH key management through IAM.'
        });
        resources.push({
            name: 'legacy-vm-03',
            type: 'GCP Instance',
            icon: '💻',
            region: region,
            severity: 'warning',
            technicalId: 'GCE_DEFAULT_SA',
            issue: 'Running with default service account and full API access scope',
            recommendation: 'Create a dedicated service account with minimal IAM roles and specific API scopes.'
        });

        // ─── 3. Cloud SQL ─────────────────────────────────────────────────
        resources.push({
            name: 'prod-db-01',
            type: 'GCP CloudSQL',
            icon: '🗃️',
            region: region,
            severity: 'critical',
            technicalId: 'RDS_PUBLIC',
            issue: 'Public IP enabled — database exposed to the internet',
            recommendation: 'Disable public IP. Use Private Service Access for intra-VPC connectivity.'
        });
        resources.push({
            name: 'dev-db-02',
            type: 'GCP CloudSQL',
            icon: '🗃️',
            region: region,
            severity: 'warning',
            technicalId: 'CLOUDSQL_SSL',
            issue: 'SSL not enforced — connections can be made without encryption',
            recommendation: 'Set requireSsl=true in Cloud SQL settings and rotate client certificates.'
        });
        resources.push({
            name: 'analytics-db-03',
            type: 'GCP CloudSQL',
            icon: '🗃️',
            region: region,
            severity: 'warning',
            technicalId: 'CLOUDSQL_FLAGS',
            issue: 'Risky database flags: log_checkpoints=off, log_connections=off',
            recommendation: 'Enable log_checkpoints, log_connections, log_disconnections for audit compliance.'
        });

        // ─── 4. Cloud Storage (Buckets) ───────────────────────────────────
        resources.push({
            name: 'cf-audit-logs-private',
            type: 'GCP Bucket',
            icon: '🪣',
            region: region,
            severity: 'warning',
            technicalId: 'S3_NO_VERSIONING',
            issue: 'Object versioning disabled — no protection against accidental deletion',
            recommendation: 'Enable versioning and configure lifecycle rules for automated cleanup of old versions.'
        });
        resources.push({
            name: 'public-assets-bucket',
            type: 'GCP Bucket',
            icon: '🪣',
            region: region,
            severity: 'critical',
            technicalId: 'S3_PUBLIC',
            issue: 'allUsers has Storage Object Viewer — bucket fully public',
            recommendation: 'Remove allUsers/allAuthenticatedUsers bindings. Enforce uniform bucket-level access.'
        });
        resources.push({
            name: 'backup-data-bucket',
            type: 'GCP Bucket',
            icon: '🪣',
            region: region,
            severity: 'warning',
            technicalId: 'S3_NO_LOGGING',
            issue: 'Access logs not enabled on backup bucket',
            recommendation: 'Enable Cloud Storage access logging with a dedicated log bucket.'
        });

        // ─── 5. IAM ───────────────────────────────────────────────────────
        resources.push({
            name: 'default-sa@project.iam',
            type: 'GCP IAM',
            icon: '🔑',
            region: 'global',
            severity: 'critical',
            technicalId: 'IAM_WILDCARD',
            issue: 'Default Service Account has Editor role — over-privileged',
            recommendation: 'Remove Editor role from default service account. Apply least-privilege task-specific roles.'
        });
        resources.push({
            name: 'project-iam-binding',
            type: 'GCP IAM',
            icon: '🔑',
            region: 'global',
            severity: 'critical',
            technicalId: 'IAM_OWNER_EXTERNAL',
            issue: '2 external (gmail.com) accounts granted project Owner — violates enterprise policy',
            recommendation: 'Remove personal account ownership. Use Google Workspace domain accounts with group-based IAM.'
        });
        resources.push({
            name: 'ci-cd-sa@project.iam',
            type: 'GCP IAM',
            icon: '🔑',
            region: 'global',
            severity: 'warning',
            technicalId: 'IAM_SA_KEY_AGE',
            issue: 'Service account key is 127 days old — exceeds 90-day rotation policy',
            recommendation: 'Rotate service account key. Consider Workload Identity Federation to eliminate static keys.'
        });

        // ─── 6. VPC / Networking ──────────────────────────────────────────
        resources.push({
            name: 'prod-vpc',
            type: 'GCP VPC',
            icon: '🌐',
            region: region,
            severity: 'warning',
            technicalId: 'VPC_FLOW_LOGS',
            issue: 'VPC Flow Logs disabled on all subnets',
            recommendation: 'Enable VPC Flow Logs with metadata inclusion for traffic analysis and threat detection.'
        });

        // ─── 7. KMS ───────────────────────────────────────────────────────
        resources.push({
            name: 'kms-key-prod',
            type: 'GCP KMS',
            icon: '🔐',
            region: region,
            severity: 'warning',
            technicalId: 'KMS_NO_ROTATION',
            issue: 'Key rotation disabled — CMEK key never rotated',
            recommendation: 'Enable automatic rotation with 90-day period. Manual rotation recommended for KMS primary versions.'
        });

        // ─── 8. GKE (Kubernetes Engine) ───────────────────────────────────
        resources.push({
            name: 'prod-gke-cluster',
            type: 'GCP GKE',
            icon: '☸️',
            region: region,
            severity: 'critical',
            technicalId: 'GKE_PUBLIC_ENDPOINT',
            issue: 'GKE master endpoint is public — Kubernetes API reachable from internet',
            recommendation: 'Enable Private Cluster mode or restrict master authorized networks to known IPs/VPN ranges.'
        });
        resources.push({
            name: 'prod-gke-cluster',
            type: 'GCP GKE',
            icon: '☸️',
            region: region,
            severity: 'warning',
            technicalId: 'GKE_NO_BINARY_AUTH',
            issue: 'Binary Authorization not enabled — unsigned container images can be deployed',
            recommendation: 'Enable Binary Authorization and configure attestor policies to allow only verified images.'
        });
        resources.push({
            name: 'dev-gke-cluster',
            type: 'GCP GKE',
            icon: '☸️',
            region: region,
            severity: 'warning',
            technicalId: 'GKE_LEGACY_AUTH',
            issue: 'Legacy ABAC authorization enabled — bypasses RBAC controls',
            recommendation: 'Disable legacy ABAC (--no-enable-legacy-authorization) and enforce Kubernetes RBAC.'
        });

        // ─── 9. Cloud Functions ───────────────────────────────────────────
        resources.push({
            name: 'process-uploads-fn',
            type: 'GCP Cloud Function',
            icon: '⚡',
            region: region,
            severity: 'critical',
            technicalId: 'GCF_PUBLIC',
            issue: 'HTTP function publicly accessible without authentication (allUsers invoker)',
            recommendation: 'Remove allUsers invoker binding. Require authentication via Cloud IAM or API Gateway.'
        });
        resources.push({
            name: 'scheduled-cleanup-fn',
            type: 'GCP Cloud Function',
            icon: '⚡',
            region: region,
            severity: 'warning',
            technicalId: 'GCF_ENV_SECRETS',
            issue: 'API keys stored in function environment variables (plaintext)',
            recommendation: 'Move secrets to Secret Manager and access via Secret Manager API within the function.'
        });

        // ─── 10. BigQuery ─────────────────────────────────────────────────
        resources.push({
            name: 'analytics-dataset',
            type: 'GCP BigQuery',
            icon: '📊',
            region: region,
            severity: 'critical',
            technicalId: 'BQ_PUBLIC',
            issue: 'Dataset publicly accessible — allAuthenticatedUsers has READER role',
            recommendation: 'Remove allAuthenticatedUsers binding. Grant access only to specific service accounts and groups.'
        });
        resources.push({
            name: 'prod-logs-dataset',
            type: 'GCP BigQuery',
            icon: '📊',
            region: region,
            severity: 'warning',
            technicalId: 'BQ_NO_CMEK',
            issue: 'Dataset uses Google-managed encryption — CMK not configured',
            recommendation: 'Configure Customer-Managed Encryption Keys (CMEK) via Cloud KMS for regulatory compliance.'
        });

        // ─── 11. Pub/Sub ──────────────────────────────────────────────────
        resources.push({
            name: 'audit-events-topic',
            type: 'GCP Pub/Sub',
            icon: '📨',
            region: region,
            severity: 'warning',
            technicalId: 'PUBSUB_NO_DLQ',
            issue: 'No dead-letter topic configured — failed messages lost permanently',
            recommendation: 'Configure dead-letter topic with max delivery attempts to capture processing failures.'
        });
        resources.push({
            name: 'scan-results-sub',
            type: 'GCP Pub/Sub',
            icon: '📨',
            region: region,
            severity: 'warning',
            technicalId: 'PUBSUB_PUBLIC',
            issue: 'Subscription allows allUsers access — messages readable without auth',
            recommendation: 'Remove allUsers binding. Grant Pub/Sub Subscriber role only to specific service accounts.'
        });

        // ─── 12. Artifact Registry ────────────────────────────────────────
        resources.push({
            name: 'cf-docker-registry',
            type: 'GCP Artifact Registry',
            icon: '📦',
            region: region,
            severity: 'warning',
            technicalId: 'AR_NO_VULN_SCAN',
            issue: 'Vulnerability scanning disabled on container image repository',
            recommendation: 'Enable Container Analysis API for automated vulnerability scanning on push.'
        });
        resources.push({
            name: 'cf-docker-registry',
            type: 'GCP Artifact Registry',
            icon: '📦',
            region: region,
            severity: 'critical',
            technicalId: 'AR_PUBLIC',
            issue: 'Repository accessible to allUsers — images publicly downloadable',
            recommendation: 'Remove allUsers binding. Restrict to internal service accounts and authorized users only.'
        });

        // ─── 13. VPC Service Controls ─────────────────────────────────────
        resources.push({
            name: 'org-service-perimeter',
            type: 'GCP VPC Service Controls',
            icon: '🔒',
            region: 'global',
            severity: 'critical',
            technicalId: 'VPC_SC_DISABLED',
            issue: 'VPC Service Controls perimeter not configured — data exfiltration risk via APIs',
            recommendation: 'Configure VPC Service Controls perimeter for BigQuery, Cloud Storage, and Cloud SQL.'
        });

        // ─── 14. Security Command Center ──────────────────────────────────
        resources.push({
            name: 'org-scc',
            type: 'GCP Security Command Center',
            icon: '🔰',
            region: 'global',
            severity: 'warning',
            technicalId: 'SCC_FINDINGS',
            issue: '14 unresolved high-severity findings in Security Command Center',
            recommendation: 'Review and remediate SCC findings. Enable SCC Premium for threat detection and web scanning.'
        });

        // ─── 15. Cloud Run ────────────────────────────────────────────────
        resources.push({
            name: 'api-cloud-run-svc',
            type: 'GCP Cloud Run',
            icon: '🚀',
            region: region,
            severity: 'critical',
            technicalId: 'CLOUDRUN_PUBLIC',
            issue: 'Cloud Run service allows unauthenticated invocations (allUsers)',
            recommendation: 'Remove allUsers invoker. Require authentication or route traffic through API Gateway with IAM.'
        });
        resources.push({
            name: 'frontend-cloud-run-svc',
            type: 'GCP Cloud Run',
            icon: '🚀',
            region: region,
            severity: 'pass',
            technicalId: null,
            issue: null,
            recommendation: null
        });

        // ─── 16. Cloud Build ──────────────────────────────────────────────
        resources.push({
            name: 'main-build-trigger',
            type: 'GCP Cloud Build',
            icon: '🔨',
            region: region,
            severity: 'warning',
            technicalId: 'CLOUDBUILD_PUBLIC_POOL',
            issue: 'Using default shared worker pool — build environment not isolated',
            recommendation: 'Use Private Pools for network isolation. Avoid logging secrets in build steps.'
        });

        // ─── 17. Secret Manager ───────────────────────────────────────────
        resources.push({
            name: 'prod-api-key',
            type: 'GCP Secret Manager',
            icon: '🔑',
            region: 'global',
            severity: 'warning',
            technicalId: 'SM_NO_ROTATION',
            issue: 'Secret has no rotation policy — last rotated 210 days ago',
            recommendation: 'Configure automatic rotation with Cloud Functions and Pub/Sub trigger.'
        });
        resources.push({
            name: 'db-password-prod',
            type: 'GCP Secret Manager',
            icon: '🔑',
            region: 'global',
            severity: 'warning',
            technicalId: 'SM_BROAD_ACCESS',
            issue: 'Secret accessible to 4 service accounts — access not scoped per consumer',
            recommendation: 'Apply principle of least privilege: grant Secret Accessor only to the consuming service account.'
        });

        // ─── 18. Logging Sinks ────────────────────────────────────────────
        resources.push({
            name: '_Default',
            type: 'GCP Logging',
            icon: '📋',
            region: 'global',
            severity: 'warning',
            technicalId: 'LOGGING_NO_SINK',
            issue: 'No log sink configured to external SIEM — audit logs not exported',
            recommendation: 'Create a log sink exporting AuditData and SystemEvent logs to Cloud Storage or Pub/Sub for SIEM.'
        });
        resources.push({
            name: 'admin-activity-log',
            type: 'GCP Logging',
            icon: '📋',
            region: 'global',
            severity: 'pass',
            technicalId: null,
            issue: null,
            recommendation: null
        });

        // ─── 19. IAM Conditional Policies ────────────────────────────────
        resources.push({
            name: 'iam-conditional-access',
            type: 'GCP IAM Conditions',
            icon: '🎛️',
            region: 'global',
            severity: 'warning',
            technicalId: 'IAM_NO_CONDITIONS',
            issue: 'Sensitive project-level roles granted without time-bound IAM conditions',
            recommendation: 'Apply expiring IAM conditions to time-sensitive access grants for contractors and temporary admins.'
        });

        // ─── 20. Compute Instance Templates ──────────────────────────────
        resources.push({
            name: 'prod-instance-template',
            type: 'GCP Instance Template',
            icon: '📄',
            region: region,
            severity: 'warning',
            technicalId: 'TEMPLATE_SERIAL_PORT',
            issue: 'Serial port access enabled in instance template — potential debug vector',
            recommendation: 'Disable serial port access in template metadata: serial-port-enable=false.'
        });
        resources.push({
            name: 'gpu-instance-template',
            type: 'GCP Instance Template',
            icon: '📄',
            region: region,
            severity: 'warning',
            technicalId: 'TEMPLATE_SHIELDED_VM',
            issue: 'Shielded VM not enabled — no Secure Boot or vTPM protection',
            recommendation: 'Enable Shielded VM options (Secure Boot, vTPM, Integrity Monitoring) in the instance template.'
        });

        // ─── 21. Organization Policies ────────────────────────────────────
        resources.push({
            name: 'org-policy',
            type: 'GCP Org Policy',
            icon: '🏛️',
            region: 'global',
            severity: 'critical',
            technicalId: 'ORGPOL_DOMAIN_RESTRICTION',
            issue: 'No domain restriction policy — external identities can be granted project access',
            recommendation: 'Apply constraints/iam.allowedPolicyMemberDomains to restrict IAM to your workspace domain.'
        });
        resources.push({
            name: 'org-policy',
            type: 'GCP Org Policy',
            icon: '🏛️',
            region: 'global',
            severity: 'warning',
            technicalId: 'ORGPOL_PUBLIC_IP',
            issue: 'No policy restricting public IP assignment to Compute VMs',
            recommendation: 'Enforce constraints/compute.vmExternalIpAccess to prevent public IPs org-wide.'
        });

        // ─── 22. Cloud SQL Flags & Users ─────────────────────────────────
        resources.push({
            name: 'cloudsql-root-user',
            type: 'GCP CloudSQL',
            icon: '🗃️',
            region: region,
            severity: 'critical',
            technicalId: 'CLOUDSQL_ROOT',
            issue: 'Root MySQL user has no password — superuser account exposed',
            recommendation: 'Set strong password on root user or disable it. Use Cloud IAM authentication for all users.'
        });

        const summary = {
            total: resources.length,
            critical: resources.filter(r => r.severity === 'critical').length,
            warning: resources.filter(r => r.severity === 'warning').length,
            pass: resources.filter(r => r.severity === 'pass').length
        };

        log.info(`GCP Scan complete: ${summary.total} resources, ${summary.critical} critical, ${summary.warning} warnings`);
        return { resources, summary };

    } catch (e) {
        log.error("GCP Scan failed:", e);
        throw e;
    }
}
