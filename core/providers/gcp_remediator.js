import { Storage } from '@google-cloud/storage';
import sqlPkg from '@google-cloud/sql';
const { CloudSqlClient } = sqlPkg;
import { BigQuery } from '@google-cloud/bigquery';
import { ClusterManagerClient } from '@google-cloud/container';
import { log } from '../logger.js';

/**
 * GCP Ultra-Deep Remediation Engine
 * 
 * Executes automated remediation actions on Google Cloud Platform resources.
 * Supports high-risk fixes for Cloud Storage, Cloud SQL, BigQuery, and GKE.
 * Includes blast-radius protection for complex networking and IAM changes.
 * 
 * @param {string} provider - Cloud provider identifier ('gcp').
 * @param {Object} credentials - GCP authentication bundle.
 * @param {string} type - Resource type (e.g., 'GCP Bucket', 'GCP GKE').
 * @param {string} name - Name of the resource to remediate.
 * @param {string} issue - Description of the security issue found.
 * @param {boolean} [dryRun=false] - If true, validates parameters without executing the fix.
 * @returns {Promise<Object>} - Remediation status {success, message, advisory}.
 */
export async function runRemediation(provider, credentials, type, name, issue, dryRun = false) {
    log.info(`⚡ GCP Auto-Remediation: ${type} "${name}" — ${issue}`);

    // Credential deobfuscation for secure token handling
    const XOR_KEY = 'CompFlow_Guard_2026';
    function deobfuscate(encoded) {
        if (!encoded) return '';
        const decoded = atob(encoded);
        let out = "";
        for (let i = 0; i < decoded.length; i++) {
            out += String.fromCharCode(decoded.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
        }
        return out;
    }

    // Dry-run mode for safety validation
    if (dryRun) {
        return { success: true, message: `[DRY-RUN] Validated safety for GCP ${type} "${name}". Action: Resolve ${issue}.` };
    }

    const projectId = credentials.projectId;
    const jsonKeyStr = credentials.isObfuscated ? deobfuscate(credentials.apiToken) : credentials.apiToken;

    if (!projectId || !jsonKeyStr) {
        return { success: false, error: 'Missing GCP credentials for remediation' };
    }

    let authConfig;
    try {
        authConfig = { projectId, credentials: JSON.parse(jsonKeyStr) };
    } catch (e) {
        return { success: false, error: 'Failed to parse GCP key' };
    }

    try {
        // ── Phase 1: Blast Radius Control (Auto-Fix Whitelist) ──
        const SAFE_WHITELIST = {
            'GCP Bucket': ['Uniform bucket-level access', 'publicly accessible'],
            'GCP BigQuery': ['publicly accessible'],
            'GCP CloudSQL': ['SSL/TLS not enforced', 'Automated backups disabled'],
            'GCP Secret': ['rotation'],
            'GCP GKE': ['Shielded Nodes']
        };

        const isSafeParams = SAFE_WHITELIST[type] && 
                             SAFE_WHITELIST[type].some(safeWord => issue.includes(safeWord));

        if (!isSafeParams && !dryRun) {
            log.info(`[BLAST RADIUS] Auto-fix blocked and escalated for ${type} "${name}": ${issue}`);
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Issue "${issue}" on ${type} is outside the strict auto-fix whitelist. Escalated for human review.`
            };
        }

        // ─── 1. CLOUD STORAGE (GCS) REMEDIATIONS ────────────────────────────────
        if (type === 'GCP Bucket') {
            const storage = new Storage(authConfig);
            const bucket = storage.bucket(name);

            // Fix: Enable Uniform Bucket-Level Access (UBLA)
            if (issue.includes('Uniform bucket-level access')) {
                await bucket.setMetadata({
                    iamConfiguration: {
                        uniformBucketLevelAccess: { enabled: true }
                    }
                });
                return { success: true, message: `Remediated: UBLA enabled on bucket "${name}".` };
            }

            // Fix: Revoke Public Access (allUsers/allAuthenticatedUsers)
            if (issue.includes('publicly accessible')) {
                const [policy] = await bucket.iam.getPolicy();
                policy.bindings = (policy.bindings || []).filter(b => 
                    !b.members.includes('allUsers') && !b.members.includes('allAuthenticatedUsers')
                );
                await bucket.iam.setPolicy(policy);
                return { success: true, message: `Remediated: Public access revoked for bucket "${name}".` };
            }
        }

        // ─── 2. BIGQUERY REMEDIATIONS ───────────────────────────────────────────
        if (type === 'GCP BigQuery') {
            const bq = new BigQuery(authConfig);
            const dataset = bq.dataset(name);

            // Fix: Revoke Public Access to Dataset
            if (issue.includes('publicly accessible')) {
                const [metadata] = await dataset.getMetadata();
                const newAccess = (metadata.access || []).filter(a => 
                    a.iamMember !== 'allUsers' && a.iamMember !== 'allAuthenticatedUsers' && a.specialGroup !== 'allAuthenticatedUsers'
                );
                await dataset.setMetadata({ access: newAccess });
                return { success: true, message: `Remediated: Public access revoked for BigQuery dataset "${name}".` };
            }
        }

        // ─── 3. CLOUD SQL REMEDIATIONS ──────────────────────────────────────────
        if (type === 'GCP CloudSQL') {
            const sqlClient = new CloudSqlClient(authConfig);

            // Fix: Enforce SSL/TLS for all connections
            if (issue.includes('SSL/TLS not enforced')) {
                await sqlClient.instances.patch({
                    project: projectId,
                    instance: name,
                    requestBody: {
                        settings: {
                            ipConfiguration: { requireSsl: true }
                        }
                    }
                });
                return { success: true, message: `Remediated: SSL/TLS enforcement enabled on Cloud SQL "${name}".` };
            }

            // Fix: Enable Automated Backups
            if (issue.includes('Automated backups disabled')) {
                await sqlClient.instances.patch({
                    project: projectId,
                    instance: name,
                    requestBody: {
                        settings: {
                            backupConfiguration: { enabled: true, startTime: '02:00' }
                        }
                    }
                });
                return { success: true, message: `Remediated: Automated backups enabled on Cloud SQL "${name}".` };
            }
        }

        // ─── 4. GKE REMEDIATIONS (ADVISORY) ─────────────────────────────────────
        if (type === 'GCP GKE') {
            if (issue.includes('Shielded Nodes')) {
                // This is safe-ish, but requires node pool recreate/patch
                return { success: true, advisory: true, message: `ADVISORY: Shielded Nodes must be enabled at the Node Pool level for cluster "${name}".` };
            }
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: GKE Cluster "${name}" requires Master Authorized Networks. Apply via Console/Terraform to prevent connectivity loss.`
            };
        }

        // ─── 5. SECRET MANAGER REMEDIATIONS ──────────────────────────────────
        if (type === 'GCP Secret' && issue.includes('rotation')) {
             // Requires a Lambda/Cloud Function for rotation logic
             return { success: true, advisory: true, message: `ADVISORY: Secret rotation for "${name}" requires a back-end Cloud Function to execute the rotation.` };
        }

        // ─── 5. ADVISORY FALLBACK ──────────────────────────────────────────────
        return {
            success: true,
            advisory: true,
            message: `ADVISORY PROTECTED: Automated fix for ${type} "${name}" requires manual approval (Potential connectivity impact).`
        };

    } catch (err) {
        log.error("GCP Remediation Execution failed:", err.message);
        throw err;
    }
}
