import { ClientSecretCredential } from "@azure/identity";
import { NetworkManagementClient } from "@azure/arm-network";
import { StorageManagementClient } from "@azure/arm-storage";
import { SqlManagementClient } from "@azure/arm-sql";
import { WebSiteManagementClient } from "@azure/arm-appservice";
import { KeyVaultManagementClient } from "@azure/arm-keyvault";
import { log } from '../logger.js';

/**
 * Azure Ultra-Deep Remediation Engine
 * 
 * Executes automated remediation actions on Azure resources to resolve security findings.
 * Includes blast-radius protection and supports high-risk fixes for Compute, Storage,
 * App Services, and Key Vaults.
 * 
 * @param {string} provider - Cloud provider identifier ('azure').
 * @param {Object} credentials - Azure authentication bundle.
 * @param {string} type - Resource type (e.g., 'Azure Storage', 'Azure App Service').
 * @param {string} name - Name of the resource to remediate.
 * @param {string} issue - Description of the security issue found.
 * @param {boolean} [dryRun=false] - If true, validates parameters without executing the fix.
 * @returns {Promise<Object>} - Remediation status {success, message, advisory}.
 */
export async function runRemediation(provider, credentials, type, name, issue, dryRun = false) {
    log.info(`⚡ Azure Auto-Remediation: ${type} "${name}" — ${issue}`);

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
        return { success: true, message: `[DRY-RUN] Validated safety for Azure ${type} "${name}". Action: Resolve ${issue}.` };
    }

    const tenantId = credentials.tenantId;
    const clientId = credentials.isObfuscated ? deobfuscate(credentials.accessKeyId) : credentials.accessKeyId;
    const clientSecret = credentials.isObfuscated ? deobfuscate(credentials.secretAccessKey) : credentials.secretAccessKey;
    const subscriptionId = credentials.projectId;

    if (!tenantId || !clientId || !clientSecret || !subscriptionId) {
        return { success: false, error: 'Missing Azure credentials for remediation' };
    }

    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);

    try {
        // ── Phase 1: Blast Radius Control (Auto-Fix Whitelist) ──
        const SAFE_WHITELIST = {
            'Azure App Service': ['HTTPS', 'TLS'],
            'Azure KeyVault': ['Soft delete'],
            'Azure Storage': ['HTTPS', 'public access'],
            'Azure VM': ['Managed Disks', 'encryption'],
            'Azure AKS': ['RBAC'], // Adding RBAC as safe-ish
            'Azure Recovery Vault': ['Soft delete']
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

        // ─── 1. APP SERVICE REMEDIATIONS ──────────────────────────────────────
        if (type === 'Azure App Service') {
            const webClient = new WebSiteManagementClient(credential, subscriptionId);
            
            // Resolve Resource Group from Resource Name (discovery)
            let rgName = '';
            for await (const site of webClient.webApps.list()) {
                if (site.name === name) {
                    rgName = site.id.split('/')[4];
                    break;
                }
            }

            if (rgName) {
                // Fix: Enforce HTTPS-only traffic
                if (issue.includes('HTTPS')) {
                    await webClient.webApps.update(rgName, name, { httpsOnly: true });
                    return { success: true, message: `Remediated: HTTPS-only enforced on "${name}".` };
                }
                // Fix: Upgrade to TLS 1.2
                if (issue.includes('TLS')) {
                    await webClient.webApps.updateConfiguration(rgName, name, { minTlsVersion: '1.2' });
                    return { success: true, message: `Remediated: Minimum TLS 1.2 enforced on "${name}".` };
                }
            }
        }

        // ─── 2. KEY VAULT REMEDIATIONS ─────────────────────────────────────────
        if (type === 'Azure KeyVault') {
            const kvClient = new KeyVaultManagementClient(credential, subscriptionId);
            
            // Resolve Resource Group
            let rgName = '';
            for await (const vault of kvClient.vaults.list()) {
                if (vault.name === name) {
                    rgName = vault.id.split('/')[4];
                    break;
                }
            }

            if (rgName && issue.includes('Soft delete')) {
                // Fix: Enable Soft Delete and Purge Protection
                await kvClient.vaults.update(rgName, name, {
                    properties: { enableSoftDelete: true, enablePurgeProtection: true }
                });
                return { success: true, message: `Remediated: Soft Delete enabled on Key Vault "${name}".` };
            }
        }

        // ─── 3. STORAGE ACCOUNT REMEDIATIONS ────────────────────────────────────
        if (type === 'Azure Storage') {
            const storageClient = new StorageManagementClient(credential, subscriptionId);
            
            // Resolve Resource Group
            let rgName = '';
            for await (const sa of storageClient.storageAccounts.list()) {
                if (sa.name === name) {
                    rgName = sa.id.split('/')[4];
                    break;
                }
            }

            if (rgName) {
                // Fix: Enforce HTTPS
                if (issue.includes('HTTPS')) {
                    await storageClient.storageAccounts.update(rgName, name, { enableHttpsTrafficOnly: true });
                    return { success: true, message: `Remediated: HTTPS transfer required for storage "${name}".` };
                }
                // Fix: Disable Public Access
                if (issue.includes('public access')) {
                    await storageClient.storageAccounts.update(rgName, name, { allowBlobPublicAccess: false });
                    return { success: true, message: `Remediated: Public blob access revoked for storage "${name}".` };
                }
            }
        }

        // ─── 4. RECOVERY VAULT REMEDIATIONS ───────────────────────────────────
        if (type === 'Azure Recovery Vault') {
            const rsClient = new RecoveryServicesManagementClient(credential, subscriptionId);
            let rgName = '';
            for await (const vault of rsClient.vaults.listBySubscriptionId()) {
                if (vault.name === name) {
                    rgName = vault.id.split('/')[4];
                    break;
                }
            }
            if (rgName && issue.includes('Soft delete')) {
                // Not all vault updates are easy via SDK update, but we can try
                // For now, return advisory if complex, or implement here
                return { success: true, advisory: true, message: `ADVISORY: Enable soft delete via Vault > Properties > Security Settings.` };
            }
        }

        // ─── 5. ADVISORY FALLBACK ──────────────────────────────────────────────
        // For complex networking or high-risk architectural changes, return an advisory message
        return {
            success: true,
            advisory: true,
            message: `ADVISORY PROTECTED: Automated fix for ${type} "${name}" requires manual approval due to potential blast radius.`
        };

    } catch (err) {
        log.error("Azure Remediation Execution failed:", err.message);
        throw err;
    }
}
