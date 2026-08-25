import { runRemediation as remediateAWS } from './providers/aws_remediator.js';
import { runRemediation as remediateGCP } from './providers/gcp_remediator.js';
import { runRemediation as remediateAzure } from './providers/azure_remediator.js';
import { runRemediation as remediateDO } from './providers/digitalocean_remediator.js';
import { runRemediation as remediateHetzner } from './providers/hetzner_remediator.js';
import { log } from './logger.js';
import { resolveFindingCode } from './finding_codes.js';

/**
 * ComplianceFlow AI — Central Multi-Cloud Remediation Dispatcher
 * 
 * Routes remediation requests to provider-specific engines with
 * blast-radius control, structured finding codes, and configurable parameters.
 * 
 * @param {string} provider - Cloud provider ('aws', 'azure', 'gcp', 'digitalocean', 'hetzner')
 * @param {Object} credentials - Provider credentials
 * @param {string} resourceType - Resource type (e.g. 'S3 Bucket', 'Security Group')
 * @param {string} resourceName - Name/identifier of the target resource
 * @param {string} issue - Human-readable issue description
 * @param {boolean} [dryRun=false] - If true, validates safety without applying changes
 * @param {Object} [options={}] - Additional options (findingCode, allowedCidr, policiesConfig)
 */
export async function runRemediation(provider, credentials, resourceType, resourceName, issue, dryRun = false, options = {}) {
    const findingCode = options.findingCode || resolveFindingCode(resourceType, issue);
    log.info(`[REMEDIATION] Target: ${resourceName} (${provider.toUpperCase()} ${resourceType}) | Code: [${findingCode}] | dryRun: ${dryRun}`);

    switch (provider.toLowerCase()) {
        case 'aws':
            return await remediateAWS(provider, credentials, resourceType, resourceName, issue, dryRun, options);
        case 'gcp':
            return await remediateGCP(provider, credentials, resourceType, resourceName, issue, dryRun);
        case 'azure':
            return await remediateAzure(provider, credentials, resourceType, resourceName, issue, dryRun, options);
        case 'digitalocean':
        case 'do':
            return await remediateDO(provider, credentials, resourceType, resourceName, issue, dryRun);
        case 'hetzner':
            return await remediateHetzner(provider, credentials, resourceType, resourceName, issue, dryRun);
        default:
            log.warn(`[REMEDIATION] Unsupported provider: ${provider}`);
            return { 
                success: false, 
                findingCode,
                message: `Remediation for ${provider} is coming soon.` 
            };
    }
}
