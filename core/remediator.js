import { runRemediation as remediateAWS } from './providers/aws_remediator.js';
import { runRemediation as remediateGCP } from './providers/gcp_remediator.js';
import { runRemediation as remediateAzure } from './providers/azure_remediator.js';
import { runRemediation as remediateDO } from './providers/digitalocean_remediator.js';
import { runRemediation as remediateHetzner } from './providers/hetzner_remediator.js';
import { log } from './logger.js';

export async function runRemediation(provider, credentials, resourceType, resourceName, issue, dryRun = false) {
    log.info(`Initiating remediation for ${resourceName} on ${provider.toUpperCase()} (dryRun: ${dryRun})...`);

    switch (provider.toLowerCase()) {
        case 'aws':
            return await remediateAWS(provider, credentials, resourceType, resourceName, issue, dryRun);
        case 'gcp':
            return await remediateGCP(provider, credentials, resourceType, resourceName, issue, dryRun);
        case 'azure':
            return await remediateAzure(provider, credentials, resourceType, resourceName, issue, dryRun);
        case 'digitalocean':
        case 'do':
            return await remediateDO(provider, credentials, resourceType, resourceName, issue, dryRun);
        case 'hetzner':
            return await remediateHetzner(provider, credentials, resourceType, resourceName, issue, dryRun);
        default:
            log.warn(`Remediation not yet implemented for ${provider}`);
            return { success: false, message: `Remediation for ${provider} is coming soon.` };
    }
}
