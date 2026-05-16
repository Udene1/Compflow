import { runRemediation as remediateAWS } from './providers/aws_remediator.js';
import { runRemediation as remediateGCP } from './providers/gcp.js';
import { runRemediation as remediateAzure } from './providers/azure.js';
import { log } from './logger.js';

export async function runRemediation(provider, credentials, resourceType, resourceName, issue) {
    log.info(`Initiating remediation for ${resourceName} on ${provider.toUpperCase()}...`);

    switch (provider.toLowerCase()) {
        case 'aws':
            return await remediateAWS(provider, credentials, resourceType, resourceName, issue);
        case 'gcp':
            return await remediateGCP(provider, credentials, resourceType, resourceName, issue);
        case 'azure':
            return await remediateAzure(provider, credentials, resourceType, resourceName, issue);
        default:
            log.warn(`Remediation not yet implemented for ${provider}`);
            return { success: false, message: `Remediation for ${provider} is coming soon.` };
    }
}
