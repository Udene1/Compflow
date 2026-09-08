import { getProvider } from './provider_registry.js';
import { log } from './logger.js';
import { resolveFindingCode } from './finding_codes.js';

export async function runRemediation(provider, credentials, resourceType, resourceName, issue, dryRun = false, options = {}) {
    const definition = getProvider(provider);
    const findingCode = options.findingCode || resolveFindingCode(resourceType, issue);
    log.info(`[REMEDIATION] Target: ${resourceName} (${definition.id.toUpperCase()} ${resourceType}) | Code: [${findingCode}] | dryRun: ${dryRun}`);
    const { runRemediation: providerRemediator } = await definition.remediate();
    return providerRemediator(definition.id, credentials, resourceType, resourceName, issue, dryRun, options);
}
