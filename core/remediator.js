import { getProvider } from './provider_registry.js';
import { log } from './logger.js';
import { resolveFindingCode } from './finding_codes.js';
import { getRemediationPolicy, REMEDIATION_AUTHORITY } from './remediation_policy.js';

export async function runRemediation(provider, credentials, resourceType, resourceName, issue, dryRun = false, options = {}) {
    const definition = getProvider(provider);
    const findingCode = String(options.findingCode || resolveFindingCode(resourceType, issue) || '').trim().toUpperCase();
    const policy = getRemediationPolicy(findingCode);
    if (policy.authority === REMEDIATION_AUTHORITY.OBSERVE || policy.authority === REMEDIATION_AUTHORITY.RECOMMEND) {
        throw new Error('REMEDIATION_EXECUTION_NOT_AUTHORIZED');
    }
    log.info(`[REMEDIATION] Target: ${resourceName} (${definition.id.toUpperCase()} ${resourceType}) | Code: [${findingCode}] | authority: ${policy.authority} | dryRun: ${dryRun}`);
    const { runRemediation: providerRemediator } = await definition.remediate();
    return providerRemediator(definition.id, credentials, resourceType, resourceName, issue, dryRun, { ...options, findingCode });
}
