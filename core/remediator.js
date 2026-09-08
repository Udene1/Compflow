import { getProvider } from './provider_registry.js';
import { log } from './logger.js';
import { resolveFindingCode } from './finding_codes.js';
import { getRemediationPolicy, REMEDIATION_AUTHORITY } from './remediation_policy.js';

/**
 * Provider execution is authorized by the canonical finding code, never by free-form
 * issue text. Providers historically used issue text for dispatch; passing the
 * canonical code as that internal dispatch token prevents a caller from selecting a
 * different mutation while retaining an otherwise valid finding code.
 */
export function canonicalProviderDispatchIssue(findingCode) {
    const normalized = String(findingCode || '').trim().toUpperCase();
    if (!normalized) throw new Error('REMEDIATION_CODE_REQUIRED');
    return normalized;
}

export async function runRemediation(provider, credentials, resourceType, resourceName, issue, dryRun = false, options = {}) {
    const definition = getProvider(provider);
    const findingCode = String(options.findingCode || resolveFindingCode(resourceType, issue) || '').trim().toUpperCase();
    const policy = getRemediationPolicy(findingCode);
    if (policy.authority === REMEDIATION_AUTHORITY.OBSERVE || policy.authority === REMEDIATION_AUTHORITY.RECOMMEND) {
        throw new Error('REMEDIATION_EXECUTION_NOT_AUTHORIZED');
    }
    const dispatchIssue = canonicalProviderDispatchIssue(findingCode);
    log.info(`[REMEDIATION] Target: ${resourceName} (${definition.id.toUpperCase()} ${resourceType}) | Code: [${findingCode}] | authority: ${policy.authority} | dryRun: ${dryRun}`);
    const { runRemediation: providerRemediator } = await definition.remediate();
    return providerRemediator(definition.id, credentials, resourceType, resourceName, dispatchIssue, dryRun, { ...options, findingCode });
}
