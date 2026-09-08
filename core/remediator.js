import { getProvider } from './provider_registry.js';
import { log } from './logger.js';
import { resolveFindingCode } from './finding_codes.js';
import { validateRemediationExecutionContract } from './remediation_execution_contract.js';

/**
 * Provider execution is authorized by the canonical finding code, never by free-form
 * issue text. The contract also binds the executable resource type and mutation text
 * to the deterministic remediation candidate before any provider module is loaded.
 */
export function canonicalProviderDispatchIssue(findingCode) {
    const normalized = String(findingCode || '').trim().toUpperCase();
    if (!normalized) throw new Error('REMEDIATION_CODE_REQUIRED');
    return normalized;
}

export async function runRemediation(provider, credentials, resourceType, resourceName, issue, dryRun = false, options = {}) {
    const definition = getProvider(provider);
    const findingCode = String(options.findingCode || resolveFindingCode(resourceType, issue) || '').trim().toUpperCase();
    const contract = validateRemediationExecutionContract({ code: findingCode, resourceType, action: issue });
    const dispatchIssue = canonicalProviderDispatchIssue(contract.code);
    log.info(`[REMEDIATION] Target: ${resourceName} (${definition.id.toUpperCase()} ${resourceType}) | Code: [${contract.code}] | authority: ${contract.authority} | dryRun: ${dryRun}`);
    const { runRemediation: providerRemediator } = await definition.remediate();
    return providerRemediator(definition.id, credentials, resourceType, resourceName, dispatchIssue, dryRun, { ...options, findingCode: contract.code });
}
