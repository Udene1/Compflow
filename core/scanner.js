import { ControlMatrix } from './controls.js';
import { log } from './logger.js';
import { evaluateCustomPolicies } from './policy_engine.js';
import { getExecutionContext } from './execution_context.js';
import { persistScanGraph } from './execution_worker_hooks.js';
import { getProvider } from './provider_registry.js';

export async function runScan(provider, credentials, customPolicies = null) {
    const definition = getProvider(provider);
    log.info(`Initiating ${definition.id.toUpperCase()} scan...`);
    const { runScan: providerScan } = await definition.scan();
    let result = await providerScan(definition.id, credentials);

    if (result && result.resources) {
        result.resources.forEach(r => {
            if (r.technicalId && ControlMatrix[r.technicalId]) {
                r.controls = ControlMatrix[r.technicalId];
                r.control = ControlMatrix[r.technicalId].soc2 ? ControlMatrix[r.technicalId].soc2[0] : 'N/A';
            }
        });

        if (customPolicies && typeof customPolicies === 'object') {
            const policyViolations = evaluateCustomPolicies(result.resources, customPolicies);
            if (policyViolations.length > 0) result.resources.push(...policyViolations);
        }

        const context = getExecutionContext();
        if (context) {
            await persistScanGraph({
                organizationId: context.organizationId,
                executionId: context.executionId,
                provider: definition.id,
                resources: result.resources
            });
        }
    }

    return result;
}
