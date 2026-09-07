import { ControlMatrix } from './controls.js';
import { log } from './logger.js';
import { evaluateCustomPolicies } from './policy_engine.js';
import { getExecutionContext } from './execution_context.js';
import { persistScanGraph } from './execution_worker_hooks.js';

export async function runScan(provider, credentials, customPolicies = null) {
    log.info(`Initiating ${provider.toUpperCase()} scan...`);

    let result;
    switch (provider.toLowerCase()) {
        case 'aws': {
            const { runScan: scanAWS } = await import('./providers/aws.js');
            result = await scanAWS(provider, credentials);
            break;
        }
        case 'hetzner': {
            const { runScan: scanHetzner } = await import('./providers/hetzner.js');
            result = await scanHetzner(provider, credentials);
            break;
        }
        case 'digitalocean':
        case 'do': {
            const { runScan: scanDO } = await import('./providers/digitalocean.js');
            result = await scanDO(provider, credentials);
            break;
        }
        case 'gcp': {
            const { runScan: scanGCP } = await import('./providers/gcp.js');
            result = await scanGCP(provider, credentials);
            break;
        }
        case 'azure': {
            const { runScan: scanAzure } = await import('./providers/azure.js');
            result = await scanAzure(provider, credentials);
            break;
        }
        default:
            throw new Error(`Unsupported cloud provider: ${provider}`);
    }

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

        // When running inside the durable queue worker, persist the exact observation
        // -> control -> evidence relationships while the scan result is still in scope.
        const context = getExecutionContext();
        if (context) {
            await persistScanGraph({
                organizationId: context.organizationId,
                executionId: context.executionId,
                provider,
                resources: result.resources
            });
        }
    }

    return result;
}
