import { runScan as scanAWS } from './providers/aws.js';
import { runScan as scanHetzner } from './providers/hetzner.js';
import { runScan as scanDO } from './providers/digitalocean.js';
import { runScan as scanGCP } from './providers/gcp.js';
import { runScan as scanAzure } from './providers/azure.js';
import { ControlMatrix } from './controls.js';
import { log } from './logger.js';

export async function runScan(provider, credentials) {
    log.info(`Initiating ${provider.toUpperCase()} scan...`);

    let result;
    switch (provider.toLowerCase()) {
        case 'aws':
            result = await scanAWS(provider, credentials);
            break;
        case 'hetzner':
            result = await scanHetzner(provider, credentials);
            break;
        case 'digitalocean':
        case 'do':
            result = await scanDO(provider, credentials);
            break;
        case 'gcp':
            result = await scanGCP(provider, credentials);
            break;
        case 'azure':
            result = await scanAzure(provider, credentials);
            break;
        default:
            throw new Error(`Unsupported cloud provider: ${provider}`);
    }

    // Enrich with Multi-Framework Controls
    if (result && result.resources) {
        result.resources.forEach(r => {
            if (r.technicalId && ControlMatrix[r.technicalId]) {
                r.controls = ControlMatrix[r.technicalId];
                // For backward compatibility, also set a primary 'control' string
                r.control = ControlMatrix[r.technicalId].soc2 ? ControlMatrix[r.technicalId].soc2[0] : 'N/A';
            }
        });
    }

    return result;
}
