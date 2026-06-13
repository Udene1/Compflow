import { ControlMatrix } from './controls.js';
import { log } from './logger.js';

export async function runScan(provider, credentials) {
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
