import { runScan as scanAWS } from './providers/aws.js';
import { runScan as scanHetzner } from './providers/hetzner.js';
import { runScan as scanDO } from './providers/digitalocean.js';
import { log } from './logger.js';

export async function runScan(provider, credentials) {
    log.info(`Initiating ${provider.toUpperCase()} scan...`);

    switch (provider.toLowerCase()) {
        case 'aws':
            return await scanAWS(provider, credentials);
        case 'hetzner':
            return await scanHetzner(provider, credentials);
        case 'digitalocean':
        case 'do':
            return await scanDO(provider, credentials);
        default:
            throw new Error(`Unsupported cloud provider: ${provider}`);
    }
}
