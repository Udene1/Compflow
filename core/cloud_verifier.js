import * as awsVerifier from './cloud/verifiers/aws.js';
import * as azureVerifier from './cloud/verifiers/azure.js';
import * as gcpVerifier from './cloud/verifiers/gcp.js';
import * as digitalOceanVerifier from './cloud/verifiers/digitalocean.js';
import * as hetznerVerifier from './cloud/verifiers/hetzner.js';
import { log } from './logger.js';

const VERIFIERS = {
    aws: awsVerifier,
    azure: azureVerifier,
    gcp: gcpVerifier,
    digitalocean: digitalOceanVerifier,
    do: digitalOceanVerifier,
    hetzner: hetznerVerifier
};

/**
 * Universal Cloud Verifier Dispatcher
 * Dispatches credential verification to the respective provider adapter.
 * Captures verification provenance and normalizes error codes.
 */
export class CloudVerifier {
    constructor(verifiers = VERIFIERS) {
        this.verifiers = { ...verifiers };
    }

    /**
     * Register or override a verifier adapter (useful for testing)
     */
    registerVerifier(provider, adapter) {
        this.verifiers[provider.toLowerCase()] = adapter;
    }

    /**
     * Authenticate and verify cloud credentials
     * @param {string} provider - 'aws', 'azure', 'gcp', 'digitalocean', 'hetzner'
     * @param {Object} credentials - provider-specific secret credentials
     * @returns {Promise<Object>} Verification result with provenance
     */
    async verify(provider, credentials) {
        const normalizedProvider = (provider || '').toLowerCase().trim();
        const adapter = this.verifiers[normalizedProvider];

        if (!adapter) {
            log.warn(`[CLOUD-VERIFIER] Unsupported cloud provider: "${provider}"`);
            return {
                verified: false,
                provider: normalizedProvider,
                errorCode: 'UNSUPPORTED_PROVIDER',
                errorMessage: `Unsupported cloud provider "${provider}". Supported: aws, azure, gcp, digitalocean, hetzner.`
            };
        }

        try {
            const result = await adapter.verify(credentials);
            return result;
        } catch (err) {
            log.error(`[CLOUD-VERIFIER] Unexpected error running ${provider} verifier:`, err.message);
            return {
                verified: false,
                provider: normalizedProvider,
                errorCode: 'CLOUD_PROVIDER_UNAVAILABLE',
                errorMessage: `Cloud provider verification service encountered an unexpected error: ${err.message}`
            };
        }
    }
}

export const cloudVerifier = new CloudVerifier();
export default cloudVerifier;
