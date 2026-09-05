import { log } from '../../logger.js';

/**
 * Hetzner Provider Verification Adapter
 * Validates API token by querying the authenticated /v1/servers endpoint.
 * Captures provenance: account/project identifier and verification method.
 */
export async function verify(credentials = {}) {
    const token = credentials.apiToken || credentials.token;

    if (!token) {
        return {
            verified: false,
            provider: 'hetzner',
            errorCode: 'CLOUD_AUTHENTICATION_FAILED',
            errorMessage: 'Missing Hetzner Cloud API token.'
        };
    }

    try {
        const resp = await fetch('https://api.hetzner.cloud/v1/servers', {
            headers: { Authorization: `Bearer ${token}` },
            signal: AbortSignal.timeout(2000)
        });

        if (!resp.ok) {
            log.warn(`[HETZNER-VERIFIER] Hetzner responded with HTTP ${resp.status}`);
            return {
                verified: false,
                provider: 'hetzner',
                errorCode: resp.status === 401 || resp.status === 403 ? 'CLOUD_AUTHENTICATION_FAILED' : 'CLOUD_PROVIDER_UNAVAILABLE',
                errorMessage: 'Hetzner Cloud API rejected the provided token.'
            };
        }

        const data = await resp.json();
        const serverCount = Array.isArray(data.servers) ? data.servers.length : 0;

        return {
            verified: true,
            provider: 'hetzner',
            accountIdentifier: `hetzner_project_${token.substring(0, 6)}`,
            principal: `hetzner_token_${token.substring(0, 6)}...`,
            verificationMethod: 'hetzner:GET /v1/servers',
            metadata: {
                serverCount
            }
        };
    } catch (err) {
        log.warn(`[HETZNER-VERIFIER] Hetzner verification network failure: ${err.message}`);
        return {
            verified: false,
            provider: 'hetzner',
            errorCode: 'CLOUD_CONNECTION_TIMEOUT',
            errorMessage: 'Could not connect to Hetzner Cloud API. Please try again.'
        };
    }
}
