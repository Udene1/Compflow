import { log } from '../../logger.js';

/**
 * DigitalOcean Provider Verification Adapter
 * Validates API token by querying the authenticated /v2/account endpoint.
 * Captures provenance: account email, UUID, and verification method.
 */
export async function verify(credentials = {}) {
    const token = credentials.apiToken || credentials.token;

    if (!token) {
        return {
            verified: false,
            provider: 'digitalocean',
            errorCode: 'CLOUD_AUTHENTICATION_FAILED',
            errorMessage: 'Missing DigitalOcean personal access token.'
        };
    }

    try {
        const resp = await fetch('https://api.digitalocean.com/v2/account', {
            headers: { Authorization: `Bearer ${token}` },
            signal: AbortSignal.timeout(2000)
        });

        if (!resp.ok) {
            log.warn(`[DO-VERIFIER] DigitalOcean responded with HTTP ${resp.status}`);
            return {
                verified: false,
                provider: 'digitalocean',
                errorCode: resp.status === 401 || resp.status === 403 ? 'CLOUD_AUTHENTICATION_FAILED' : 'CLOUD_PROVIDER_UNAVAILABLE',
                errorMessage: 'DigitalOcean API rejected the personal access token.'
            };
        }

        const data = await resp.json();
        const account = data.account || {};

        return {
            verified: true,
            provider: 'digitalocean',
            accountIdentifier: account.email || account.uuid || 'do_account',
            principal: account.email || 'do_user',
            verificationMethod: 'digitalocean:GET /v2/account',
            metadata: {
                uuid: account.uuid,
                email: account.email,
                status: account.status
            }
        };
    } catch (err) {
        log.warn(`[DO-VERIFIER] DigitalOcean verification network failure: ${err.message}`);
        return {
            verified: false,
            provider: 'digitalocean',
            errorCode: 'CLOUD_CONNECTION_TIMEOUT',
            errorMessage: 'Could not connect to DigitalOcean API. Please try again.'
        };
    }
}
