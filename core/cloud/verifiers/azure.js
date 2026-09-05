import { ClientSecretCredential } from '@azure/identity';
import { log } from '../../logger.js';

/**
 * Azure Provider Verification Adapter
 * Validates Azure Service Principal credentials by acquiring an OAuth2 token.
 * Captures provenance: subscription ID, client ID (principal), and verification method.
 */
export async function verify(credentials = {}) {
    const tenantId = credentials.tenantId;
    const clientId = credentials.clientId || credentials.accessKeyId;
    const clientSecret = credentials.clientSecret || credentials.secretAccessKey;
    const subscriptionId = credentials.subscriptionId;

    if (!tenantId || !clientId || !clientSecret) {
        return {
            verified: false,
            provider: 'azure',
            errorCode: 'CLOUD_AUTHENTICATION_FAILED',
            errorMessage: 'Missing Azure credentials (tenantId, clientId, and clientSecret are required).'
        };
    }

    try {
        const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
        const tokenResponse = await credential.getToken('https://management.azure.com/.default');

        if (!tokenResponse || !tokenResponse.token) {
            throw new Error('No token returned from Azure Identity service.');
        }

        const accountIdentifier = subscriptionId || `tenant_${tenantId.substring(0, 8)}`;
        const principal = `sp_${clientId.substring(0, 8)}...`;

        return {
            verified: true,
            provider: 'azure',
            accountIdentifier,
            principal,
            verificationMethod: 'azure:ClientSecretCredential.getToken',
            metadata: {
                tenantId,
                subscriptionId: subscriptionId || null,
                expiresOnTimestamp: tokenResponse.expiresOnTimestamp
            }
        };
    } catch (err) {
        log.warn(`[AZURE-VERIFIER] Azure Service Principal authentication failed: ${err.message}`);

        let errorCode = 'CLOUD_AUTHENTICATION_FAILED';
        if (err.message?.includes('timeout')) {
            errorCode = 'CLOUD_CONNECTION_TIMEOUT';
        } else if (err.message?.includes('denied') || err.message?.includes('unauthorized')) {
            errorCode = 'CLOUD_PERMISSION_DENIED';
        }

        return {
            verified: false,
            provider: 'azure',
            errorCode,
            errorMessage: 'Azure authentication failed. Please check your Tenant ID, Client ID, and Client Secret.'
        };
    }
}
