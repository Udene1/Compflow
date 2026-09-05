import { GoogleAuth } from 'google-auth-library';
import { log } from '../../logger.js';

/**
 * GCP Provider Verification Adapter
 * Validates Google Cloud Service Account credentials by calling GoogleAuth.getClient() & getProjectId().
 * Captures provenance: project ID, client email (principal), and verification method.
 */
export async function verify(credentials = {}) {
    let creds = credentials;
    if (typeof credentials.serviceAccountJson === 'string') {
        try {
            creds = JSON.parse(credentials.serviceAccountJson);
        } catch {
            return {
                verified: false,
                provider: 'gcp',
                errorCode: 'CLOUD_AUTHENTICATION_FAILED',
                errorMessage: 'Malformed serviceAccountJson string in GCP credentials.'
            };
        }
    } else if (credentials.apiToken && typeof credentials.apiToken === 'string' && credentials.apiToken.startsWith('{')) {
        try {
            creds = JSON.parse(credentials.apiToken);
        } catch {
            // Not a JSON string
        }
    }

    if (!creds || (!creds.client_email && !creds.project_id && !creds.private_key)) {
        return {
            verified: false,
            provider: 'gcp',
            errorCode: 'CLOUD_AUTHENTICATION_FAILED',
            errorMessage: 'Missing GCP service account credentials (project_id, client_email, or private_key required).'
        };
    }

    try {
        const auth = new GoogleAuth({
            credentials: creds,
            scopes: 'https://www.googleapis.com/auth/cloud-platform'
        });

        await auth.getClient();
        const projectId = await auth.getProjectId();

        return {
            verified: true,
            provider: 'gcp',
            accountIdentifier: projectId,
            principal: creds.client_email || `sa_${projectId}`,
            verificationMethod: 'gcp:GoogleAuth.getClient',
            metadata: {
                projectId,
                clientEmail: creds.client_email || null
            }
        };
    } catch (err) {
        log.warn(`[GCP-VERIFIER] Google Cloud authentication failed: ${err.message}`);

        let errorCode = 'CLOUD_AUTHENTICATION_FAILED';
        if (err.message?.includes('timeout')) {
            errorCode = 'CLOUD_CONNECTION_TIMEOUT';
        } else if (err.message?.includes('denied') || err.message?.includes('unauthorized')) {
            errorCode = 'CLOUD_PERMISSION_DENIED';
        }

        return {
            verified: false,
            provider: 'gcp',
            errorCode,
            errorMessage: 'GCP authentication failed. Please verify your Service Account credentials and project ID.'
        };
    }
}
