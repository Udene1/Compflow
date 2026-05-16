import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';

/**
 * Platform-level STS client.
 * Uses PLATFORM_AWS_* env vars — the platform's own AWS identity.
 * This identity has ONLY sts:AssumeRole and ses:SendEmail permissions.
 */
const stsConfig = {
    region: process.env.AWS_REGION || 'us-east-1'
};

// Use explicit keys if provided (for local dev/Vercel), 
// otherwise let the SDK use the IAM Role (for AWS Lambda).
if (process.env.PLATFORM_AWS_ACCESS_KEY_ID && process.env.PLATFORM_AWS_SECRET_ACCESS_KEY) {
    stsConfig.credentials = {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY,
    };
}

const stsClient = new STSClient(stsConfig);

/**
 * Assumes a client's cross-account IAM role and returns temporary credentials.
 * Mandatory ExternalId is used to prevent the "Confused Deputy" problem.
 * 
 * @param {string} roleArn - The client's IAM Role ARN
 * @param {string} clientId - Unique client identifier (used as session name)
 * @param {string} externalId - Required unique external ID for this client
 * @returns {Promise<{accessKeyId: string, secretAccessKey: string, sessionToken: string}>}
 */
export async function getClientCredentials(roleArn, clientId, externalId) {
    if (!externalId) {
        throw new Error(`[SECURITY] Attempted AssumeRole for ${clientId} without ExternalId. Aborting to prevent Confused Deputy risk.`);
    }

    const command = new AssumeRoleCommand({
        RoleArn: roleArn,
        RoleSessionName: `complianceflow-${clientId}-${Date.now()}`,
        ExternalId: externalId,
        DurationSeconds: 3600, // 1 hour TTL
    });

    const response = await stsClient.send(command);
    
    return {
        accessKeyId: response.Credentials.AccessKeyId,
        secretAccessKey: response.Credentials.SecretAccessKey,
        sessionToken: response.Credentials.SessionToken,
    };
}

/**
 * Validates that all platform-level environment variables are set.
 * Call this at agent startup to fail fast with a clear error.
 */
export function validatePlatformEnv() {
    const required = [
        'PLATFORM_AWS_ACCESS_KEY_ID',
        'PLATFORM_AWS_SECRET_ACCESS_KEY',
        'GEMINI_API_KEY',
    ];

    const missing = required.filter(key => !process.env[key]);

    if (missing.length > 0) {
        const isProduction = process.env.NODE_ENV === 'production';
        const message = `[CREDENTIALS] Missing environment variables: ${missing.join(', ')}`;
        
        if (isProduction) {
            throw new Error(message);
        } else {
            console.warn(`⚠️  ${message} — running in degraded mode.`);
        }
    }

    return missing.length === 0;
}
