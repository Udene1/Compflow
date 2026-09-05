import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { log } from '../../logger.js';

/**
 * AWS Provider Verification Adapter
 * Validates IAM/STS credentials by performing an authenticated GetCallerIdentity call.
 * Captures provenance: account identifier, principal ARN, and verification method.
 */
export async function verify(credentials = {}) {
    const region = credentials.region || 'us-east-1';
    
    // Validate credential presence
    const accessKeyId = credentials.accessKeyId;
    const secretAccessKey = credentials.secretAccessKey;
    const sessionToken = credentials.sessionToken;
    const roleArn = credentials.roleArn;

    if (!roleArn && (!accessKeyId || !secretAccessKey)) {
        return {
            verified: false,
            provider: 'aws',
            errorCode: 'CLOUD_AUTHENTICATION_FAILED',
            errorMessage: 'Missing AWS credentials (accessKeyId and secretAccessKey, or roleArn required).'
        };
    }

    try {
        const sts = new STSClient({
            region,
            credentials: {
                accessKeyId,
                secretAccessKey,
                ...(sessionToken ? { sessionToken } : {})
            }
        });

        const callerIdentity = await sts.send(new GetCallerIdentityCommand({}));

        const accountIdentifier = callerIdentity.Account;
        const principal = callerIdentity.Arn || callerIdentity.UserId;

        return {
            verified: true,
            provider: 'aws',
            accountIdentifier,
            principal,
            verificationMethod: 'sts:GetCallerIdentity',
            metadata: {
                region,
                userId: callerIdentity.UserId
            }
        };
    } catch (err) {
        log.warn(`[AWS-VERIFIER] AWS STS authentication failed: ${err.message}`);
        
        let errorCode = 'CLOUD_AUTHENTICATION_FAILED';
        if (err.name === 'TimeoutError' || err.message?.includes('timeout')) {
            errorCode = 'CLOUD_CONNECTION_TIMEOUT';
        } else if (err.name === 'AccessDenied' || err.message?.includes('denied')) {
            errorCode = 'CLOUD_PERMISSION_DENIED';
        }

        return {
            verified: false,
            provider: 'aws',
            errorCode,
            errorMessage: 'AWS authentication failed. Please verify your access key ID and secret access key.'
        };
    }
}
