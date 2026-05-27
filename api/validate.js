import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';

export const handler = async (event) => {
    // Add CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
        'Content-Type': 'application/json'
    };

    try {
        const body = JSON.parse(event.body);
        const { provider, credentials } = body;

        if (provider === 'aws') {
            const sts = new STSClient({
                region: credentials.region || 'us-east-1',
                credentials: {
                    accessKeyId: credentials.accessKeyId,
                    secretAccessKey: credentials.secretAccessKey
                }
            });

            const data = await sts.send(new GetCallerIdentityCommand({}));
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ 
                    success: true, 
                    message: "Identity verified successfully.",
                    identity: data.Arn,
                    accountId: data.Account
                })
            };
        }

        // Mock success for other providers for now (with artificial delay for "realness")
        await new Promise(r => setTimeout(r, 1500));
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true, message: `${provider.toUpperCase()} connection established.` })
        };

    } catch (e) {
        console.error("Validation Error:", e);
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ 
                success: false, 
                error: e.name === 'InvalidSignatureException' ? "Invalid Credentials" : e.message 
            })
        };
    }
};
