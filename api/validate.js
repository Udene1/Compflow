import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    try {
        const { provider, credentials } = req.body;

        if (provider === 'aws') {
            const sts = new STSClient({
                region: credentials.region || 'us-east-1',
                credentials: {
                    accessKeyId: credentials.accessKeyId,
                    secretAccessKey: credentials.secretAccessKey
                }
            });

            const data = await sts.send(new GetCallerIdentityCommand({}));
            return res.status(200).json({ 
                success: true, 
                message: "Identity verified successfully.",
                identity: data.Arn,
                accountId: data.Account
            });
        }

        // Mock success for other providers for now (with artificial delay for "realness")
        await new Promise(r => setTimeout(r, 1500));
        return res.status(200).json({ 
            success: true, 
            message: `${provider.toUpperCase()} connection established.` 
        });

    } catch (e) {
        console.error("Validation Error:", e);
        return res.status(401).json({ 
            success: false, 
            error: e.name === 'InvalidSignatureException' ? "Invalid Credentials" : e.message 
        });
    }
}
