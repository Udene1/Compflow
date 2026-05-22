import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";

export default async function handler(req, res) {
    // 1. Always return JSON
    try {
        if (req.method === 'OPTIONS') return res.status(200).end();
        
        // 2. Validate Env
        const LAMBDA_KEY = process.env.PLATFORM_AWS_ACCESS_KEY_ID;
        const LAMBDA_SECRET = process.env.PLATFORM_AWS_SECRET_ACCESS_KEY;
        const FUNCTION_NAME = process.env.SCAN_FUNCTION_NAME || "comp-flow-ains-dev-scan";
        
        if (!LAMBDA_KEY || !LAMBDA_SECRET) {
            return res.status(503).json({ error: "Cloud scanner credentials missing in environment." });
        }

        // 3. Initialize Client
        const lambda = new LambdaClient({
            region: process.env.AWS_REGION || "us-east-1",
            credentials: {
                accessKeyId: LAMBDA_KEY,
                secretAccessKey: LAMBDA_SECRET
            }
        });

        // 4. Trigger Async
        const payload = {
            provider: req.body?.provider,
            credentials: req.body?.credentials,
            clientId: req.body?.clientId || 'adhoc_user',
            email: req.body?.email
        };

        console.log(`[SCAN-PROXY] dispatching to ${FUNCTION_NAME}`);

        const command = new InvokeCommand({
            FunctionName: FUNCTION_NAME,
            InvocationType: 'Event',
            Payload: Buffer.from(JSON.stringify(payload))
        });

        await lambda.send(command);

        return res.status(202).json({ 
            success: true, 
            status: 'queued', 
            clientId: payload.clientId 
        });

    } catch (err) {
        console.error('[SCAN-PROXY] Fatal Error:', err);
        return res.status(500).json({ 
            error: "Internal server error triggering scan. " + err.message 
        });
    }
}
