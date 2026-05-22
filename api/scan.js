import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";

/**
 * Vercel Scan Proxy (Async)
 * Triggers a deep cloud scan on AWS Lambda asynchronously to bypass Vercel's 10s timeout limit.
 * The frontend will poll for results using the Audit API.
 */
export default async function handler(req, res) {
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    const clientConfig = { 
        region: process.env.AWS_REGION || "us-east-1"
    };

    if (process.env.PLATFORM_AWS_ACCESS_KEY_ID && process.env.PLATFORM_AWS_SECRET_ACCESS_KEY) {
        clientConfig.credentials = {
            accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY
        };
    }

    const lambda = new LambdaClient(clientConfig);
    const clientId = req.body.clientId || 'adhoc_user';
    const FUNCTION_NAME = process.env.SCAN_FUNCTION_NAME || "comp-flow-ains-dev-scan";

    try {
        console.log(`[SCAN-PROXY] Triggering async scan for ${clientId}...`);
        
        // Invoke Lambda asynchronously
        const command = new InvokeCommand({
            FunctionName: FUNCTION_NAME,
            InvocationType: 'Event', // This makes the call asynchronous
            Payload: JSON.stringify({ ...req.body, clientId })
        });

        await lambda.send(command);

        // Return immediately to the frontend
        return res.status(202).json({ 
            success: true, 
            status: 'queued', 
            clientId,
            message: 'Deep scan initiated. Polling for results...'
        });

    } catch (e) {
        console.error('[SCAN-PROXY] Failed to trigger Lambda:', e);
        return res.status(502).json({
            error: 'Could not reach the scanning backend.'
        });
    }
}
