import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";
import { createJob } from '../core/jobs.js';

/**
 * Scan Proxy (Vercel API Route)
 * Creates a job record, triggers Lambda async, returns jobId.
 * Total execution: ~2-3 seconds (safe for Vercel free tier).
 */
export default async function handler(req, res) {
    try {
        if (req.method === 'OPTIONS') return res.status(200).end();
        if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

        // 1. Validate env
        const LAMBDA_KEY = process.env.PLATFORM_AWS_ACCESS_KEY_ID;
        const LAMBDA_SECRET = process.env.PLATFORM_AWS_SECRET_ACCESS_KEY;
        const FUNCTION_NAME = process.env.SCAN_FUNCTION_NAME || "comp-flow-ains-dev-scan";
        
        if (!LAMBDA_KEY || !LAMBDA_SECRET) {
            return res.status(503).json({ error: "Cloud scanner credentials missing in environment." });
        }

        // 2. Create a job record in DynamoDB
        const clientId = req.body?.clientId || 'adhoc_user';
        const jobId = await createJob(clientId, 'on_demand');

        // 3. Initialize Lambda client
        const lambda = new LambdaClient({
            region: process.env.AWS_REGION || "us-east-1",
            credentials: {
                accessKeyId: LAMBDA_KEY,
                secretAccessKey: LAMBDA_SECRET
            }
        });

        // 4. Trigger Lambda async with jobId
        const payload = {
            jobId,
            provider: req.body?.provider,
            credentials: req.body?.credentials,
            clientId,
            email: req.body?.email
        };

        console.log(`[SCAN-PROXY] Job ${jobId} → dispatching to ${FUNCTION_NAME}`);

        const command = new InvokeCommand({
            FunctionName: FUNCTION_NAME,
            InvocationType: 'Event',
            Payload: Buffer.from(JSON.stringify(payload))
        });

        await lambda.send(command);

        // 5. Return jobId immediately
        return res.status(202).json({ 
            success: true, 
            status: 'queued', 
            jobId,
            clientId
        });

    } catch (err) {
        console.error('[SCAN-PROXY] Fatal Error:', err);
        return res.status(500).json({ 
            error: "Internal server error triggering scan. " + err.message 
        });
    }
}
