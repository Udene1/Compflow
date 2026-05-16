import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { getClient } from '../core/registry.js';

const sqs = new SQSClient({ 
    region: process.env.AWS_REGION || "us-east-1",
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY
    }
});

const QUEUE_URL = process.env.SCAN_QUEUE_URL;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).end();

    const { clientId } = req.body;
    if (!clientId) return res.status(400).json({ error: "Missing clientId" });

    try {
        const client = await getClient(clientId);
        if (!client) return res.status(404).json({ error: "Client not found" });

        console.log(`[API] Triggering manual scan for ${client.name}...`);

        await sqs.send(new SendMessageCommand({
            QueueUrl: QUEUE_URL,
            MessageBody: JSON.stringify({ ...client, credentials: { ...client } }) // Pass client as creds for now, adapter will map it
        }));

        return res.status(200).json({ success: true, message: "Scan dispatched to queue." });

    } catch (e) {
        console.error("Trigger API Error:", e);
        res.status(500).json({ error: e.message });
    }
}
