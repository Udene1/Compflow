import { getClient } from '../core/registry.js';
import { createJob } from '../core/jobs.js';
import { enqueueJob } from '../core/queue.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).end();

    const { clientId } = req.body;
    if (!clientId) return res.status(400).json({ error: "Missing clientId" });

    try {
        const client = await getClient(clientId);
        if (!client) return res.status(404).json({ error: "Client not found" });

        console.log(`[API] Triggering manual scan for ${client.name}...`);

        const jobId = await createJob(clientId, 'on_demand');

        const job = await enqueueJob({
            ...client,
            jobId
        });

        return res.status(200).json({ 
            success: true, 
            message: "Scan dispatched to queue.",
            jobId,
            messageId: job.id
        });

    } catch (e) {
        console.error("Trigger API Error:", e);
        res.status(500).json({ error: e.message });
    }
}
