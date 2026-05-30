import { getClient, saveClient } from '../../core/registry.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).end();

    const { id, autoRemediate } = req.body;
    if (!id) return res.status(400).json({ error: "Missing id" });

    try {
        const tenant = await getClient(id);
        if (!tenant) return res.status(404).json({ error: "Tenant not found" });

        tenant.autoRemediate = autoRemediate;
        await saveClient(tenant);
        
        return res.status(200).json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
}
