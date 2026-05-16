import { loadClients, saveClient, getClient } from '../core/registry.js';
import { v4 as uuidv4 } from 'uuid';

export default async function handler(req, res) {
    const { method } = req;

    try {
        if (method === 'GET') {
            const tenants = await loadClients();
            return res.status(200).json({ tenants });
        }

        if (method === 'POST') {
            const { name, provider, roleArn, apiToken, email, autoRemediate } = req.body;
            if (!name || !provider) return res.status(400).json({ error: "Missing required fields" });

            const newTenant = {
                id: uuidv4(),
                name,
                provider,
                roleArn,
                apiToken,
                email: email || "",
                autoRemediate: autoRemediate === true,
                status: 'active'
            };

            await saveClient(newTenant);
            return res.status(201).json({ success: true, tenant: newTenant });
        }

        // Specific toggle endpoint logic can be handled here or in separate file
        if (method === 'PATCH') {
            const { id, autoRemediate } = req.body;
            const tenant = await getClient(id);
            if (!tenant) return res.status(404).json({ error: "Tenant not found" });

            tenant.autoRemediate = autoRemediate;
            await saveClient(tenant);
            return res.status(200).json({ success: true });
        }

        res.setHeader('Allow', ['GET', 'POST', 'PATCH']);
        res.status(405).end(`Method ${method} Not Allowed`);

    } catch (e) {
        console.error("API Tenants Error:", e);
        res.status(500).json({ error: e.message });
    }
}
