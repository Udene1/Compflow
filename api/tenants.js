import { loadClients, saveClient, getClient } from '../core/registry.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * Multi-Tenant Organization Scoped Tenants API Handler
 * Enforces that users can only view, create, or modify cloud environments owned by their organization.
 */
export default async function handler(req, res) {
    const { method } = req;

    try {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        if (method === 'OPTIONS') {
            return res.status(200).end();
        }

        // Extract organization ID from authenticated user context (attached by requireAuth)
        const orgId = req.user?.orgId || req.authContext?.orgId || 'org_default';
        const userRole = req.user?.role || req.authContext?.role || 'VIEWER';

        // 1. GET: List all tenants for the user's organization
        if (method === 'GET') {
            // Superadmins / OWNERs can query all if explicitly requested, otherwise scoped to their org
            const tenants = await loadClients(orgId);
            return res.status(200).json({ 
                orgId,
                total: tenants.length,
                tenants 
            });
        }

        // 2. POST: Register a new cloud environment for this organization
        if (method === 'POST') {
            const { name, provider, roleArn, apiToken, email, autoRemediate } = req.body;
            if (!name || !provider) {
                return res.status(400).json({ error: "Missing required fields (name, provider)" });
            }

            const newTenant = {
                id: uuidv4(),
                orgId, // Strictly bind tenant to the authenticated organization
                name,
                provider,
                roleArn,
                apiToken,
                email: email || (req.user?.email || ""),
                autoRemediate: autoRemediate === true,
                status: 'active'
            };

            await saveClient(newTenant, orgId);
            return res.status(201).json({ success: true, tenant: newTenant });
        }

        // 3. PATCH: Update tenant settings (e.g. toggle auto-remediation)
        if (method === 'PATCH') {
            const { id, autoRemediate, status } = req.body;
            if (!id) return res.status(400).json({ error: "Missing tenant ID" });

            // Verify ownership: tenant MUST belong to user's org
            const tenant = await getClient(id, orgId);
            if (!tenant) {
                return res.status(404).json({ 
                    error: "Tenant not found or does not belong to your organization." 
                });
            }

            if (autoRemediate !== undefined) tenant.autoRemediate = autoRemediate === true;
            if (status !== undefined) tenant.status = status;

            await saveClient(tenant, orgId);
            return res.status(200).json({ success: true, tenant });
        }

        res.setHeader('Allow', ['GET', 'POST', 'PATCH', 'OPTIONS']);
        res.status(405).end(`Method ${method} Not Allowed`);

    } catch (e) {
        console.error("[API TENANTS ERROR]:", e);
        res.status(500).json({ error: e.message });
    }
}
