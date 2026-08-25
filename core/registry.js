import pool from './db.js';

/**
 * ComplianceFlow AI — Tenant Registry with Org-Scoped Multi-Tenancy
 * Enforces organizational boundaries so tenants are strictly isolated per org.
 */

/**
 * Loads clients/tenants from PostgreSQL, filtered by orgId when provided.
 * If orgId is null or undefined, returns all tenants (for internal superadmin/worker sweeps).
 * 
 * @param {string|null} orgId - Organization ID from authenticated session
 * @returns {Promise<Array>} List of tenant objects
 */
export async function loadClients(orgId = null) {
    try {
        let query = 'SELECT * FROM tenants';
        const params = [];

        if (orgId) {
            query += ' WHERE org_id = $1';
            params.push(orgId);
        }

        query += ' ORDER BY created_at DESC';

        const res = await pool.query(query, params);
        return res.rows.map(r => ({
            id: r.id,
            orgId: r.org_id || 'org_default',
            name: r.name,
            provider: r.provider,
            roleArn: r.role_arn,
            apiToken: r.api_token,
            email: r.email,
            autoRemediate: r.auto_remediate,
            status: r.status,
            createdAt: r.created_at,
            updatedAt: r.updated_at
        }));
    } catch (e) {
        console.error('[REGISTRY] Failed to load clients from PostgreSQL:', e.message);
        return [];
    }
}

/**
 * Adds or updates a client/tenant in PostgreSQL, binding it to an organization.
 * 
 * @param {Object} clientData - Tenant details
 * @param {string} orgId - Organization ID from authenticated session
 */
export async function saveClient(clientData, orgId = 'org_default') {
    try {
        const tenantOrgId = clientData.orgId || orgId || 'org_default';
        const query = `
            INSERT INTO tenants (id, org_id, name, provider, role_arn, api_token, email, auto_remediate, status, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
            ON CONFLICT (id) DO UPDATE SET
                org_id = EXCLUDED.org_id,
                name = EXCLUDED.name,
                provider = EXCLUDED.provider,
                role_arn = EXCLUDED.role_arn,
                api_token = EXCLUDED.api_token,
                email = EXCLUDED.email,
                auto_remediate = EXCLUDED.auto_remediate,
                status = EXCLUDED.status,
                updated_at = CURRENT_TIMESTAMP;
        `;
        await pool.query(query, [
            clientData.id,
            tenantOrgId,
            clientData.name,
            clientData.provider,
            clientData.roleArn || null,
            clientData.apiToken || null,
            clientData.email || '',
            clientData.autoRemediate === true,
            clientData.status || 'active'
        ]);
        console.log(`[REGISTRY] Client ${clientData.name} (Org: ${tenantOrgId}) saved to PostgreSQL successfully.`);
    } catch (e) {
        console.error(`[REGISTRY] Failed to save client ${clientData.name}:`, e.message);
        throw e;
    }
}

/**
 * Gets a specific client/tenant by ID, with optional orgId isolation check.
 * 
 * @param {string} clientId - Tenant unique identifier
 * @param {string|null} orgId - Optional org ID to enforce tenant ownership
 * @returns {Promise<Object|null>} Tenant object if found and owned by org, null otherwise
 */
export async function getClient(clientId, orgId = null) {
    try {
        let query = 'SELECT * FROM tenants WHERE id = $1';
        const params = [clientId];

        if (orgId) {
            query += ' AND org_id = $2';
            params.push(orgId);
        }

        const res = await pool.query(query, params);
        if (res.rows.length === 0) return null;
        const r = res.rows[0];
        return {
            id: r.id,
            orgId: r.org_id || 'org_default',
            name: r.name,
            provider: r.provider,
            roleArn: r.role_arn,
            apiToken: r.api_token,
            email: r.email,
            autoRemediate: r.auto_remediate,
            status: r.status,
            createdAt: r.created_at,
            updatedAt: r.updated_at
        };
    } catch (e) {
        console.error(`[REGISTRY] Failed to get client ${clientId}:`, e.message);
        return null;
    }
}
