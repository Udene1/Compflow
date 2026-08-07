import pool from './db.js';

/**
 * Loads all clients/tenants from PostgreSQL.
 */
export async function loadClients() {
    try {
        const res = await pool.query('SELECT * FROM tenants ORDER BY created_at DESC');
        return res.rows.map(r => ({
            id: r.id,
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
 * Adds or updates a client/tenant in PostgreSQL.
 */
export async function saveClient(clientData) {
    try {
        const query = `
            INSERT INTO tenants (id, name, provider, role_arn, api_token, email, auto_remediate, status, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
            ON CONFLICT (id) DO UPDATE SET
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
            clientData.name,
            clientData.provider,
            clientData.roleArn || null,
            clientData.apiToken || null,
            clientData.email || '',
            clientData.autoRemediate === true,
            clientData.status || 'active'
        ]);
        console.log(`[REGISTRY] Client ${clientData.name} saved to PostgreSQL successfully.`);
    } catch (e) {
        console.error(`[REGISTRY] Failed to save client ${clientData.name}:`, e.message);
        throw e;
    }
}

/**
 * Gets a specific client/tenant by ID.
 */
export async function getClient(clientId) {
    try {
        const res = await pool.query('SELECT * FROM tenants WHERE id = $1', [clientId]);
        if (res.rows.length === 0) return null;
        const r = res.rows[0];
        return {
            id: r.id,
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
