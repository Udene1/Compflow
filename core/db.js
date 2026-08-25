let pool = null;

class MemoryFallbackPool {
    constructor() {
        this.tenants = [];
        this.organizations = [];
        this.users = [];
        this.memberships = [];
        this.sessions = [];
        this.jobs = new Map();
    }

    async query(sql, params = []) {
        // Simple mock query evaluator for fallback mode
        if (sql.includes('SELECT * FROM tenants')) {
            if (sql.includes('WHERE org_id = $1') && params.length > 0) {
                return { rows: this.tenants.filter(t => t.org_id === params[0]) };
            }
            if (sql.includes('WHERE id = $1 AND org_id = $2') && params.length >= 2) {
                const found = this.tenants.filter(t => t.id === params[0] && t.org_id === params[1]);
                return { rows: found };
            }
            if (sql.includes('WHERE id = $1') && params.length > 0) {
                return { rows: this.tenants.filter(t => t.id === params[0]) };
            }
            return { rows: this.tenants };
        }
        if (sql.includes('INSERT INTO tenants')) {
            const [id, orgId, name, provider, roleArn, apiToken, email, autoRemediate, status] = params;
            const existingIdx = this.tenants.findIndex(t => t.id === id);
            const record = { id, org_id: orgId || 'org_default', name, provider, role_arn: roleArn, api_token: apiToken, email, auto_remediate: autoRemediate, status, created_at: new Date() };
            if (existingIdx >= 0) {
                this.tenants[existingIdx] = record;
            } else {
                this.tenants.push(record);
            }
            return { rowCount: 1 };
        }
        if (sql.includes('SELECT * FROM users WHERE email = $1')) {
            const user = this.users.find(u => u.email === params[0]);
            return { rows: user ? [user] : [] };
        }
        if (sql.includes('INSERT INTO users')) {
            const [id, email, name, avatarUrl] = params;
            const existingIdx = this.users.findIndex(u => u.id === id || u.email === email);
            const user = { id, email, name, avatar_url: avatarUrl, created_at: new Date() };
            if (existingIdx >= 0) {
                this.users[existingIdx] = { ...this.users[existingIdx], ...user };
            } else {
                this.users.push(user);
            }
            return { rows: [user], rowCount: 1 };
        }
        if (sql.includes('SELECT * FROM organizations WHERE id = $1')) {
            const org = this.organizations.find(o => o.id === params[0]);
            return { rows: org ? [org] : [] };
        }
        if (sql.includes('INSERT INTO organizations')) {
            const [id, name, domain, ssoProvider] = params;
            const org = { id, name, domain, sso_provider: ssoProvider, created_at: new Date() };
            this.organizations.push(org);
            return { rows: [org], rowCount: 1 };
        }
        if (sql.includes('SELECT * FROM org_memberships')) {
            const [userId, orgId] = params;
            const m = this.memberships.find(x => x.user_id === userId && x.org_id === orgId);
            return { rows: m ? [m] : [] };
        }
        if (sql.includes('INSERT INTO org_memberships')) {
            const [userId, orgId, role] = params;
            const record = { user_id: userId, org_id: orgId, role: role || 'ENGINEER', joined_at: new Date() };
            this.memberships.push(record);
            return { rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
    }
}

const fallbackPool = new MemoryFallbackPool();
let realPool = null;

try {
    const { default: pg } = await import('pg');
    const { Pool } = pg;
    realPool = new Pool({
        host: process.env.POSTGRES_HOST || 'localhost',
        port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
        database: process.env.POSTGRES_DB || 'compflow',
        user: process.env.POSTGRES_USER || 'compflow_user',
        password: process.env.POSTGRES_PASSWORD || 'compflow_pass',
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 1000
    });
} catch (e) {
    realPool = null;
}

const resilientPool = {
    async query(sql, params = []) {
        if (realPool) {
            try {
                return await realPool.query(sql, params);
            } catch (err) {
                if (err.code === 'ECONNREFUSED' || err.message?.includes('connect') || err.message?.includes('timeout')) {
                    return await fallbackPool.query(sql, params);
                }
                throw err;
            }
        }
        return await fallbackPool.query(sql, params);
    }
};

// Auto-initialize jobs, tenants, and authentication tables on startup
export async function initDb() {
    const query = `
        CREATE TABLE IF NOT EXISTS jobs (
            job_id VARCHAR(64) PRIMARY KEY,
            client_id VARCHAR(64) NOT NULL,
            scan_type VARCHAR(32) DEFAULT 'on_demand',
            status VARCHAR(32) DEFAULT 'queued',
            progress INT DEFAULT 0,
            logs JSONB DEFAULT '[]'::jsonb,
            resources JSONB DEFAULT '[]'::jsonb,
            error_message TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP WITH TIME ZONE,
            expires_at INT
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_client_id ON jobs(client_id);

        CREATE TABLE IF NOT EXISTS tenants (
            id VARCHAR(64) PRIMARY KEY,
            org_id VARCHAR(64) DEFAULT 'org_default',
            name VARCHAR(255) NOT NULL,
            provider VARCHAR(64) NOT NULL,
            role_arn TEXT,
            api_token TEXT,
            email VARCHAR(255),
            auto_remediate BOOLEAN DEFAULT false,
            status VARCHAR(32) DEFAULT 'active',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_tenants_org_id ON tenants(org_id);
        ALTER TABLE tenants ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) DEFAULT 'org_default';

        -- Multi-Tenant Team Authentication & SSO Schema
        CREATE TABLE IF NOT EXISTS organizations (
            id VARCHAR(64) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            domain VARCHAR(255),
            sso_provider VARCHAR(32) DEFAULT 'native',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(64) PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255),
            avatar_url TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS org_memberships (
            user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
            org_id VARCHAR(64) REFERENCES organizations(id) ON DELETE CASCADE,
            role VARCHAR(32) DEFAULT 'ENGINEER',
            joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, org_id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id VARCHAR(64) PRIMARY KEY,
            user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
            org_id VARCHAR(64) REFERENCES organizations(id) ON DELETE CASCADE,
            token_hash VARCHAR(255) NOT NULL,
            role VARCHAR(32) DEFAULT 'ENGINEER',
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;

    try {
        await resilientPool.query(query);
    } catch (err) {
        console.error('[DB] Failed to initialize PostgreSQL table:', err.message);
    }
}

export default resilientPool;
