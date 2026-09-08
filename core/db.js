import { Pool } from 'pg';

const pool = new Pool({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
    database: process.env.POSTGRES_DB || 'compflow',
    user: process.env.POSTGRES_USER || 'compflow_user',
    password: process.env.POSTGRES_PASSWORD || 'compflow_pass',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 1000
});

const SCHEMA_LOCK_KEY = "'compflow:schema'";
function isSchemaDdl(sql) { return typeof sql === 'string' && /^\s*(CREATE|ALTER|DROP)\s+/i.test(sql); }

const resilientPool = {
    async query(sql, params = []) {
        if (!isSchemaDdl(sql)) {
            try {
                return await pool.query(sql, params);
            } catch (err) {
                throw new Error(`[DB] PostgreSQL query failed: ${err.message}`);
            }
        }
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(`SELECT pg_advisory_xact_lock(hashtextextended(${SCHEMA_LOCK_KEY},0))`);
            const result = await client.query(sql, params);
            await client.query('COMMIT');
            return result;
        } catch (err) {
            await client.query('ROLLBACK').catch(() => {});
            throw new Error(`[DB] PostgreSQL schema query failed: ${err.message}`);
        } finally {
            client.release();
        }
    },
    async connect() {
        try {
            return await pool.connect();
        } catch (err) {
            throw new Error(`[DB] PostgreSQL connection unavailable: ${err.message}`);
        }
    }
};

// Auto-initialize jobs, tenants, authentication, and onboarding tables on startup.
// Database initialization is authoritative: startup must not silently continue with
// an incomplete schema or an in-memory substitute.
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

        CREATE TABLE IF NOT EXISTS identities (
            id VARCHAR(64) PRIMARY KEY,
            user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
            provider VARCHAR(32) NOT NULL,
            provider_subject VARCHAR(255) NOT NULL,
            provider_email VARCHAR(255),
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            last_login_at TIMESTAMPTZ,
            UNIQUE (provider, provider_subject)
        );
        CREATE INDEX IF NOT EXISTS idx_identities_user ON identities(user_id);

        CREATE TABLE IF NOT EXISTS audit_events (
            id VARCHAR(64) PRIMARY KEY,
            organization_id VARCHAR(64),
            actor_user_id VARCHAR(64),
            event_type VARCHAR(64) NOT NULL,
            resource_type VARCHAR(64),
            resource_id VARCHAR(64),
            metadata JSONB DEFAULT '{}'::jsonb,
            ip_address VARCHAR(45),
            user_agent TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_audit_events_org ON audit_events(organization_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);

        CREATE TABLE IF NOT EXISTS organization_frameworks (
            id VARCHAR(64) PRIMARY KEY,
            org_id VARCHAR(64) REFERENCES organizations(id) ON DELETE CASCADE,
            framework_id VARCHAR(32) NOT NULL,
            status VARCHAR(32) DEFAULT 'selected',
            selected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            selected_by VARCHAR(64),
            UNIQUE (org_id, framework_id)
        );

        CREATE TABLE IF NOT EXISTS onboarding_state (
            org_id VARCHAR(64) PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            status VARCHAR(32) DEFAULT 'AUTHENTICATED',
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS cloud_connections (
            id VARCHAR(64) PRIMARY KEY,
            organization_id VARCHAR(64) REFERENCES organizations(id),
            provider VARCHAR(32) NOT NULL,
            display_name VARCHAR(255),
            status VARCHAR(32) DEFAULT 'PENDING',
            account_identifier VARCHAR(255),
            region VARCHAR(32),
            credential_reference VARCHAR(255),
            created_by VARCHAR(64),
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            last_verified_at TIMESTAMPTZ,
            last_scan_at TIMESTAMPTZ,
            error_code VARCHAR(64),
            error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS secrets (
            id VARCHAR(64) PRIMARY KEY,
            org_id VARCHAR(64),
            connection_id VARCHAR(64),
            encrypted_data BYTEA NOT NULL,
            iv BYTEA NOT NULL,
            version INT DEFAULT 1,
            created_by VARCHAR(64),
            last_accessed_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id VARCHAR(64) PRIMARY KEY,
            organization_id VARCHAR(64) REFERENCES organizations(id),
            connection_id VARCHAR(64) REFERENCES cloud_connections(id),
            job_id VARCHAR(64),
            scan_type VARCHAR(64) DEFAULT 'initial_onboarding_scan',
            status VARCHAR(32) DEFAULT 'QUEUED',
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            error_code VARCHAR(64),
            error_message TEXT,
            resources_discovered INT DEFAULT 0,
            findings_count INT DEFAULT 0,
            evidence_count INT DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization_id);
        CREATE INDEX IF NOT EXISTS idx_scans_conn ON scans(connection_id);

        CREATE TABLE IF NOT EXISTS findings (
            id VARCHAR(64) PRIMARY KEY,
            organization_id VARCHAR(64) REFERENCES organizations(id),
            scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE CASCADE,
            resource_id VARCHAR(255),
            control_id VARCHAR(64),
            severity VARCHAR(32) NOT NULL,
            status VARCHAR(32) DEFAULT 'FAIL',
            code VARCHAR(64),
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(organization_id);

        ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT 'active';
        ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS website VARCHAR(255);
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS industry VARCHAR(64);
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS company_size VARCHAR(32);
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS onboarding_status VARCHAR(32) DEFAULT 'AUTHENTICATED';
        ALTER TABLE org_memberships ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT 'active';
        ALTER TABLE org_memberships ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
        ALTER TABLE sessions ADD COLUMN IF NOT EXISTS is_revoked BOOLEAN DEFAULT false;
        ALTER TABLE sessions ADD COLUMN IF NOT EXISTS rotated_from VARCHAR(64);
        ALTER TABLE cloud_connections ADD COLUMN IF NOT EXISTS principal VARCHAR(255);
        ALTER TABLE cloud_connections ADD COLUMN IF NOT EXISTS verification_method VARCHAR(64);
    `;

    try {
        await resilientPool.query(query);
    } catch (err) {
        console.error('[DB] Failed to initialize PostgreSQL schema:', err.message);
        throw err;
    }
}

export default resilientPool;
