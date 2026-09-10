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
            try { return await pool.query(sql, params); }
            catch (err) { throw new Error(`[DB] PostgreSQL query failed: ${err.message}`); }
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
        } finally { client.release(); }
    },
    async connect() {
        try { return await pool.connect(); }
        catch (err) { throw new Error(`[DB] PostgreSQL connection unavailable: ${err.message}`); }
    }
};

// All authoritative schema is initialized once at startup. Runtime modules must
// never perform DDL because DDL can take AccessExclusiveLocks and deadlock with
// legitimate transactional reads/writes from concurrent workers.
export async function initDb() {
    const query = `
        CREATE TABLE IF NOT EXISTS jobs (
            job_id VARCHAR(64) PRIMARY KEY, client_id VARCHAR(64) NOT NULL, org_id VARCHAR(64),
            scan_type VARCHAR(32) DEFAULT 'on_demand', status VARCHAR(32) DEFAULT 'queued', progress INT DEFAULT 0,
            logs JSONB DEFAULT '[]'::jsonb, resources JSONB DEFAULT '[]'::jsonb, error_message TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP WITH TIME ZONE, expires_at INT
        );
        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS org_id VARCHAR(64);
        CREATE INDEX IF NOT EXISTS idx_jobs_client_id ON jobs(client_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_org_id ON jobs(org_id);
        CREATE TABLE IF NOT EXISTS tenants (
            id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) DEFAULT 'org_default', name VARCHAR(255) NOT NULL,
            provider VARCHAR(64) NOT NULL, role_arn TEXT, api_token TEXT, email VARCHAR(255), auto_remediate BOOLEAN DEFAULT false,
            status VARCHAR(32) DEFAULT 'active', created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_tenants_org_id ON tenants(org_id);
        ALTER TABLE tenants ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) DEFAULT 'org_default';
        CREATE TABLE IF NOT EXISTS organizations (
            id VARCHAR(64) PRIMARY KEY, name VARCHAR(255) NOT NULL, domain VARCHAR(255),
            sso_provider VARCHAR(32) DEFAULT 'native', created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(64) PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, name VARCHAR(255), avatar_url TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT 'active';
        ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
        CREATE TABLE IF NOT EXISTS org_memberships (
            user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE, org_id VARCHAR(64) REFERENCES organizations(id) ON DELETE CASCADE,
            role VARCHAR(32) DEFAULT 'ENGINEER', joined_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, org_id)
        );
        ALTER TABLE org_memberships ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT 'active';
        ALTER TABLE org_memberships ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
        CREATE TABLE IF NOT EXISTS sessions (
            id VARCHAR(64) PRIMARY KEY, user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
            org_id VARCHAR(64) REFERENCES organizations(id) ON DELETE CASCADE, token_hash VARCHAR(255) NOT NULL,
            role VARCHAR(32) DEFAULT 'ENGINEER', expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        ALTER TABLE sessions ADD COLUMN IF NOT EXISTS is_revoked BOOLEAN DEFAULT false;
        ALTER TABLE sessions ADD COLUMN IF NOT EXISTS rotated_from VARCHAR(64);
        CREATE TABLE IF NOT EXISTS identities (
            id VARCHAR(64) PRIMARY KEY, user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
            provider VARCHAR(32) NOT NULL, provider_subject VARCHAR(255) NOT NULL, provider_email VARCHAR(255),
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            last_login_at TIMESTAMPTZ, UNIQUE (provider, provider_subject)
        );
        CREATE INDEX IF NOT EXISTS idx_identities_user ON identities(user_id);
        CREATE TABLE IF NOT EXISTS audit_events (
            id VARCHAR(64) PRIMARY KEY, organization_id VARCHAR(64), actor_user_id VARCHAR(64), event_type VARCHAR(64) NOT NULL,
            resource_type VARCHAR(64), resource_id VARCHAR(64), metadata JSONB DEFAULT '{}'::jsonb,
            ip_address VARCHAR(45), user_agent TEXT, created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_audit_events_org ON audit_events(organization_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
        CREATE TABLE IF NOT EXISTS organization_frameworks (
            id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) REFERENCES organizations(id) ON DELETE CASCADE,
            framework_id VARCHAR(32) NOT NULL, status VARCHAR(32) DEFAULT 'selected', selected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            selected_by VARCHAR(64), UNIQUE (org_id, framework_id)
        );
        CREATE TABLE IF NOT EXISTS onboarding_state (
            org_id VARCHAR(64) PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            status VARCHAR(32) DEFAULT 'AUTHENTICATED', updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, completed_at TIMESTAMPTZ
        );
        CREATE TABLE IF NOT EXISTS cloud_connections (
            id VARCHAR(64) PRIMARY KEY, organization_id VARCHAR(64) REFERENCES organizations(id), provider VARCHAR(32) NOT NULL,
            display_name VARCHAR(255), status VARCHAR(32) DEFAULT 'PENDING', account_identifier VARCHAR(255), region VARCHAR(32),
            credential_reference VARCHAR(255), created_by VARCHAR(64), created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, last_verified_at TIMESTAMPTZ, last_scan_at TIMESTAMPTZ,
            error_code VARCHAR(64), error_message TEXT
        );
        CREATE TABLE IF NOT EXISTS secrets (
            id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64), connection_id VARCHAR(64), encrypted_data BYTEA NOT NULL, iv BYTEA NOT NULL,
            version INT DEFAULT 1, created_by VARCHAR(64), last_accessed_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scans (
            id VARCHAR(64) PRIMARY KEY, organization_id VARCHAR(64) REFERENCES organizations(id), connection_id VARCHAR(64) REFERENCES cloud_connections(id),
            job_id VARCHAR(64), scan_type VARCHAR(64) DEFAULT 'initial_onboarding_scan', status VARCHAR(32) DEFAULT 'QUEUED',
            started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, error_code VARCHAR(64), error_message TEXT,
            resources_discovered INT DEFAULT 0, findings_count INT DEFAULT 0, evidence_count INT DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization_id);
        CREATE INDEX IF NOT EXISTS idx_scans_conn ON scans(connection_id);
        CREATE TABLE IF NOT EXISTS findings (
            id VARCHAR(64) PRIMARY KEY, organization_id VARCHAR(64) REFERENCES organizations(id), scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE CASCADE,
            resource_id VARCHAR(255), control_id VARCHAR(64), severity VARCHAR(32) NOT NULL, status VARCHAR(32) DEFAULT 'FAIL',
            code VARCHAR(64), created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(organization_id);
        CREATE TABLE IF NOT EXISTS organization_entitlements (
            organization_id VARCHAR(64) PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            plan VARCHAR(32) NOT NULL, status VARCHAR(32) NOT NULL, source VARCHAR(64) NOT NULL,
            starts_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMPTZ,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK (plan IN ('pilot','trial','standard','enterprise')),
            CHECK (status IN ('ACTIVE','TRIAL','PILOT','PAST_DUE','CANCELED'))
        );
        CREATE INDEX IF NOT EXISTS organization_entitlements_status_idx ON organization_entitlements (status, expires_at);
        CREATE TABLE IF NOT EXISTS execution_runs (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', lease_owner TEXT, lease_token TEXT,
            lease_expires_at TIMESTAMPTZ, heartbeat_at TIMESTAMPTZ, started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
            error_code TEXT, error_message TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, version BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (status IN ('PENDING','RUNNING','SUCCEEDED','FAILED','CANCELLED'))
        );
        CREATE INDEX IF NOT EXISTS execution_runs_org_status_idx ON execution_runs (organization_id, status, updated_at);
        CREATE INDEX IF NOT EXISTS execution_runs_lease_idx ON execution_runs (organization_id, lease_expires_at) WHERE status = 'RUNNING';
        CREATE TABLE IF NOT EXISTS execution_graph_nodes (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, node_type TEXT NOT NULL, logical_key TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING', label TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (organization_id, execution_id, node_type, logical_key)
        );
        CREATE INDEX IF NOT EXISTS execution_graph_nodes_execution_idx ON execution_graph_nodes (organization_id, execution_id);
        CREATE TABLE IF NOT EXISTS execution_graph_edges (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL,
            from_node_id TEXT NOT NULL REFERENCES execution_graph_nodes(id) ON DELETE CASCADE,
            to_node_id TEXT NOT NULL REFERENCES execution_graph_nodes(id) ON DELETE CASCADE,
            edge_type TEXT NOT NULL DEFAULT 'DEPENDS_ON', metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (execution_id, from_node_id, to_node_id, edge_type)
        );
        CREATE INDEX IF NOT EXISTS execution_graph_edges_execution_idx ON execution_graph_edges (organization_id, execution_id);
        CREATE TABLE IF NOT EXISTS execution_attempts (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL,
            node_id TEXT NOT NULL REFERENCES execution_graph_nodes(id) ON DELETE CASCADE, attempt_number INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'RUNNING', started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), finished_at TIMESTAMPTZ,
            heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), error_code TEXT, error_message TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            UNIQUE (node_id, attempt_number)
        );
        CREATE INDEX IF NOT EXISTS execution_attempts_execution_idx ON execution_attempts (organization_id, execution_id, started_at);
        CREATE INDEX IF NOT EXISTS execution_attempts_running_heartbeat_idx ON execution_attempts (organization_id, status, heartbeat_at) WHERE status = 'RUNNING';
        CREATE UNIQUE INDEX IF NOT EXISTS execution_attempts_one_running_node_idx ON execution_attempts (node_id) WHERE status = 'RUNNING';
        CREATE TABLE IF NOT EXISTS execution_events (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, node_id TEXT, attempt_id TEXT,
            sequence BIGINT GENERATED ALWAYS AS IDENTITY, event_type TEXT NOT NULL, actor_type TEXT NOT NULL DEFAULT 'SYSTEM', actor_id TEXT,
            result TEXT, payload JSONB NOT NULL DEFAULT '{}'::jsonb, occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (organization_id, id)
        );
        ALTER TABLE execution_events ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
        CREATE UNIQUE INDEX IF NOT EXISTS execution_events_idempotency_idx ON execution_events (organization_id, execution_id, event_type, idempotency_key) WHERE idempotency_key IS NOT NULL;
        CREATE INDEX IF NOT EXISTS execution_events_execution_sequence_idx ON execution_events (organization_id, execution_id, sequence);
        CREATE INDEX IF NOT EXISTS execution_events_execution_time_idx ON execution_events (organization_id, execution_id, occurred_at, sequence);
        CREATE INDEX IF NOT EXISTS execution_events_node_idx ON execution_events (organization_id, execution_id, node_id, sequence);
        CREATE TABLE IF NOT EXISTS execution_evidence_records (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, node_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
            control_id TEXT NOT NULL, provider TEXT NOT NULL, connection_id TEXT NOT NULL, resource_id TEXT, source_type TEXT NOT NULL, source_ref TEXT,
            collected_at TIMESTAMPTZ NOT NULL, evidence JSONB NOT NULL, evidence_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            evidence_kind TEXT NOT NULL DEFAULT 'observation', observed_at TIMESTAMPTZ, freshness_expires_at TIMESTAMPTZ,
            lineage JSONB NOT NULL DEFAULT '[]'::jsonb, UNIQUE (organization_id, execution_id, node_id, attempt_id)
        );
        CREATE INDEX IF NOT EXISTS execution_evidence_records_control_idx ON execution_evidence_records (organization_id, execution_id, control_id, collected_at DESC);
        CREATE INDEX IF NOT EXISTS execution_evidence_records_resource_idx ON execution_evidence_records (organization_id, resource_id, collected_at DESC);
        CREATE TABLE IF NOT EXISTS exposure_paths (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, path_key TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'POTENTIAL', severity TEXT NOT NULL, confidence NUMERIC(5,4) NOT NULL DEFAULT 0,
            title TEXT NOT NULL, summary TEXT NOT NULL, evidence_complete BOOLEAN NOT NULL DEFAULT false,
            observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (organization_id, execution_id, path_key), CHECK (status IN ('POTENTIAL','BLOCKED','VERIFIED')),
            CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')), CHECK (confidence >= 0 AND confidence <= 1)
        );
        CREATE INDEX IF NOT EXISTS exposure_paths_org_idx ON exposure_paths (organization_id, updated_at DESC);
        CREATE INDEX IF NOT EXISTS exposure_paths_execution_idx ON exposure_paths (organization_id, execution_id, severity, updated_at DESC);
        CREATE TABLE IF NOT EXISTS exposure_path_nodes (
            id TEXT PRIMARY KEY, path_id TEXT NOT NULL REFERENCES exposure_paths(id) ON DELETE CASCADE, position INTEGER NOT NULL,
            node_type TEXT NOT NULL, resource_id TEXT NOT NULL, label TEXT NOT NULL, observed BOOLEAN NOT NULL DEFAULT true,
            finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb, evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb, UNIQUE (path_id, position)
        );
        CREATE INDEX IF NOT EXISTS exposure_path_nodes_path_idx ON exposure_path_nodes (path_id, position);
        CREATE TABLE IF NOT EXISTS exposure_path_edges (
            id TEXT PRIMARY KEY, path_id TEXT NOT NULL REFERENCES exposure_paths(id) ON DELETE CASCADE, position INTEGER NOT NULL,
            from_node_id TEXT NOT NULL REFERENCES exposure_path_nodes(id) ON DELETE CASCADE,
            to_node_id TEXT NOT NULL REFERENCES exposure_path_nodes(id) ON DELETE CASCADE, relationship TEXT NOT NULL,
            evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb, metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            UNIQUE (path_id, position)
        );
        CREATE INDEX IF NOT EXISTS exposure_path_edges_path_idx ON exposure_path_edges (path_id, position);
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS website VARCHAR(255);
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS industry VARCHAR(64);
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS company_size VARCHAR(32);
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS onboarding_status VARCHAR(32) DEFAULT 'AUTHENTICATED';
        ALTER TABLE cloud_connections ADD COLUMN IF NOT EXISTS principal VARCHAR(255);
        ALTER TABLE cloud_connections ADD COLUMN IF NOT EXISTS verification_method VARCHAR(255);
    `;
    await resilientPool.query(query);
}

export default resilientPool;
