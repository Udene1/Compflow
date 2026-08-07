import pg from 'pg';

const { Pool } = pg;

const pool = new Pool({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
    database: process.env.POSTGRES_DB || 'compflow',
    user: process.env.POSTGRES_USER || 'compflow_user',
    password: process.env.POSTGRES_PASSWORD || 'compflow_pass',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000
});

// Auto-initialize jobs table on startup
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
    `;

    try {
        await pool.query(query);
        console.log('[DB] PostgreSQL jobs table initialized.');
    } catch (err) {
        console.error('[DB] Failed to initialize PostgreSQL table:', err.message);
    }
}

export default pool;
