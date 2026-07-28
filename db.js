// ─── ComplianceFlow AI: PostgreSQL Database Client ───
import pg from 'pg';
const { Pool } = pg;

const connectionString = process.env.DATABASE_URL;

const poolConfig = connectionString
    ? { connectionString }
    : {
        host: process.env.PGHOST || 'localhost',
        port: parseInt(process.env.PGPORT || '5432', 10),
        user: process.env.PGUSER || 'postgres',
        password: process.env.PGPASSWORD || 'postgres',
        database: process.env.PGDATABASE || 'complianceflow',
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
    };

export const pool = new Pool(poolConfig);

pool.on('error', (err) => {
    console.error('[DB] Unexpected error on idle PostgreSQL client:', err);
});

let isInitialized = false;

/**
 * Ensures required database tables exist.
 */
export async function initDb() {
    if (isInitialized) return;

    const createJobsTableQuery = `
        CREATE TABLE IF NOT EXISTS jobs (
            job_id VARCHAR(64) PRIMARY KEY,
            client_id VARCHAR(64) NOT NULL,
            scan_type VARCHAR(32) DEFAULT 'on_demand',
            status VARCHAR(32) NOT NULL DEFAULT 'queued',
            progress INT NOT NULL DEFAULT 0,
            logs JSONB DEFAULT '[]'::jsonb,
            resources JSONB DEFAULT '[]'::jsonb,
            error_message TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS idx_jobs_client_id ON jobs(client_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
        CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);
    `;

    try {
        const client = await pool.connect();
        try {
            await client.query(createJobsTableQuery);
            console.log('[DB] PostgreSQL schema initialized successfully.');
            isInitialized = true;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error('[DB] Schema initialization failed:', err.message);
    }
}

/**
 * Execute SQL query with parameter binding.
 */
export async function query(text, params) {
    if (!isInitialized) {
        await initDb();
    }
    return pool.query(text, params);
}

export default { pool, query, initDb };
