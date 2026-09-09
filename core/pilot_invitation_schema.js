import pool from './db.js';

export async function initPilotInvitationSchema() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS pilot_invitations (
            id VARCHAR(64) PRIMARY KEY,
            token_hash VARCHAR(64) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL,
            email_domain VARCHAR(255) NOT NULL,
            company_name VARCHAR(255) NOT NULL,
            created_by_user_id VARCHAR(64),
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMPTZ NOT NULL,
            redeemed_at TIMESTAMPTZ,
            redeemed_by_user_id VARCHAR(64),
            organization_id VARCHAR(64),
            revoked_at TIMESTAMPTZ,
            status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK (status IN ('PENDING','REDEEMED','EXPIRED','REVOKED'))
        );
        CREATE INDEX IF NOT EXISTS pilot_invitations_email_idx ON pilot_invitations (email, created_at DESC);
        CREATE INDEX IF NOT EXISTS pilot_invitations_status_idx ON pilot_invitations (status, expires_at);
        CREATE INDEX IF NOT EXISTS pilot_invitations_org_idx ON pilot_invitations (organization_id);
    `);
}
