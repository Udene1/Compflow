let pool = null;

class MemoryFallbackPool {
    constructor() {
        this.tenants = [];
        this.organizations = [];
        this.users = [];
        this.identities = [];
        this.memberships = [];
        this.sessions = [];
        this.audit_events = [];
        this.organization_frameworks = [];
        this.onboarding_state = [];
        this.cloud_connections = [];
        this.secrets = [];
        this.scans = [];
        this.findings = [];
        this.jobs = new Map();
    }

    async query(sql, params = []) {
        const normalized = sql.replace(/\s+/g, ' ').trim();

        // ── TENANTS ──
        if (normalized.includes('SELECT * FROM tenants')) {
            if (normalized.includes('WHERE org_id = $1') && params.length > 0) {
                return { rows: this.tenants.filter(t => t.org_id === params[0]) };
            }
            if (normalized.includes('WHERE id = $1 AND org_id = $2') && params.length >= 2) {
                const found = this.tenants.filter(t => t.id === params[0] && t.org_id === params[1]);
                return { rows: found };
            }
            if (normalized.includes('WHERE id = $1') && params.length > 0) {
                return { rows: this.tenants.filter(t => t.id === params[0]) };
            }
            return { rows: [...this.tenants] };
        }
        if (normalized.includes('INSERT INTO tenants')) {
            const [id, orgId, name, provider, roleArn, apiToken, email, autoRemediate, status] = params;
            const existingIdx = this.tenants.findIndex(t => t.id === id);
            const record = { id, org_id: orgId || 'org_default', name, provider, role_arn: roleArn, api_token: apiToken, email, auto_remediate: autoRemediate, status, created_at: new Date() };
            if (existingIdx >= 0) {
                this.tenants[existingIdx] = record;
            } else {
                this.tenants.push(record);
            }
            return { rowCount: 1, rows: [record] };
        }

        // ── USERS ──
        if (normalized.includes('SELECT * FROM users WHERE email = $1')) {
            const user = this.users.find(u => u.email?.toLowerCase() === params[0]?.toLowerCase());
            return { rows: user ? [user] : [] };
        }
        if (normalized.includes('SELECT * FROM users WHERE id = $1')) {
            const user = this.users.find(u => u.id === params[0]);
            return { rows: user ? [user] : [] };
        }
        if (normalized.includes('INSERT INTO users')) {
            const [id, email, name, avatarUrl] = params;
            const existingIdx = this.users.findIndex(u => u.id === id || u.email?.toLowerCase() === email?.toLowerCase());
            const user = { id, email, name, avatar_url: avatarUrl, status: 'active', created_at: new Date(), updated_at: new Date() };
            if (existingIdx >= 0) {
                this.users[existingIdx] = { ...this.users[existingIdx], ...user };
                return { rows: [this.users[existingIdx]], rowCount: 1 };
            } else {
                this.users.push(user);
                return { rows: [user], rowCount: 1 };
            }
        }

        // ── IDENTITIES ──
        if (normalized.includes('SELECT * FROM identities WHERE provider = $1 AND provider_subject = $2')) {
            const row = this.identities.find(i => i.provider === params[0] && String(i.provider_subject) === String(params[1]));
            return { rows: row ? [row] : [] };
        }
        if (normalized.includes('SELECT * FROM identities WHERE user_id = $1')) {
            const rows = this.identities.filter(i => i.user_id === params[0]);
            return { rows };
        }
        if (normalized.includes('INSERT INTO identities')) {
            const [id, userId, provider, providerSubject, providerEmail] = params;
            const existingIdx = this.identities.findIndex(i => i.provider === provider && String(i.provider_subject) === String(providerSubject));
            const record = { id, user_id: userId, provider, provider_subject: String(providerSubject), provider_email: providerEmail, created_at: new Date(), updated_at: new Date(), last_login_at: new Date() };
            if (existingIdx >= 0) {
                this.identities[existingIdx] = { ...this.identities[existingIdx], ...record };
            } else {
                this.identities.push(record);
            }
            return { rowCount: 1, rows: [record] };
        }
        if (normalized.includes('UPDATE identities SET last_login_at')) {
            const [id] = params;
            const idx = this.identities.findIndex(i => i.id === id);
            if (idx >= 0) {
                this.identities[idx].last_login_at = new Date();
                this.identities[idx].updated_at = new Date();
            }
            return { rowCount: 1 };
        }

        // ── ORGANIZATIONS ──
        if (normalized.includes('FROM organizations WHERE id = $1')) {
            const org = this.organizations.find(o => o.id === params[0]);
            return { rows: org ? [org] : [] };
        }
        if (normalized.includes('INSERT INTO organizations')) {
            const [id, name, domain, ssoProvider] = params;
            const existing = this.organizations.find(o => o.id === id);
            if (existing) return { rows: [existing], rowCount: 0 };
            const org = { id, name, domain, sso_provider: ssoProvider, onboarding_status: 'AUTHENTICATED', created_at: new Date() };
            this.organizations.push(org);
            return { rows: [org], rowCount: 1 };
        }
        if (normalized.includes('UPDATE organizations')) {
            const orgId = params[params.length - 1];
            let org = this.organizations.find(o => o.id === orgId);
            if (!org) {
                org = { id: orgId, name: params[0] || 'Organization', onboarding_status: 'AUTHENTICATED', created_at: new Date() };
                this.organizations.push(org);
            }
            if (params.length === 5) {
                // name, website, industry, company_size, id
                org.name = params[0];
                org.website = params[1];
                org.industry = params[2];
                org.company_size = params[3];
            }
            if (normalized.includes("onboarding_status = 'ONBOARDING_COMPLETED'")) {
                org.onboarding_status = 'ONBOARDING_COMPLETED';
            }
            org.updated_at = new Date();
            return { rows: [org], rowCount: 1 };
        }

        // ── ORG MEMBERSHIPS ──
        if (normalized.includes('SELECT * FROM org_memberships WHERE org_id = $1')) {
            const rows = this.memberships.filter(m => m.org_id === params[0]);
            return { rows };
        }
        if (normalized.includes('SELECT * FROM org_memberships WHERE user_id = $1 AND org_id = $2')) {
            const [userId, orgId] = params;
            const m = this.memberships.find(x => x.user_id === userId && x.org_id === orgId);
            return { rows: m ? [m] : [] };
        }
        if (normalized.includes('SELECT * FROM org_memberships WHERE user_id = $1')) {
            const rows = this.memberships.filter(m => m.user_id === params[0]);
            return { rows };
        }
        if (normalized.includes('INSERT INTO org_memberships')) {
            const [userId, orgId, role] = params;
            const existing = this.memberships.find(m => m.user_id === userId && m.org_id === orgId);
            if (!existing) {
                const record = { user_id: userId, org_id: orgId, role: role || 'ENGINEER', joined_at: new Date() };
                this.memberships.push(record);
            }
            return { rowCount: 1 };
        }

        // ── SESSIONS ──
        if (normalized.includes('INSERT INTO sessions')) {
            const [id, userId, orgId, tokenHash, role, expiresAt] = params;
            const record = { id, user_id: userId, org_id: orgId, token_hash: tokenHash, role, expires_at: expiresAt, is_revoked: false, created_at: new Date() };
            this.sessions.push(record);
            return { rowCount: 1 };
        }
        if (normalized.includes('FROM sessions WHERE token_hash = $1')) {
            const s = this.sessions.find(x => x.token_hash === params[0]);
            return { rows: s ? [s] : [] };
        }
        if (normalized.includes('UPDATE sessions SET is_revoked = true')) {
            const s = this.sessions.find(x => x.token_hash === params[0]);
            if (s) s.is_revoked = true;
            return { rowCount: s ? 1 : 0 };
        }

        // ── AUDIT EVENTS ──
        if (normalized.includes('INSERT INTO audit_events')) {
            const [id, orgId, actorUserId, eventType, resourceType, resourceId, metadata, ip, userAgent] = params;
            const record = {
                id, organization_id: orgId, actor_user_id: actorUserId,
                event_type: eventType, resource_type: resourceType, resource_id: resourceId,
                metadata: typeof metadata === 'string' ? JSON.parse(metadata) : (metadata || {}),
                ip_address: ip, user_agent: userAgent, created_at: new Date()
            };
            this.audit_events.push(record);
            return { rowCount: 1, rows: [record] };
        }
        if (normalized.includes('SELECT * FROM audit_events')) {
            if (normalized.includes('WHERE organization_id = $1')) {
                return { rows: this.audit_events.filter(a => a.organization_id === params[0]) };
            }
            return { rows: [...this.audit_events] };
        }

        // ── ONBOARDING STATE ──
        if (normalized.includes('SELECT * FROM onboarding_state WHERE org_id = $1')) {
            const state = this.onboarding_state.find(s => s.org_id === params[0]);
            return { rows: state ? [state] : [] };
        }
        if (normalized.includes('INSERT INTO onboarding_state') || normalized.includes('UPDATE onboarding_state')) {
            const orgId = params[0];
            const status = params[1];
            const existingIdx = this.onboarding_state.findIndex(s => s.org_id === orgId);
            const record = { org_id: orgId, status, updated_at: new Date(), completed_at: status === 'ONBOARDING_COMPLETED' ? new Date() : null };
            if (existingIdx >= 0) {
                this.onboarding_state[existingIdx] = { ...this.onboarding_state[existingIdx], ...record };
            } else {
                this.onboarding_state.push(record);
            }
            return { rowCount: 1, rows: [record] };
        }

        // ── ORGANIZATION FRAMEWORKS ──
        if (normalized.includes('FROM organization_frameworks WHERE org_id = $1')) {
            const rows = this.organization_frameworks.filter(f => f.org_id === params[0]);
            return { rows };
        }
        if (normalized.includes('INSERT INTO organization_frameworks')) {
            const [id, orgId, frameworkId, status, selectedBy] = params;
            const existingIdx = this.organization_frameworks.findIndex(f => f.org_id === orgId && f.framework_id === frameworkId);
            const record = { id, org_id: orgId, framework_id: frameworkId, status: status || 'selected', selected_by: selectedBy, selected_at: new Date() };
            if (existingIdx >= 0) {
                this.organization_frameworks[existingIdx] = record;
            } else {
                this.organization_frameworks.push(record);
            }
            return { rowCount: 1 };
        }

        // ── CLOUD CONNECTIONS ──
        if (normalized.includes('FROM cloud_connections WHERE organization_id = $1')) {
            let rows = this.cloud_connections.filter(c => c.organization_id === params[0]);
            if (normalized.includes("status = 'VERIFIED'") || (params.length > 1 && params[1] === 'VERIFIED')) {
                rows = rows.filter(c => c.status === 'VERIFIED');
            }
            return { rows };
        }
        if (normalized.includes('FROM cloud_connections WHERE id = $1')) {
            const conn = this.cloud_connections.find(c => c.id === params[0]);
            return { rows: conn ? [conn] : [] };
        }
        if (normalized.includes('INSERT INTO cloud_connections')) {
            const [id, orgId, provider, displayName, status, accountId, region, credRef, createdBy] = params;
            const record = {
                id, organization_id: orgId, provider, display_name: displayName,
                status: status || 'PENDING', account_identifier: accountId, region,
                credential_reference: credRef, created_by: createdBy,
                created_at: new Date(), updated_at: new Date()
            };
            this.cloud_connections.push(record);
            return { rowCount: 1, rows: [record] };
        }
        if (normalized.includes('UPDATE cloud_connections')) {
            const conn = this.cloud_connections.find(c => c.id === params[params.length - 1]);
            if (conn) {
                if (normalized.includes("status = 'VERIFIED'")) {
                    conn.status = 'VERIFIED';
                    conn.account_identifier = params[0];
                    conn.principal = params[1];
                    conn.verification_method = params[2];
                    conn.last_verified_at = new Date();
                    conn.error_code = null;
                    conn.error_message = null;
                } else if (normalized.includes("status = 'FAILED'")) {
                    conn.status = 'FAILED';
                    conn.error_code = params[0];
                    conn.error_message = params[1];
                } else if (normalized.includes('account_identifier = $2')) {
                    // SET status = $1, account_identifier = $2, principal = $3, verification_method = $4, ... WHERE id = $5
                    conn.status = params[0];
                    conn.account_identifier = params[1];
                    conn.principal = params[2];
                    conn.verification_method = params[3];
                    conn.last_verified_at = new Date();
                    conn.error_code = null;
                    conn.error_message = null;
                } else if (normalized.includes('error_code = $2')) {
                    // SET status = $1, error_code = $2, error_message = $3 WHERE id = $4
                    conn.status = params[0];
                    conn.error_code = params[1];
                    conn.error_message = params[2];
                } else if (normalized.includes('status = $1')) {
                    conn.status = params[0];
                    if (params[0] === 'VERIFIED') conn.last_verified_at = new Date();
                    if (params[1]) conn.error_message = params[1];
                }
                conn.updated_at = new Date();
                return { rowCount: 1, rows: [conn] };
            }
            return { rowCount: 0, rows: [] };
        }

        // ── SECRETS ──
        if (normalized.includes('INSERT INTO secrets')) {
            const [id, orgId, connectionId, encryptedData, iv, createdBy] = params;
            const existingIdx = this.secrets.findIndex(s => s.org_id === orgId && s.connection_id === connectionId);
            const record = {
                id, org_id: orgId, connection_id: connectionId,
                encrypted_data: encryptedData, iv, version: 1,
                created_by: createdBy, created_at: new Date(), updated_at: new Date(),
                last_accessed_at: null
            };
            if (existingIdx >= 0) {
                this.secrets[existingIdx] = record;
            } else {
                this.secrets.push(record);
            }
            return { rowCount: 1, rows: [record] };
        }
        if (normalized.includes('FROM secrets WHERE org_id = $1 AND connection_id = $2')) {
            const secret = this.secrets.find(s => s.org_id === params[0] && s.connection_id === params[1]);
            return { rows: secret ? [secret] : [] };
        }
        if (normalized.includes('UPDATE secrets SET encrypted_data')) {
            const [encryptedData, iv, orgId, connectionId] = params;
            const secret = this.secrets.find(s => s.org_id === orgId && s.connection_id === connectionId);
            if (secret) {
                secret.encrypted_data = encryptedData;
                secret.iv = iv;
                secret.version = (secret.version || 1) + 1;
                secret.updated_at = new Date();
                return { rowCount: 1, rows: [{ id: secret.id, version: secret.version }] };
            }
            return { rowCount: 0, rows: [] };
        }
        if (normalized.includes('UPDATE secrets SET last_accessed_at')) {
            const secret = this.secrets.find(s => s.id === params[0]);
            if (secret) secret.last_accessed_at = new Date();
            return { rowCount: 1 };
        }
        if (normalized.includes('DELETE FROM secrets WHERE org_id = $1 AND connection_id = $2')) {
            const prevLen = this.secrets.length;
            this.secrets = this.secrets.filter(s => !(s.org_id === params[0] && s.connection_id === params[1]));
            return { rowCount: prevLen - this.secrets.length };
        }

        // ── SCANS ──
        if (normalized.includes('INSERT INTO scans')) {
            let id = params[0];
            let orgId = params[1];
            let connId = params[2];
            let scanType = params[3] || 'initial_onboarding_scan';
            let status = params[4] || 'QUEUED';

            if (normalized.includes("'COMPLETED'")) status = 'COMPLETED';
            else if (normalized.includes("'RUNNING'")) status = 'RUNNING';
            else if (normalized.includes("'PARTIAL'")) status = 'PARTIAL';
            else if (normalized.includes("'FAILED'")) status = 'FAILED';

            const record = {
                id, organization_id: orgId, connection_id: connId,
                job_id: id, scan_type: scanType,
                status,
                started_at: status === 'RUNNING' ? new Date() : null,
                completed_at: status === 'COMPLETED' ? new Date() : null,
                error_code: null, error_message: null,
                resources_discovered: 0, findings_count: 0, evidence_count: 0,
                created_at: new Date(), updated_at: new Date()
            };
            this.scans.push(record);
            return { rowCount: 1, rows: [record] };
        }
        if (normalized.includes('FROM scans WHERE organization_id = $1')) {
            const matched = this.scans.filter(s => s.organization_id === params[0]);
            // Sort by created_at DESC
            matched.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            return { rows: matched };
        }
        if (normalized.includes('FROM scans WHERE connection_id = $1')) {
            const matched = this.scans.filter(s => s.connection_id === params[0]);
            matched.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            return { rows: matched };
        }
        if (normalized.includes('FROM scans WHERE id = $1')) {
            const scan = this.scans.find(s => s.id === params[0]);
            return { rows: scan ? [scan] : [] };
        }
        if (normalized.includes('UPDATE scans')) {
            const scan = this.scans.find(s => s.id === params[params.length - 1]);
            if (scan) {
                if (normalized.includes('resources_discovered = $1') || normalized.includes('resources_discovered =')) {
                    scan.resources_discovered = params[0] || 0;
                    scan.findings_count = params[1] || 0;
                    scan.evidence_count = params[2] || 0;
                }
                if (normalized.includes('status = $1')) {
                    scan.status = params[0];
                    if (params[0] === 'RUNNING') scan.started_at = new Date();
                    if (params[0] === 'COMPLETED' || params[0] === 'PARTIAL' || params[0] === 'FAILED') scan.completed_at = new Date();
                }
                scan.updated_at = new Date();
                return { rowCount: 1, rows: [scan] };
            }
            return { rowCount: 0, rows: [] };
        }

        // ── FINDINGS ──
        if (normalized.includes('INSERT INTO findings')) {
            let id = params[0];
            let orgId = params[1];
            let scanId = params[2];
            let resourceId = params[3] || 'resource_1';
            let controlId = params[4] || 'control_1';
            let severity = params[5] || 'MEDIUM';
            let status = params[6] || 'FAIL';
            let code = params[7] || 'CODE_1';

            if (normalized.includes("'CRITICAL'")) severity = 'CRITICAL';
            else if (normalized.includes("'HIGH'")) severity = 'HIGH';
            else if (normalized.includes("'MEDIUM'")) severity = 'MEDIUM';
            else if (normalized.includes("'LOW'")) severity = 'LOW';

            if (normalized.includes("'PASS'")) status = 'PASS';
            else if (normalized.includes("'FAIL'")) status = 'FAIL';

            const record = {
                id, organization_id: orgId, scan_id: scanId, resource_id: resourceId,
                control_id: controlId, severity, status,
                code, created_at: new Date()
            };
            this.findings.push(record);
            return { rowCount: 1, rows: [record] };
        }
        if (normalized.includes('FROM findings WHERE scan_id = $1')) {
            const rows = this.findings.filter(f => f.scan_id === params[0]);
            if (normalized.includes('COUNT(*)')) {
                // Group by severity simulation
                const counts = {};
                for (const f of rows) {
                    const sev = f.severity?.toUpperCase() || 'MEDIUM';
                    counts[sev] = (counts[sev] || 0) + 1;
                }
                return {
                    rows: Object.entries(counts).map(([severity, count]) => ({ severity, count }))
                };
            }
            return { rows };
        }
        if (normalized.includes('FROM findings WHERE organization_id = $1')) {
            const rows = this.findings.filter(f => f.organization_id === params[0]);
            return { rows };
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
                    if (process.env.NODE_ENV === 'production') {
                        throw new Error(`[DB] Production database unavailable: ${err.message}`);
                    }
                    return await fallbackPool.query(sql, params);
                }
                throw err;
            }
        }
        if (process.env.NODE_ENV === 'production') {
            throw new Error('[DB] Production database pool not initialized');
        }
        return await fallbackPool.query(sql, params);
    },
    async connect() {
        if (realPool) {
            try { return await realPool.connect(); }
            catch (err) {
                if (process.env.NODE_ENV === 'production') throw new Error(`[DB] Production database unavailable: ${err.message}`);
                throw new Error(`[DB] Transactional PostgreSQL connection unavailable: ${err.message}`);
            }
        }
        if (process.env.NODE_ENV === 'production') throw new Error('[DB] Production database pool not initialized');
        throw new Error('[DB] Transactional PostgreSQL connection unavailable: real database required');
    }
};

// Auto-initialize jobs, tenants, authentication, and onboarding tables on startup
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

        -- Identity Federation Table (Google, GitHub, etc.)
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

        -- Audit Events (PostgreSQL Lean Audit Log)
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

        -- Framework Selections
        CREATE TABLE IF NOT EXISTS organization_frameworks (
            id VARCHAR(64) PRIMARY KEY,
            org_id VARCHAR(64) REFERENCES organizations(id) ON DELETE CASCADE,
            framework_id VARCHAR(32) NOT NULL,
            status VARCHAR(32) DEFAULT 'selected',
            selected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            selected_by VARCHAR(64),
            UNIQUE (org_id, framework_id)
        );

        -- Onboarding State (Decoupled from connection and scan states)
        CREATE TABLE IF NOT EXISTS onboarding_state (
            org_id VARCHAR(64) PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            status VARCHAR(32) DEFAULT 'AUTHENTICATED',
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMPTZ
        );

        -- Cloud Connections
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

        -- Encrypted Secrets Storage
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

        -- Authoritative Scans Lifecycle Table (Amendment 2)
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

        -- Persisted Compliance Findings Table (Amendment 6)
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

        -- Additive column migrations for existing tables
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
        console.error('[DB] Failed to initialize PostgreSQL table:', err.message);
    }
}

export default resilientPool;
