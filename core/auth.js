import crypto from 'crypto';
import pool from './db.js';
import { recordAuditEvent } from './audit_events.js';
import { log } from './logger.js';

const AUTH_SECRET = (() => {
    const secret = process.env.AUTH_SECRET || process.env.JWT_SECRET;
    if (!secret) {
        if (process.env.NODE_ENV === 'production') {
            // Hard fail: production must not run with a known/hardcoded secret.
            throw new Error(
                'FATAL: AUTH_SECRET (or JWT_SECRET) env var is required in production.\n' +
                'Generate one: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"\n' +
                'Server cannot start without it.'
            );
        }
        // Dev-only fallback — loudly warn so developers know
        console.warn('\n⚠️  [AUTH] AUTH_SECRET not set — using insecure dev-only fallback.');
        console.warn('   DO NOT deploy to production without setting AUTH_SECRET.\n');
        return 'CompFlow_Auth_Engine_Secret_2026_DEV_ONLY';
    }
    return secret;
})();

// ─── Server-Side Session Revocation List ─────────────────────────────────────
// Fast in-memory cache for positive hits; backed authoritatively by PostgreSQL sessions table
const _revokedSessions = new Map(); // token_hash -> expiry timestamp
const REVOCATION_CLEANUP_INTERVAL = 60 * 60 * 1000; // Prune expired entries every hour

// Periodic cleanup of expired revocation entries to prevent memory growth
setInterval(() => {
    const now = Date.now();
    for (const [hash, expiry] of _revokedSessions) {
        if (expiry < now) _revokedSessions.delete(hash);
    }
}, REVOCATION_CLEANUP_INTERVAL).unref();

/**
 * Helper to clear local in-memory revocation cache (used in multi-instance simulation tests)
 */
export function _clearRevocationCache() {
    _revokedSessions.clear();
}

/**
 * Revokes a session token server-side (called on logout and token rotation).
 * The token is hashed, stored in memory cache, and authoritatively marked revoked in the database.
 */
export async function revokeSession(tokenString) {
    if (!tokenString) return;
    const hash = crypto.createHash('sha256').update(tokenString).digest('hex');
    const expiry = Date.now() + (7 * 24 * 60 * 60 * 1000);

    // Authoritative DB update for multi-instance persistence — BEFORE cache
    try {
        await pool.query('UPDATE sessions SET is_revoked = true WHERE token_hash = $1;', [hash]);
    } catch (err) {
        log.warn(`[AUTH] Failed to mark session revoked in DB: ${err.message}`);
        if (process.env.NODE_ENV === 'production') throw err;
    }

    // Only populate cache after successful DB persistence
    _revokedSessions.set(hash, expiry);
    log.info(`[AUTH] Session revoked (hash: ${hash.substring(0, 12)}...)`);
}

/**
 * Authoritative check if a session token has been server-side revoked.
 * Checks memory cache for fast positive hit, falls back to PostgreSQL when absent.
 */
export async function isSessionRevoked(tokenString) {
    if (!tokenString) return false;
    const hash = crypto.createHash('sha256').update(tokenString).digest('hex');

    // 1. Fast in-memory cache check
    if (_revokedSessions.has(hash)) {
        return true;
    }

    // 2. Authoritative PostgreSQL lookup (e.g. cross-instance revocation)
    try {
        const res = await pool.query('SELECT is_revoked, expires_at FROM sessions WHERE token_hash = $1;', [hash]);
        if (res.rows && res.rows.length > 0) {
            const row = res.rows[0];
            if (row.is_revoked) {
                // Populate memory cache to accelerate subsequent lookups on this instance
                _revokedSessions.set(hash, Date.now() + (7 * 24 * 60 * 60 * 1000));
                return true;
            }
        }
    } catch (err) {
        log.warn(`[AUTH] Persistent revocation check failed: ${err.message}`);
        if (process.env.NODE_ENV === 'production') {
            // Fail closed in production if database is unavailable
            return true;
        }
    }

    return false;
}

export const ROLES = {
    OWNER: 'OWNER',
    ADMIN: 'ADMIN',
    ENGINEER: 'ENGINEER',
    AUDITOR: 'AUDITOR',
    VIEWER: 'VIEWER'
};

const ROLE_HIERARCHY = {
    [ROLES.OWNER]: 100,
    [ROLES.ADMIN]: 80,
    [ROLES.ENGINEER]: 60,
    [ROLES.AUDITOR]: 40,
    [ROLES.VIEWER]: 20
};

/**
 * Checks whether userRole meets the minimum level or belongs to allowedRoles.
 */
export function hasRole(userRole, allowedRoles = []) {
    if (!allowedRoles || allowedRoles.length === 0) return true;
    if (allowedRoles.includes(userRole)) return true;

    // Hierarchy fallback: if allowed includes 'ENGINEER', 'ADMIN' & 'OWNER' also qualify
    const userLevel = ROLE_HIERARCHY[userRole] || 0;
    const minRequiredLevel = Math.min(...allowedRoles.map(r => ROLE_HIERARCHY[r] || 999));
    return userLevel >= minRequiredLevel;
}

/**
 * Signs an object payload using HMAC-SHA256.
 */
export function signAuthPayload(payload) {
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('hex');
}

/**
 * Generates a signed, URL-safe session token and records it authoritatively in the database.
 * The session is ONLY returned if PostgreSQL persistence succeeds.
 * Default lifetime is 24 hours (1 day).
 */
export async function createSessionToken(user, org, role = ROLES.ENGINEER, expiryDays = 1, rotatedFrom = null) {
    const issuedAt = new Date().toISOString();
    const durationMs = (expiryDays <= 0 ? 0 : expiryDays) * 24 * 60 * 60 * 1000;
    const expiresAt = new Date(Date.now() + durationMs).toISOString();

    const payload = {
        sessionId: 'sess_' + crypto.randomUUID(),
        userId: user.id || user.userId,
        email: user.email,
        name: user.name || user.email?.split('@')[0],
        avatarUrl: user.avatarUrl || user.avatar_url || '',
        orgId: org.id || org.orgId || 'org_default',
        orgName: org.name || org.orgName || 'Primary Workspace',
        role: role || ROLES.ENGINEER,
        issuedAt,
        expiresAt
    };

    const signature = signAuthPayload(payload);
    const token = Buffer.from(JSON.stringify({ payload, signature })).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Authoritatively persist to PostgreSQL sessions table BEFORE returning token
    try {
        await pool.query(
            `INSERT INTO sessions (id, user_id, org_id, token_hash, role, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6);`,
            [payload.sessionId, payload.userId, payload.orgId, tokenHash, payload.role, expiresAt]
        );
    } catch (err) {
        log.error(`[AUTH] Session persistence failed: ${err.message}`);
        throw new Error(`Session persistence failed: ${err.message}`);
    }

    return {
        token,
        payload,
        expiresAt
    };
}

/**
 * Validates a session token string, asserts signature, expiration, and checks revocation authoritatively.
 */
export async function validateSessionToken(tokenString) {
    if (!tokenString || typeof tokenString !== 'string') {
        return { valid: false, error: 'Missing session token' };
    }

    try {
        // Authoritative server-side revocation check
        if (await isSessionRevoked(tokenString)) {
            return { valid: false, error: 'Session has been revoked (logged out)' };
        }

        const decoded = JSON.parse(Buffer.from(tokenString, 'base64url').toString('utf8'));
        const { payload, signature } = decoded;

        if (!payload || !signature) {
            return { valid: false, error: 'Malformed session token structure' };
        }

        // Verify cryptographic signature
        const expectedSignature = signAuthPayload(payload);
        const isSigValid = crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );

        if (!isSigValid) {
            return { valid: false, error: 'Invalid or forged session token signature' };
        }

        // Verify expiration
        if (new Date(payload.expiresAt) < new Date()) {
            return { valid: false, error: 'Session token has expired' };
        }

        return { valid: true, user: payload };
    } catch (err) {
        return { valid: false, error: 'Failed to decode session token: ' + err.message };
    }
}

/**
 * Rotates an active session token: invalidates the old one and generates a new 24h session.
 */
export async function rotateSession(oldTokenString) {
    const check = await validateSessionToken(oldTokenString);
    if (!check.valid) {
        throw new Error(`Cannot rotate invalid session: ${check.error}`);
    }

    // Authoritatively revoke old token
    await revokeSession(oldTokenString);

    // Create fresh session for same user/org
    const newSession = await createSessionToken(
        { id: check.user.userId, email: check.user.email, name: check.user.name, avatarUrl: check.user.avatarUrl },
        { id: check.user.orgId, name: check.user.orgName },
        check.user.role,
        1,
        oldTokenString
    );

    log.info(`[AUTH] Session rotated for user ${check.user.email}`);
    return newSession;
}

/**
 * Provisions or updates a user from an OAuth provider profile (Google, GitHub).
 * Strictly adheres to Amendment 4 & 5:
 * - Looks up by (provider, provider_subject)
 * - Never auto-merges based only on email (throws ACCOUNT_EXISTS error)
 * - Preserves existing user IDs and relations
 */
export async function upsertUserFromOAuth(profile, provider = 'google', providerSubject = null) {
    const email = (profile.email || '').toLowerCase().trim();
    if (!email) {
        throw new Error('OAuth profile does not contain a valid email address.');
    }

    const name = profile.name || email.split('@')[0];
    const avatarUrl = profile.picture || profile.avatar_url || '';
    const subject = String(providerSubject || profile.sub || profile.id || email);

    // 1. Check for existing identity (provider + provider_subject)
    const identityRes = await pool.query(
        'SELECT * FROM identities WHERE provider = $1 AND provider_subject = $2;',
        [provider, subject]
    );

    if (identityRes.rows && identityRes.rows.length > 0) {
        const identity = identityRes.rows[0];
        // Touch last_login_at
        await pool.query('UPDATE identities SET last_login_at = CURRENT_TIMESTAMP WHERE id = $1;', [identity.id]);

        // Retrieve existing user
        const userRes = await pool.query('SELECT * FROM users WHERE id = $1;', [identity.user_id]);
        const userRow = userRes.rows?.[0] || { id: identity.user_id, email, name, avatar_url: avatarUrl };

        // Retrieve membership
        const memRes = await pool.query('SELECT * FROM org_memberships WHERE user_id = $1;', [identity.user_id]);
        const memRow = memRes.rows?.[0];
        const orgId = memRow?.org_id || 'org_default';

        const orgRes = await pool.query('SELECT * FROM organizations WHERE id = $1;', [orgId]);
        const orgRow = orgRes.rows?.[0] || { id: orgId, name: 'Primary Workspace', domain: email.split('@')[1] };

        const role = memRow?.role || ROLES.ENGINEER;

        log.info(`[AUTH] Existing identity recognized: ${email} via ${provider}`);
        return {
            user: { id: userRow.id, email: userRow.email, name: userRow.name, avatarUrl: userRow.avatar_url },
            org: { id: orgRow.id, name: orgRow.name, domain: orgRow.domain },
            role
        };
    }

    // 2. Identity not found — check if an account with this email already exists
    const existingUserRes = await pool.query('SELECT * FROM users WHERE email = $1;', [email]);
    if (existingUserRes.rows && existingUserRes.rows.length > 0) {
        // Amendment 5: Never auto-merge users based only on email
        const err = new Error(
            'This email is already associated with a Compflow account. Please sign in using your existing authentication method. After signing in, you can connect additional login methods from Settings → Security → Connected accounts.'
        );
        err.code = 'ACCOUNT_EXISTS';
        throw err;
    }

    // 3. Brand-new user: generate unique ID (crypto.randomUUID, not email hash)
    const userId = 'usr_' + crypto.randomUUID().replace(/-/g, '').substring(0, 16);
    await pool.query(
        'INSERT INTO users (id, email, name, avatar_url) VALUES ($1, $2, $3, $4);',
        [userId, email, name, avatarUrl]
    );

    // 4. Create identity record
    const identityId = 'idn_' + crypto.randomUUID().replace(/-/g, '').substring(0, 16);
    await pool.query(
        'INSERT INTO identities (id, user_id, provider, provider_subject, provider_email) VALUES ($1, $2, $3, $4, $5);',
        [identityId, userId, provider, subject, email]
    );

    // 5. Resolve or provision organization
    const domain = email.includes('@') ? email.split('@')[1] : 'personal';
    const isGenericDomain = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com'].includes(domain);
    const orgId = isGenericDomain 
        ? `org_${userId.replace('usr_', '')}` 
        : `org_${domain.replace(/[^a-zA-Z0-9]/g, '_')}`;
    const orgName = isGenericDomain ? `${name}'s Workspace` : `${domain.toUpperCase()} Governance`;

    await pool.query(
        'INSERT INTO organizations (id, name, domain, sso_provider) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING;',
        [orgId, orgName, domain, provider]
    );

    // 6. Ensure Org Membership (first user in org is OWNER)
    const existingMembers = await pool.query('SELECT * FROM org_memberships WHERE org_id = $1;', [orgId]);
    const assignedRole = (existingMembers.rows && existingMembers.rows.length === 0) ? ROLES.OWNER : ROLES.ENGINEER;

    await pool.query(
        'INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, $3) ON CONFLICT (user_id, org_id) DO NOTHING;',
        [userId, orgId, assignedRole]
    );

    // 7. Initialize onboarding state
    await pool.query(
        'INSERT INTO onboarding_state (org_id, status) VALUES ($1, $2) ON CONFLICT (org_id) DO NOTHING;',
        [orgId, 'AUTHENTICATED']
    );

    // 8. Record audit events
    await recordAuditEvent(orgId, userId, 'user_created', 'user', userId, { provider, emailDomain: domain }).catch(() => {});
    await recordAuditEvent(orgId, userId, 'membership_created', 'organization', orgId, { role: assignedRole }).catch(() => {});

    log.info(`[AUTH] Successfully authenticated user ${email} (Role: ${assignedRole}, Org: ${orgName}).`);

    return {
        user: { id: userId, email, name, avatarUrl },
        org: { id: orgId, name: orgName, domain },
        role: assignedRole
    };
}

