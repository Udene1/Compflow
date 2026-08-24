import crypto from 'crypto';
import pool from './db.js';
import { log } from './logger.js';

const AUTH_SECRET = process.env.AUTH_SECRET || process.env.JWT_SECRET || 'CompFlow_Auth_Engine_Secret_2026';

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
 * Generates a signed, URL-safe session token.
 */
export function createSessionToken(user, org, role = ROLES.ENGINEER, expiryDays = 7) {
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString();

    const payload = {
        sessionId: 'sess_' + crypto.randomUUID(),
        userId: user.id || user.userId,
        email: user.email,
        name: user.name || user.email.split('@')[0],
        avatarUrl: user.avatarUrl || user.avatar_url || '',
        orgId: org.id || org.orgId || 'org_default',
        orgName: org.name || org.orgName || 'Primary Workspace',
        role: role || ROLES.ENGINEER,
        issuedAt,
        expiresAt
    };

    const signature = signAuthPayload(payload);
    const token = Buffer.from(JSON.stringify({ payload, signature })).toString('base64url');

    return {
        token,
        payload,
        expiresAt
    };
}

/**
 * Validates a session token string, asserts signature and expiration.
 */
export function validateSessionToken(tokenString) {
    if (!tokenString || typeof tokenString !== 'string') {
        return { valid: false, error: 'Missing session token' };
    }

    try {
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
 * Provisions or updates a user from an OAuth provider profile (Google, GitHub).
 */
export async function upsertUserFromOAuth(profile, provider = 'google') {
    const email = (profile.email || '').toLowerCase().trim();
    if (!email) {
        throw new Error('OAuth profile does not contain a valid email address.');
    }

    const name = profile.name || email.split('@')[0];
    const avatarUrl = profile.picture || profile.avatar_url || '';
    const userId = 'usr_' + crypto.createHash('sha256').update(email).digest('hex').substring(0, 16);

    // 1. Upsert User Record
    const userQuery = `
        INSERT INTO users (id, email, name, avatar_url)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            avatar_url = EXCLUDED.avatar_url;
    `;
    await pool.query(userQuery, [userId, email, name, avatarUrl]);

    // 2. Resolve or Provision Organization (default to domain or individual org)
    const domain = email.includes('@') ? email.split('@')[1] : 'personal';
    const isGenericDomain = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com'].includes(domain);
    const orgId = isGenericDomain 
        ? `org_${userId.replace('usr_', '')}` 
        : `org_${domain.replace(/[^a-zA-Z0-9]/g, '_')}`;
    const orgName = isGenericDomain ? `${name}'s Workspace` : `${domain.toUpperCase()} Governance`;

    const orgQuery = `
        INSERT INTO organizations (id, name, domain, sso_provider)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO NOTHING;
    `;
    await pool.query(orgQuery, [orgId, orgName, domain, provider]);

    // 3. Ensure Org Membership
    const memberQuery = `
        INSERT INTO org_memberships (user_id, org_id, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, org_id) DO NOTHING;
    `;
    // First user in org becomes OWNER, others default to ENGINEER
    const existingMembers = await pool.query('SELECT * FROM org_memberships WHERE org_id = $1', [orgId]);
    const assignedRole = (existingMembers.rows && existingMembers.rows.length === 0) ? ROLES.OWNER : ROLES.ENGINEER;

    await pool.query(memberQuery, [userId, orgId, assignedRole]);

    log.info(`[AUTH] Successfully authenticated user ${email} (Role: ${assignedRole}, Org: ${orgName}).`);

    return {
        user: { id: userId, email, name, avatarUrl },
        org: { id: orgId, name: orgName, domain },
        role: assignedRole
    };
}
