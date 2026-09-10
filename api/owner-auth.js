import { Router } from 'express';
import crypto from 'crypto';
import pool from '../core/db.js';
import { ROLES, createSessionToken } from '../core/auth.js';
import { hashPassword, verifyPassword } from '../core/password_auth.js';
import { recordAuditEvent } from '../core/audit_events.js';
import { revokeSession } from '../core/auth.js';
import { log } from '../core/logger.js';

const router = Router();
const APP_URL = process.env.APP_URL || 'https://compflow.icu';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const OWNER_EMAIL = (process.env.OWNER_EMAIL || 'kenneth@compflow.icu').toLowerCase().trim();

function cookie(token) {
    const domain = IS_PRODUCTION ? ' Domain=.compflow.icu;' : '';
    return `cf_session=${token}; HttpOnly; Secure; SameSite=Lax;${domain} Path=/; Max-Age=${24 * 60 * 60}`;
}

function normalizeEmail(value) { return String(value || '').toLowerCase().trim(); }
function validPassword(password) { return typeof password === 'string' && password.length >= 12 && Buffer.byteLength(password, 'utf8') <= 1024; }

router.get('/status', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT EXISTS (
                SELECT 1 FROM org_memberships WHERE role = $1 AND status = 'active'
            ) AS claimed`,
            [ROLES.OWNER]
        );
        const claimed = Boolean(result.rows[0]?.claimed);
        const bootstrapConfigured = Boolean(process.env.OWNER_BOOTSTRAP_CODE);
        res.json({
            passwordLogin: true,
            ownerBootstrap: !claimed && bootstrapConfigured,
            claimed,
            ownerEmail: OWNER_EMAIL
        });
    } catch (error) {
        log.error('[OWNER_AUTH] Status check failed:', error.message);
        res.status(503).json({ error: 'AUTHORITY_UNAVAILABLE', message: 'Authentication authority is unavailable.' });
    }
});

router.post('/bootstrap', async (req, res) => {
    const bootstrapCode = process.env.OWNER_BOOTSTRAP_CODE;
    const suppliedCode = String(req.body?.bootstrapCode || '');
    const email = normalizeEmail(req.body?.email);
    const name = String(req.body?.name || 'Kenneth Elioku').trim().slice(0, 255);
    const password = req.body?.password;

    if (!bootstrapCode) return res.status(503).json({ error: 'OWNER_BOOTSTRAP_NOT_CONFIGURED', message: 'Owner bootstrap is not configured.' });
    if (!crypto.timingSafeEqual(Buffer.from(suppliedCode), Buffer.from(bootstrapCode))) return res.status(401).json({ error: 'INVALID_BOOTSTRAP_CODE', message: 'Owner setup could not be authorized.' });
    if (email !== OWNER_EMAIL) return res.status(403).json({ error: 'OWNER_EMAIL_REQUIRED', message: 'Only the configured owner email can claim the initial owner account.' });
    if (!validPassword(password)) return res.status(400).json({ error: 'PASSWORD_INVALID', message: 'Choose a password of at least 12 characters.' });

    const client = await pool.connect();
    let session = null;
    try {
        await client.query('BEGIN');
        await client.query(`SELECT pg_advisory_xact_lock(hashtextextended('compflow:owner-bootstrap', 0))`);
        const ownerCheck = await client.query(`SELECT 1 FROM org_memberships WHERE role = $1 AND status = 'active' LIMIT 1`, [ROLES.OWNER]);
        if (ownerCheck.rows.length) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'OWNER_ALREADY_CLAIMED', message: 'The initial owner account has already been claimed.' });
        }

        let user = (await client.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email])).rows[0];
        const passwordHash = await hashPassword(password);
        if (user) {
            await client.query('UPDATE users SET name = $1, password_hash = $2, updated_at = CURRENT_TIMESTAMP, status = \'active\' WHERE id = $3', [name, passwordHash, user.id]);
            user = (await client.query('SELECT * FROM users WHERE id = $1', [user.id])).rows[0];
        } else {
            user = (await client.query(`INSERT INTO users (id, email, name, password_hash, status) VALUES ($1,$2,$3,$4,'active') RETURNING *`, ['usr_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16), email, name, passwordHash])).rows[0];
        }

        let org = (await client.query('SELECT * FROM organizations WHERE lower(domain) = $1 ORDER BY created_at ASC LIMIT 1', ['compflow.icu'])).rows[0];
        if (!org) {
            org = (await client.query(`INSERT INTO organizations (id, name, domain, sso_provider, onboarding_status) VALUES ($1,'ComplianceFlow','compflow.icu','native','AUTHENTICATED') RETURNING *`, ['org_compflow_icu'])).rows[0];
        }
        await client.query(`INSERT INTO org_memberships (user_id, org_id, role, status) VALUES ($1,$2,$3,'active') ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role, status = 'active', updated_at = CURRENT_TIMESTAMP`, [user.id, org.id, ROLES.OWNER]);
        await client.query(`INSERT INTO onboarding_state (org_id, status) VALUES ($1,'AUTHENTICATED') ON CONFLICT (org_id) DO NOTHING`, [org.id]);
        await client.query('COMMIT');

        session = await createSessionToken({ id: user.id, email: user.email, name: user.name }, { id: org.id, name: org.name }, ROLES.OWNER, 1);
        try {
            await recordAuditEvent(org.id, user.id, 'owner_bootstrapped', 'user', user.id, { provider: 'password', emailDomain: 'compflow.icu' }, req);
        } catch (auditError) {
            await revokeSession(session.token);
            throw auditError;
        }
        res.setHeader('Set-Cookie', cookie(session.token));
        return res.json({ success: true, user: session.payload, redirect: `${APP_URL}/app.html` });
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        log.error('[OWNER_AUTH] Bootstrap failed:', error.message);
        return res.status(500).json({ error: 'OWNER_BOOTSTRAP_FAILED', message: 'Owner setup could not be completed.' });
    } finally { client.release(); }
});

router.post('/login', async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (!email || typeof password !== 'string') return res.status(400).json({ error: 'CREDENTIALS_REQUIRED', message: 'Email and password are required.' });

    try {
        const userRes = await pool.query(`SELECT u.* FROM users u WHERE lower(u.email) = $1 AND u.status = 'active' LIMIT 1`, [email]);
        const user = userRes.rows[0];
        if (!user || !user.password_hash || !(await verifyPassword(password, user.password_hash))) {
            return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Email or password is incorrect.' });
        }
        const membershipRes = await pool.query(`SELECT m.*, o.name AS org_name, o.domain AS org_domain FROM org_memberships m JOIN organizations o ON o.id = m.org_id WHERE m.user_id = $1 AND m.status = 'active' ORDER BY CASE m.role WHEN 'OWNER' THEN 5 WHEN 'ADMIN' THEN 4 WHEN 'ENGINEER' THEN 3 WHEN 'AUDITOR' THEN 2 ELSE 1 END DESC LIMIT 1`, [user.id]);
        const membership = membershipRes.rows[0];
        if (!membership) return res.status(403).json({ error: 'NO_ACTIVE_MEMBERSHIP', message: 'This account has no active workspace membership.' });

        const session = await createSessionToken({ id: user.id, email: user.email, name: user.name, avatarUrl: user.avatar_url }, { id: membership.org_id, name: membership.org_name }, membership.role, 1);
        try {
            await recordAuditEvent(membership.org_id, user.id, 'user_authenticated', 'session', session.payload.sessionId, { provider: 'password', result: 'success' }, req);
        } catch (auditError) {
            await revokeSession(session.token);
            throw auditError;
        }
        res.setHeader('Set-Cookie', cookie(session.token));
        return res.json({ success: true, user: session.payload });
    } catch (error) {
        if (error.message === 'Authentication audit persistence failed.') return res.status(503).json({ error: 'AUTH_AUDIT_UNAVAILABLE', message: 'Authentication could not be completed.' });
        log.error('[OWNER_AUTH] Login failed:', error.message);
        return res.status(500).json({ error: 'LOGIN_FAILED', message: 'Authentication could not be completed.' });
    }
});

export default router;
