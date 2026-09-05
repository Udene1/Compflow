import { Router } from 'express';
import crypto from 'crypto';
import { createSessionToken, upsertUserFromOAuth, ROLES, validateSessionToken, revokeSession, rotateSession } from '../core/auth.js';
import { requireAuth } from '../core/auth_guard.js';
import { recordAuditEvent } from '../core/audit_events.js';
import { log } from '../core/logger.js';

const router = Router();

const APP_URL = process.env.APP_URL || 'https://compflow.icu';
const API_URL = process.env.API_URL || 'https://api.compflow.icu';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ─────────────────────────────────────────────────────────────────────────────
// Cookie & Session Helpers
// Adheres strictly to Amendment 2 (HttpOnly sole mechanism) and Amendment 3 (SameSite=Lax)
// ─────────────────────────────────────────────────────────────────────────────
function buildSessionCookies(token, maxAgeSec = 24 * 60 * 60) {
    const domainAttr = IS_PRODUCTION ? ' Domain=.compflow.icu;' : '';
    return [
        `cf_session=${token}; HttpOnly; Secure; SameSite=Lax;${domainAttr} Path=/; Max-Age=${maxAgeSec}`
    ];
}

function buildClearCookies() {
    const domainAttr = IS_PRODUCTION ? ' Domain=.compflow.icu;' : '';
    return [
        `cf_session=; HttpOnly; Secure; SameSite=Lax;${domainAttr} Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
        `oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
        `oauth_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
    ];
}

export function parseCookies(cookieHeader) {
    const list = {};
    if (!cookieHeader) return list;
    cookieHeader.split(';').forEach(cookie => {
        const [name, ...rest] = cookie.split('=');
        const trimmed = name?.trim();
        if (!trimmed) return;
        list[trimmed] = decodeURIComponent(rest.join('=').trim());
    });
    return list;
}

function getCookie(req, name) {
    if (req.cookies && req.cookies[name]) return req.cookies[name];
    const cookies = parseCookies(req.headers.cookie);
    return cookies[name] || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain & Organization Restriction Configuration
// ─────────────────────────────────────────────────────────────────────────────
const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || '')
    .split(',')
    .map(d => d.trim().toLowerCase())
    .filter(Boolean);

const ALLOWED_GITHUB_ORGS = (process.env.ALLOWED_GITHUB_ORGS || '')
    .split(',')
    .map(o => o.trim().toLowerCase())
    .filter(Boolean);

const REJECT_PERSONAL_EMAILS = process.env.REJECT_PERSONAL_EMAILS === 'true';

const PERSONAL_DOMAINS = new Set([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
    'aol.com', 'protonmail.com', 'zoho.com', 'mail.com', 'yandex.com'
]);

function validateEmailDomain(email) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return { allowed: false, reason: 'Invalid email address format.' };

    if (REJECT_PERSONAL_EMAILS && PERSONAL_DOMAINS.has(domain)) {
        return {
            allowed: false,
            reason: `Personal email domains (${domain}) are not allowed. Please sign in with your corporate email.`
        };
    }

    if (ALLOWED_DOMAINS.length > 0 && !ALLOWED_DOMAINS.includes(domain)) {
        return {
            allowed: false,
            reason: `Email domain "${domain}" is not authorized. Allowed domains: [${ALLOWED_DOMAINS.join(', ')}]`
        };
    }

    return { allowed: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Providers Status Endpoint
// ─────────────────────────────────────────────────────────────────────────────
router.get('/providers', (req, res) => {
    const isDev = process.env.NODE_ENV !== 'production';

    res.json({
        google: {
            enabled: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
            authUrl: `${API_URL}/api/auth/google`
        },
        github: {
            enabled: Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET),
            authUrl: `${API_URL}/api/auth/github`
        },
        devLogin: isDev,
        pilotAccess: Boolean(process.env.PILOT_ACCESS_CODE),
        domainRestrictions: {
            allowedDomains: ALLOWED_DOMAINS.length > 0 ? ALLOWED_DOMAINS : 'all',
            rejectPersonalEmails: REJECT_PERSONAL_EMAILS,
            allowedGitHubOrgs: ALLOWED_GITHUB_ORGS.length > 0 ? ALLOWED_GITHUB_ORGS : 'all'
        }
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Google OAuth 2.0 Flow with PKCE and State Verification (Amendment 17)
// ─────────────────────────────────────────────────────────────────────────────
router.get('/google', (req, res) => {
    if (!process.env.GOOGLE_CLIENT_ID) {
        return res.status(503).json({
            error: 'Google SSO Not Configured',
            message: 'GOOGLE_CLIENT_ID is missing in platform environment.'
        });
    }

    // Cryptographic state for CSRF & replay prevention
    const state = crypto.randomBytes(32).toString('hex');

    // PKCE code verifier and challenge derivation (RFC 7636)
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

    res.setHeader('Set-Cookie', [
        `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
        `oauth_verifier=${codeVerifier}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
    ]);

    const params = new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        redirect_uri: `${API_URL}/api/auth/google/callback`,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        access_type: 'offline',
        prompt: 'select_account',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
    });

    if (ALLOWED_DOMAINS.length === 1) {
        params.set('hd', ALLOWED_DOMAINS[0]);
    }

    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

router.get('/google/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        log.warn(`[AUTH] Google returned OAuth error: ${error}`);
        return res.redirect(`${APP_URL}/app.html?auth_error=oauth_failed`);
    }

    if (!code || !state) {
        return res.redirect(`${APP_URL}/app.html?auth_error=missing_oauth_params`);
    }

    // ── State Validation & Single-Use Replay Prevention (Amendment 17) ──
    const storedState = getCookie(req, 'oauth_state');
    const codeVerifier = getCookie(req, 'oauth_verifier');

    // Clear state & verifier cookies IMMEDIATELY so state is single-use
    res.setHeader('Set-Cookie', [
        'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'oauth_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    ]);

    if (!storedState || typeof state !== 'string' || storedState.length !== state.length) {
        log.warn('[AUTH] Missing or invalid oauth_state cookie for Google callback');
        return res.redirect(`${APP_URL}/app.html?auth_error=state_mismatch`);
    }

    const isStateValid = crypto.timingSafeEqual(Buffer.from(state), Buffer.from(storedState));
    if (!isStateValid) {
        log.warn('[AUTH] Google OAuth state mismatch — possible replay or CSRF attempt');
        return res.redirect(`${APP_URL}/app.html?auth_error=state_mismatch`);
    }

    try {
        const tokenBody = new URLSearchParams({
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: `${API_URL}/api/auth/google/callback`,
            grant_type: 'authorization_code'
        });

        if (codeVerifier) {
            tokenBody.set('code_verifier', codeVerifier);
        }

        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: tokenBody
        });

        const tokens = await tokenResponse.json();
        if (!tokens.access_token) {
            throw new Error(tokens.error_description || 'Failed to obtain access token from Google');
        }

        const profileResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${tokens.access_token}` }
        });
        const profile = await profileResponse.json();

        // Domain restriction verification
        const domainCheck = validateEmailDomain(profile.email);
        if (!domainCheck.allowed) {
            log.warn(`[AUTH] Domain restriction blocked Google login for ${profile.email}`);
            return res.redirect(`${APP_URL}/app.html?auth_error=domain_restricted`);
        }

        if (ALLOWED_DOMAINS.length > 0 && profile.hd) {
            if (!ALLOWED_DOMAINS.includes(profile.hd.toLowerCase())) {
                log.warn(`[AUTH] Google hd mismatch for ${profile.email}`);
                return res.redirect(`${APP_URL}/app.html?auth_error=domain_restricted`);
            }
        }

        const { user, org, role } = await upsertUserFromOAuth(profile, 'google', profile.id);
        const session = createSessionToken(user, org, role, 1);

        res.setHeader('Set-Cookie', buildSessionCookies(session.token));
        await recordAuditEvent(org.id, user.id, 'user_authenticated', 'session', session.payload.sessionId, { provider: 'google', result: 'success' }, req).catch(() => {});

        log.info(`[AUTH] Google OAuth success: ${user.email} (Role: ${role}, Org: ${org.name})`);
        return res.redirect(`${APP_URL}/app.html?auth=success&role=${role}`);
    } catch (err) {
        if (err.code === 'ACCOUNT_EXISTS') {
            log.info(`[AUTH] Email collision blocked auto-merge for Google login: ${err.message}`);
            return res.redirect(`${APP_URL}/app.html?auth_error=account_exists`);
        }
        log.error('[AUTH] Google OAuth callback failure:', err.message);
        return res.redirect(`${APP_URL}/app.html?auth_error=oauth_failed`);
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. GitHub OAuth Flow with State Verification
// Note: GitHub OAuth Apps do not support PKCE. Uses confidential client auth flow.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/github', (req, res) => {
    if (!process.env.GITHUB_CLIENT_ID) {
        return res.status(503).json({
            error: 'GitHub SSO Not Configured',
            message: 'GITHUB_CLIENT_ID is missing in platform environment.'
        });
    }

    const state = crypto.randomBytes(32).toString('hex');
    res.setHeader('Set-Cookie', `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);

    const params = new URLSearchParams({
        client_id: process.env.GITHUB_CLIENT_ID,
        redirect_uri: `${API_URL}/api/auth/github/callback`,
        scope: 'read:user user:email read:org',
        state
    });

    res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

router.get('/github/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        log.warn(`[AUTH] GitHub returned OAuth error: ${error}`);
        return res.redirect(`${APP_URL}/app.html?auth_error=oauth_failed`);
    }

    if (!code || !state) {
        return res.redirect(`${APP_URL}/app.html?auth_error=missing_oauth_params`);
    }

    // Single-use state verification
    const storedState = getCookie(req, 'oauth_state');
    res.setHeader('Set-Cookie', 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT');

    if (!storedState || typeof state !== 'string' || storedState.length !== state.length) {
        log.warn('[AUTH] Missing or invalid oauth_state cookie for GitHub callback');
        return res.redirect(`${APP_URL}/app.html?auth_error=state_mismatch`);
    }

    const isStateValid = crypto.timingSafeEqual(Buffer.from(state), Buffer.from(storedState));
    if (!isStateValid) {
        log.warn('[AUTH] GitHub OAuth state mismatch');
        return res.redirect(`${APP_URL}/app.html?auth_error=state_mismatch`);
    }

    try {
        const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                client_id: process.env.GITHUB_CLIENT_ID,
                client_secret: process.env.GITHUB_CLIENT_SECRET,
                code,
                redirect_uri: `${API_URL}/api/auth/github/callback`
            })
        });
        const tokenData = await tokenRes.json();

        if (!tokenData.access_token) {
            throw new Error(tokenData.error_description || 'Failed to obtain GitHub access token');
        }

        const userRes = await fetch('https://api.github.com/user', {
            headers: {
                Authorization: `token ${tokenData.access_token}`,
                'User-Agent': 'ComplianceFlow-Auth'
            }
        });
        const profile = await userRes.json();

        if (!profile.email) {
            const emailRes = await fetch('https://api.github.com/user/emails', {
                headers: {
                    Authorization: `token ${tokenData.access_token}`,
                    'User-Agent': 'ComplianceFlow-Auth'
                }
            });
            const emails = await emailRes.json();
            const primary = Array.isArray(emails) && (emails.find(e => e.primary) || emails[0]);
            if (primary) profile.email = primary.email;
        }

        const domainCheck = validateEmailDomain(profile.email);
        if (!domainCheck.allowed) {
            log.warn(`[AUTH] Domain restriction blocked GitHub login for ${profile.email}`);
            return res.redirect(`${APP_URL}/app.html?auth_error=domain_restricted`);
        }

        if (ALLOWED_GITHUB_ORGS.length > 0) {
            const orgsRes = await fetch('https://api.github.com/user/orgs', {
                headers: {
                    Authorization: `token ${tokenData.access_token}`,
                    'User-Agent': 'ComplianceFlow-Auth'
                }
            });
            const userOrgs = await orgsRes.json();
            const orgLogins = Array.isArray(userOrgs) ? userOrgs.map(o => o.login.toLowerCase()) : [];
            const isMember = ALLOWED_GITHUB_ORGS.some(allowed => orgLogins.includes(allowed));

            if (!isMember) {
                log.warn(`[AUTH] GitHub org restriction blocked login for ${profile.login}`);
                return res.redirect(`${APP_URL}/app.html?auth_error=domain_restricted`);
            }
        }

        const { user, org, role } = await upsertUserFromOAuth(profile, 'github', profile.id);
        const session = createSessionToken(user, org, role, 1);

        res.setHeader('Set-Cookie', buildSessionCookies(session.token));
        await recordAuditEvent(org.id, user.id, 'user_authenticated', 'session', session.payload.sessionId, { provider: 'github', result: 'success' }, req).catch(() => {});

        log.info(`[AUTH] GitHub OAuth success: ${user.email} (Role: ${role}, Org: ${org.name})`);
        return res.redirect(`${APP_URL}/app.html?auth=success&role=${role}`);
    } catch (err) {
        if (err.code === 'ACCOUNT_EXISTS') {
            log.info(`[AUTH] Email collision blocked auto-merge for GitHub login: ${err.message}`);
            return res.redirect(`${APP_URL}/app.html?auth_error=account_exists`);
        }
        log.error('[AUTH] GitHub OAuth callback failure:', err.message);
        return res.redirect(`${APP_URL}/app.html?auth_error=oauth_failed`);
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Current User Session (/api/auth/me)
// ─────────────────────────────────────────────────────────────────────────────
router.get('/me', requireAuth(), (req, res) => {
    res.json({
        authenticated: true,
        user: req.user
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Pilot Access Code Login
// ─────────────────────────────────────────────────────────────────────────────
router.post('/pilot-login', async (req, res) => {
    const pilotCode = process.env.PILOT_ACCESS_CODE;
    if (!pilotCode) {
        return res.status(503).json({
            error: 'Pilot Access Not Configured',
            message: 'No pilot access code has been set. Contact your administrator.'
        });
    }

    const { code, email, name } = req.body || {};
    if (!code || code !== pilotCode) {
        log.warn(`[AUTH] Failed pilot login attempt from ${req.ip}`);
        return res.status(401).json({
            error: 'Invalid Access Code',
            message: 'The pilot access code is incorrect. Please check with your administrator.'
        });
    }

    if (!email) {
        return res.status(400).json({ error: 'Email required', message: 'Please provide your work email address.' });
    }

    const domainCheck = validateEmailDomain(email);
    if (!domainCheck.allowed) {
        return res.status(403).json({ error: 'Domain Restricted', message: domainCheck.reason });
    }

    try {
        const { user, org } = await upsertUserFromOAuth({ email, name: name || email.split('@')[0] }, 'pilot_code');
        const session = createSessionToken(user, org, ROLES.ADMIN, 1);

        // Sole browser session mechanism: HttpOnly cookie. No token in JSON response!
        res.setHeader('Set-Cookie', buildSessionCookies(session.token));
        await recordAuditEvent(org.id, user.id, 'user_authenticated', 'session', session.payload.sessionId, { provider: 'pilot_code', result: 'success' }, req).catch(() => {});

        log.info(`[AUTH] Pilot login: ${email} via access code`);

        res.json({
            success: true,
            message: `Authenticated as ${email}`,
            user: session.payload
        });
    } catch (err) {
        if (err.code === 'ACCOUNT_EXISTS') {
            return res.status(409).json({ error: 'Account Exists', message: err.message });
        }
        log.error('[AUTH] Pilot login failure:', err.message);
        res.status(500).json({ error: 'Login failed', message: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5b. Developer Mock Login (development environment ONLY)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/dev-login', async (req, res) => {
    if (process.env.NODE_ENV === 'production') {
        return res.status(403).json({
            error: 'Forbidden',
            message: 'Developer login is disabled in production environments.'
        });
    }

    const email = req.body?.email || 'admin@compflow.icu';
    const role = req.body?.role || ROLES.ADMIN;
    const name = req.body?.name || 'Compliance Administrator';

    if (!Object.values(ROLES).includes(role)) {
        return res.status(400).json({
            error: 'Bad Request',
            message: `Invalid role "${role}". Valid roles: ${Object.values(ROLES).join(', ')}`
        });
    }

    try {
        const { user, org } = await upsertUserFromOAuth({ email, name }, 'dev_portal');
        const session = createSessionToken(user, org, role, 1);

        // Sole browser session mechanism: HttpOnly cookie. No token in JSON response!
        res.setHeader('Set-Cookie', buildSessionCookies(session.token));
        await recordAuditEvent(org.id, user.id, 'user_authenticated', 'session', session.payload.sessionId, { provider: 'dev_portal', role }, req).catch(() => {});

        log.info(`[AUTH] Dev-login: ${email} as ${role}`);

        res.json({
            success: true,
            message: `Authenticated as ${email} (${role})`,
            user: session.payload
        });
    } catch (err) {
        if (err.code === 'ACCOUNT_EXISTS') {
            return res.status(409).json({ error: 'Account Exists', message: err.message });
        }
        log.error('[AUTH] Dev-login failure:', err.message);
        res.status(500).json({ error: 'Dev login failed', message: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Session Rotation (Amendment 18)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/rotate', requireAuth(), async (req, res) => {
    const token = getCookie(req, 'cf_session');
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized', message: 'Active session cookie required to rotate.' });
    }

    try {
        const newSession = rotateSession(token);
        res.setHeader('Set-Cookie', buildSessionCookies(newSession.token));
        await recordAuditEvent(newSession.payload.orgId, newSession.payload.userId, 'session_rotated', 'session', newSession.payload.sessionId, { result: 'success' }, req).catch(() => {});

        res.json({
            success: true,
            message: 'Session rotated successfully.',
            user: newSession.payload
        });
    } catch (err) {
        res.status(400).json({ error: 'Session rotation failed', message: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Logout (Server-Side Session Invalidation)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
    const token = getCookie(req, 'cf_session');

    if (token) {
        const check = validateSessionToken(token);
        if (check.valid && check.user) {
            await recordAuditEvent(check.user.orgId, check.user.userId, 'session_revoked', 'session', check.user.sessionId, { result: 'success' }, req).catch(() => {});
        }
        revokeSession(token);
    }

    res.setHeader('Set-Cookie', buildClearCookies());
    log.info('[AUTH] Session revoked and cookies cleared.');
    res.json({ success: true, message: 'Logged out successfully. Session revoked.' });
});

export default router;
