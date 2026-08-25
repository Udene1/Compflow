import { Router } from 'express';
import crypto from 'crypto';
import { createSessionToken, upsertUserFromOAuth, ROLES, validateSessionToken, revokeSession } from '../core/auth.js';
import { requireAuth, optionalAuth } from '../core/auth_guard.js';
import { log } from '../core/logger.js';

const router = Router();

const APP_URL = process.env.APP_URL || 'https://compflow.icu';
const API_URL = process.env.API_URL || 'https://api.compflow.icu';

// ─────────────────────────────────────────────────────────────────────────────
// Domain & Organization Restriction Configuration
// ─────────────────────────────────────────────────────────────────────────────
// Comma-separated list of allowed email domains. If empty, all domains are allowed.
// Example: ALLOWED_DOMAINS=acme.com,contoso.org,compflow.icu
const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || '')
    .split(',')
    .map(d => d.trim().toLowerCase())
    .filter(Boolean);

// Comma-separated list of allowed GitHub organization logins.
// Example: ALLOWED_GITHUB_ORGS=acme-corp,contoso-security
const ALLOWED_GITHUB_ORGS = (process.env.ALLOWED_GITHUB_ORGS || '')
    .split(',')
    .map(o => o.trim().toLowerCase())
    .filter(Boolean);

// Whether to reject personal email domains (gmail.com, yahoo.com, etc.)
const REJECT_PERSONAL_EMAILS = process.env.REJECT_PERSONAL_EMAILS === 'true';

const PERSONAL_DOMAINS = new Set([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
    'aol.com', 'protonmail.com', 'zoho.com', 'mail.com', 'yandex.com'
]);

/**
 * Validates that an email domain is allowed by organization policy.
 * Returns { allowed: true } or { allowed: false, reason: string }
 */
function validateEmailDomain(email) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return { allowed: false, reason: 'Invalid email address format.' };

    // Check personal email rejection
    if (REJECT_PERSONAL_EMAILS && PERSONAL_DOMAINS.has(domain)) {
        return {
            allowed: false,
            reason: `Personal email domains (${domain}) are not allowed. Please sign in with your corporate email.`
        };
    }

    // Check domain allowlist (if configured)
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
    const devExplicitlyAllowed = process.env.ENABLE_DEV_LOGIN === 'true';

    res.json({
        google: {
            enabled: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
            authUrl: '/api/auth/google'
        },
        github: {
            enabled: Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET),
            authUrl: '/api/auth/github'
        },
        devLogin: isDev && devExplicitlyAllowed,
        domainRestrictions: {
            allowedDomains: ALLOWED_DOMAINS.length > 0 ? ALLOWED_DOMAINS : 'all',
            rejectPersonalEmails: REJECT_PERSONAL_EMAILS,
            allowedGitHubOrgs: ALLOWED_GITHUB_ORGS.length > 0 ? ALLOWED_GITHUB_ORGS : 'all'
        }
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Google OAuth 2.0 Flow (with hd claim enforcement)
// ─────────────────────────────────────────────────────────────────────────────
router.get('/google', (req, res) => {
    if (!process.env.GOOGLE_CLIENT_ID) {
        return res.status(503).json({
            error: 'Google SSO Not Configured',
            message: 'GOOGLE_CLIENT_ID is missing in platform environment.'
        });
    }

    const state = crypto.randomBytes(16).toString('hex');
    res.setHeader('Set-Cookie', `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);

    const params = new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        redirect_uri: `${API_URL}/api/auth/google/callback`,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        access_type: 'offline',
        prompt: 'select_account'
    });

    // If only one domain is allowed, enforce Google's hd (hosted domain) parameter
    // This restricts the Google account picker to only show that domain's accounts
    if (ALLOWED_DOMAINS.length === 1) {
        params.set('hd', ALLOWED_DOMAINS[0]);
    }

    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

router.get('/google/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(error)}`);
    }

    if (!code) {
        return res.status(400).json({ error: 'Missing authorization code' });
    }

    try {
        // Exchange code for tokens
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                redirect_uri: `${API_URL}/api/auth/google/callback`,
                grant_type: 'authorization_code'
            })
        });

        const tokens = await tokenResponse.json();
        if (!tokens.access_token) {
            throw new Error(tokens.error_description || 'Failed to obtain access token from Google');
        }

        // Fetch user profile
        const profileResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${tokens.access_token}` }
        });
        const profile = await profileResponse.json();

        // ── Domain Restriction Enforcement ──
        const domainCheck = validateEmailDomain(profile.email);
        if (!domainCheck.allowed) {
            log.warn(`[AUTH] Domain restriction blocked Google login for ${profile.email}: ${domainCheck.reason}`);
            return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(domainCheck.reason)}`);
        }

        // ── Google hd (hosted domain) Claim Verification ──
        // Even if hd was set in the auth URL, verify it server-side (defense in depth)
        if (ALLOWED_DOMAINS.length > 0 && profile.hd) {
            if (!ALLOWED_DOMAINS.includes(profile.hd.toLowerCase())) {
                const reason = `Google Workspace domain "${profile.hd}" is not authorized.`;
                log.warn(`[AUTH] hd claim mismatch blocked Google login for ${profile.email}: ${reason}`);
                return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(reason)}`);
            }
        }

        // Upsert user & create session
        const { user, org, role } = await upsertUserFromOAuth(profile, 'google');
        const session = createSessionToken(user, org, role, 7);

        // Set secure session cookie & redirect to dashboard
        res.setHeader('Set-Cookie', [
            `cf_session=${session.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`,
            `cf_user_email=${encodeURIComponent(user.email)}; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`
        ]);

        log.info(`[AUTH] Google OAuth success: ${user.email} (Role: ${role}, Org: ${org.name})`);
        return res.redirect(`${APP_URL}/app.html?auth=success&role=${role}`);
    } catch (err) {
        log.error('[AUTH] Google OAuth callback failure:', err);
        return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(err.message)}`);
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. GitHub OAuth Flow (with org membership enforcement)
// ─────────────────────────────────────────────────────────────────────────────
router.get('/github', (req, res) => {
    if (!process.env.GITHUB_CLIENT_ID) {
        return res.status(503).json({
            error: 'GitHub SSO Not Configured',
            message: 'GITHUB_CLIENT_ID is missing in platform environment.'
        });
    }

    const state = crypto.randomBytes(16).toString('hex');
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
        return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(error)}`);
    }

    try {
        // Exchange code for token
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

        // Fetch User Profile & primary email
        const userRes = await fetch('https://api.github.com/user', {
            headers: {
                Authorization: `token ${tokenData.access_token}`,
                'User-Agent': 'ComplianceFlow-Auth'
            }
        });
        const profile = await userRes.json();

        // If email is private, fetch from emails endpoint
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

        // ── Domain Restriction Enforcement ──
        const domainCheck = validateEmailDomain(profile.email);
        if (!domainCheck.allowed) {
            log.warn(`[AUTH] Domain restriction blocked GitHub login for ${profile.email}: ${domainCheck.reason}`);
            return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(domainCheck.reason)}`);
        }

        // ── GitHub Organization Membership Check ──
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
                const reason = `GitHub user "${profile.login}" is not a member of required organizations: [${ALLOWED_GITHUB_ORGS.join(', ')}]`;
                log.warn(`[AUTH] GitHub org restriction blocked: ${reason}`);
                return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(reason)}`);
            }
        }

        const { user, org, role } = await upsertUserFromOAuth(profile, 'github');
        const session = createSessionToken(user, org, role, 7);

        res.setHeader('Set-Cookie', [
            `cf_session=${session.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`,
            `cf_user_email=${encodeURIComponent(user.email)}; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`
        ]);

        log.info(`[AUTH] GitHub OAuth success: ${user.email} (Role: ${role}, Org: ${org.name})`);
        return res.redirect(`${APP_URL}/app.html?auth=success&role=${role}`);
    } catch (err) {
        log.error('[AUTH] GitHub OAuth callback failure:', err);
        return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(err.message)}`);
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
// 5. Developer & Testing Mock Login (disabled in production by default)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/dev-login', async (req, res) => {
    // Block dev-login in production unless explicitly enabled
    if (process.env.NODE_ENV === 'production' && process.env.ENABLE_DEV_LOGIN !== 'true') {
        return res.status(403).json({
            error: 'Forbidden',
            message: 'Developer login is disabled in production. Set ENABLE_DEV_LOGIN=true to override.'
        });
    }

    const email = req.body?.email || 'admin@compflow.icu';
    const role = req.body?.role || ROLES.ADMIN;
    const name = req.body?.name || 'Compliance Administrator';

    // Validate role is a known role
    if (!Object.values(ROLES).includes(role)) {
        return res.status(400).json({
            error: 'Bad Request',
            message: `Invalid role "${role}". Valid roles: ${Object.values(ROLES).join(', ')}`
        });
    }

    try {
        const { user, org } = await upsertUserFromOAuth({ email, name }, 'dev_portal');
        const session = createSessionToken(user, org, role, 1); // Dev sessions expire in 1 day

        res.setHeader('Set-Cookie', [
            `cf_session=${session.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${24 * 60 * 60}`,
            `cf_user_email=${encodeURIComponent(user.email)}; Secure; SameSite=Lax; Path=/; Max-Age=${24 * 60 * 60}`
        ]);

        log.info(`[AUTH] Dev-login: ${email} as ${role}`);

        res.json({
            success: true,
            message: `Authenticated as ${email} (${role})`,
            sessionToken: session.token,
            user: session.payload
        });
    } catch (err) {
        log.error('[AUTH] Dev-login failure:', err);
        res.status(500).json({ error: 'Dev login failed', message: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Logout (server-side session invalidation)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
    // Extract token to add to server-side revocation list
    const cookies = req.cookies || {};
    const token = cookies.cf_session ||
                  req.headers.authorization?.replace(/^Bearer\s+/i, '');
    
    if (token) {
        revokeSession(token);
    }

    // Clear all auth cookies with explicit expiry
    res.setHeader('Set-Cookie', [
        'cf_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'cf_user_email=; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    ]);

    log.info(`[AUTH] Session revoked and cookies cleared.`);
    res.json({ success: true, message: 'Logged out successfully. Session revoked.' });
});

export default router;
