import { Router } from 'express';
import crypto from 'crypto';
import { createSessionToken, upsertUserFromOAuth, ROLES, validateSessionToken } from '../core/auth.js';
import { requireAuth, optionalAuth } from '../core/auth_guard.js';
import { log } from '../core/logger.js';

const router = Router();

const APP_URL = process.env.APP_URL || 'https://compflow.icu';
const API_URL = process.env.API_URL || 'https://api.compflow.icu';

// ─────────────────────────────────────────────────────────────────────────────
// 1. Providers Status Endpoint
// ─────────────────────────────────────────────────────────────────────────────
router.get('/providers', (req, res) => {
    res.json({
        google: {
            enabled: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
            authUrl: '/api/auth/google'
        },
        github: {
            enabled: Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET),
            authUrl: '/api/auth/github'
        },
        devLogin: process.env.NODE_ENV !== 'production' || process.env.ENABLE_DEV_LOGIN === 'true'
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Google OAuth 2.0 Flow
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

        // Upsert user & create session
        const { user, org, role } = await upsertUserFromOAuth(profile, 'google');
        const session = createSessionToken(user, org, role, 7);

        // Set secure session cookie & redirect to dashboard
        res.setHeader('Set-Cookie', [
            `cf_session=${session.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`,
            `cf_user_email=${encodeURIComponent(user.email)}; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`
        ]);

        return res.redirect(`${APP_URL}/app.html?auth=success&role=${role}`);
    } catch (err) {
        log.error('[AUTH] Google OAuth callback failure:', err);
        return res.redirect(`${APP_URL}/app.html?auth_error=${encodeURIComponent(err.message)}`);
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. GitHub OAuth Flow
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
        scope: 'read:user user:email',
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

        const { user, org, role } = await upsertUserFromOAuth(profile, 'github');
        const session = createSessionToken(user, org, role, 7);

        res.setHeader('Set-Cookie', [
            `cf_session=${session.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`,
            `cf_user_email=${encodeURIComponent(user.email)}; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`
        ]);

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
// 5. Developer & Testing Mock Login
// ─────────────────────────────────────────────────────────────────────────────
router.post('/dev-login', async (req, res) => {
    const email = req.body?.email || 'admin@compflow.icu';
    const role = req.body?.role || ROLES.ADMIN;
    const name = req.body?.name || 'Compliance Administrator';

    const { user, org } = await upsertUserFromOAuth({ email, name }, 'dev_portal');
    const session = createSessionToken(user, org, role, 7);

    res.setHeader('Set-Cookie', [
        `cf_session=${session.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`,
        `cf_user_email=${encodeURIComponent(user.email)}; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`
    ]);

    res.json({
        success: true,
        message: `Authenticated as ${email} (${role})`,
        sessionToken: session.token,
        user: session.payload
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Logout
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
    res.setHeader('Set-Cookie', [
        'cf_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0',
        'cf_user_email=; Secure; SameSite=Lax; Path=/; Max-Age=0'
    ]);
    res.json({ success: true, message: 'Logged out successfully' });
});

export default router;
