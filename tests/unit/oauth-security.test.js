import { describe, it, expect, afterEach } from 'vitest';
import crypto from 'crypto';
import authRouter from '../../api/auth.js';
import { 
    createSessionToken, 
    validateSessionToken, 
    revokeSession, 
    rotateSession,
    isSessionRevoked,
    ROLES 
} from '../../core/auth.js';

function invokeRouter(router, { method = 'GET', url = '/', headers = {}, body = {}, cookies = {} }) {
    return new Promise((resolve) => {
        const [path, queryString] = url.split('?');
        const query = {};
        if (queryString) {
            new URLSearchParams(queryString).forEach((val, key) => {
                query[key] = val;
            });
        }

        const req = {
            method,
            url,
            path,
            query,
            headers: { ...headers },
            cookies: { ...cookies },
            body
        };

        const res = {
            statusCode: 200,
            headers: {},
            body: null,
            setHeader(k, v) { res.headers[k.toLowerCase()] = v; return res; },
            getHeader(k) { return res.headers[k.toLowerCase()]; },
            status(code) { res.statusCode = code; return res; },
            json(data) { res.body = data; resolve(res); return res; },
            send(data) { res.body = data; resolve(res); return res; },
            redirect(url) {
                res.statusCode = 302;
                res.headers['location'] = url;
                resolve(res);
                return res;
            },
            end() { resolve(res); return res; }
        };

        router(req, res, () => {
            resolve(res);
        });
    });
}

describe('OAuth & Session Security Enforcement', () => {

    describe('OAuth State Validation & Replay Defense (Amendment 17)', () => {
        it('rejects Google OAuth callback when state parameter is missing', async () => {
            const res = await invokeRouter(authRouter, {
                method: 'GET',
                url: '/google/callback?code=mock_code'
            });

            expect(res.statusCode).toBe(302);
            expect(res.headers['location']).toContain('auth_error=missing_oauth_params');
        });

        it('rejects Google OAuth callback when oauth_state cookie is missing (no state saved)', async () => {
            const res = await invokeRouter(authRouter, {
                method: 'GET',
                url: '/google/callback?code=mock_code&state=forged_state_value'
            });

            expect(res.statusCode).toBe(302);
            expect(res.headers['location']).toContain('auth_error=state_mismatch');
        });

        it('rejects Google OAuth callback when state does not match cookie (CSRF defense)', async () => {
            const realState = 'a'.repeat(64);
            const attackerState = 'b'.repeat(64);

            const res = await invokeRouter(authRouter, {
                method: 'GET',
                url: `/google/callback?code=mock_code&state=${attackerState}`,
                headers: { cookie: `oauth_state=${realState}` },
                cookies: { oauth_state: realState }
            });

            expect(res.statusCode).toBe(302);
            expect(res.headers['location']).toContain('auth_error=state_mismatch');
        });

        it('rejects GitHub OAuth callback when state does not match cookie', async () => {
            const realState = 'x'.repeat(64);
            const forgedState = 'y'.repeat(64);

            const res = await invokeRouter(authRouter, {
                method: 'GET',
                url: `/github/callback?code=mock_code&state=${forgedState}`,
                headers: { cookie: `oauth_state=${realState}` },
                cookies: { oauth_state: realState }
            });

            expect(res.statusCode).toBe(302);
            expect(res.headers['location']).toContain('auth_error=state_mismatch');
        });

        it('enforces single-use state by clearing oauth_state cookie immediately upon validation', async () => {
            const state = 'f'.repeat(64);

            const res = await invokeRouter(authRouter, {
                method: 'GET',
                url: `/google/callback?code=invalid_mock_code&state=${state}`,
                headers: { cookie: `oauth_state=${state}` },
                cookies: { oauth_state: state }
            });

            expect(res.statusCode).toBe(302);
            const setCookies = res.headers['set-cookie'] || [];
            const clearStateCookie = setCookies.some(c => c.includes('oauth_state=') && (c.includes('Max-Age=0') || c.includes('Expires=')));
            expect(clearStateCookie).toBe(true);
        });

        it('redirects error parameters safely without leaking stack traces or internal errors', async () => {
            const res = await invokeRouter(authRouter, {
                method: 'GET',
                url: '/google/callback?error=access_denied'
            });

            expect(res.statusCode).toBe(302);
            expect(res.headers['location']).toContain('auth_error=oauth_failed');
            expect(res.headers['location']).not.toContain('stack');
        });
    });

    describe('Environment Hardening', () => {
        const originalEnv = process.env.NODE_ENV;

        afterEach(() => {
            process.env.NODE_ENV = originalEnv;
        });

        it('strictly forbids /api/auth/dev-login in production environments', async () => {
            process.env.NODE_ENV = 'production';

            const res = await invokeRouter(authRouter, {
                method: 'POST',
                url: '/dev-login',
                body: { role: 'ADMIN' }
            });

            expect(res.statusCode).toBe(403);
            expect(res.body.error).toBe('Forbidden');
            expect(res.body.message).toContain('disabled in production');
        });
    });

    describe('Session Replay & Rotation (Amendment 18)', () => {
        const mockUser = { id: 'usr_sec_1', email: 'sec@acme.com', name: 'Security Officer' };
        const mockOrg = { id: 'org_sec', name: 'Security Org' };

        it('rejects revoked session tokens on validation', () => {
            const session = createSessionToken(mockUser, mockOrg, ROLES.ADMIN, 1);
            expect(validateSessionToken(session.token).valid).toBe(true);

            revokeSession(session.token);

            expect(isSessionRevoked(session.token)).toBe(true);
            const check = validateSessionToken(session.token);
            expect(check.valid).toBe(false);
            expect(check.error).toContain('revoked');
        });

        it('rotates a session: invalidates old token and returns valid new token', () => {
            const originalSession = createSessionToken(mockUser, mockOrg, ROLES.ENGINEER, 1);
            expect(validateSessionToken(originalSession.token).valid).toBe(true);

            const newSession = rotateSession(originalSession.token);
            expect(newSession).toBeDefined();
            expect(newSession.token).not.toBe(originalSession.token);

            // Old token MUST now be revoked and invalid
            const oldCheck = validateSessionToken(originalSession.token);
            expect(oldCheck.valid).toBe(false);
            expect(oldCheck.error).toContain('revoked');

            // New token MUST be valid
            const newCheck = validateSessionToken(newSession.token);
            expect(newCheck.valid).toBe(true);
            expect(newCheck.user.email).toBe(mockUser.email);
        });

        it('fails rotation if the provided session token is already expired or invalid', () => {
            const expiredSession = createSessionToken(mockUser, mockOrg, ROLES.ENGINEER, -1);
            expect(() => rotateSession(expiredSession.token)).toThrow('Cannot rotate invalid session');
        });
    });
});
