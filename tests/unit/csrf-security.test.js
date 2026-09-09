import { describe, it, expect, beforeEach } from 'vitest';
import authRouter from '../../api/auth.js';
import onboardingRouter from '../../api/onboarding.js';
import { requireAuth } from '../../core/auth_guard.js';
import { createSessionToken, ROLES } from '../../core/auth.js';

function invokeWithMiddleware(middlewareChain, { method = 'GET', url = '/', headers = {}, body = {}, cookies = {} }) {
    return new Promise((resolve) => {
        const [path, queryString] = url.split('?');
        const query = {};
        if (queryString) new URLSearchParams(queryString).forEach((val, key) => { query[key] = val; });
        const req = { method, url, path, query, headers: { ...headers }, cookies: { ...cookies }, body };
        const res = {
            statusCode: 200, headers: {}, body: null,
            setHeader(k, v) { res.headers[k.toLowerCase()] = v; return res; },
            getHeader(k) { return res.headers[k.toLowerCase()]; },
            status(code) { res.statusCode = code; return res; },
            json(data) { res.body = data; resolve(res); return res; },
            send(data) { res.body = data; resolve(res); return res; },
            redirect(url) { res.statusCode = 302; res.headers.location = url; resolve(res); return res; },
            end() { resolve(res); return res; }
        };
        let idx = 0;
        function dispatch() {
            if (idx >= middlewareChain.length) return resolve(res);
            middlewareChain[idx++](req, res, dispatch);
        }
        dispatch();
    });
}

describe('CSRF & Cookie Security Protection (Amendment 19)', () => {
    let validSession;
    beforeEach(async () => {
        validSession = await createSessionToken(
            { id: 'usr_csrf_test', email: 'csrf@acme.com', name: 'CSRF Tester' },
            { id: 'org_csrf', name: 'CSRF Org' }, ROLES.ADMIN, 1
        );
    });

    describe('Cookie Security Attributes', () => {
        it('ensures session cookies are issued with HttpOnly, Secure, and SameSite=Lax', async () => {
            const res = await invokeWithMiddleware([authRouter], { method: 'POST', url: '/dev-login', body: { role: 'ADMIN', email: 'admin@acme.com' } });
            expect(res.statusCode).toBe(200);
            const setCookies = res.headers['set-cookie'] || [];
            const sessionCookie = setCookies.find(c => c.startsWith('cf_session='));
            expect(sessionCookie).toBeDefined();
            expect(sessionCookie).toContain('HttpOnly');
            expect(sessionCookie).toContain('Secure');
            expect(sessionCookie).toContain('SameSite=Lax');
            expect(setCookies.find(c => c.startsWith('cf_user_email='))).toBeUndefined();
        });
    });

    describe('State-Changing Endpoint Authorization & Cookie Requirements', () => {
        const onboardingChain = [requireAuth(), onboardingRouter];
        for (const [label, url, body] of [
            ['organization', '/organization', { name: 'Malicious Org Name' }],
            ['objectives', '/objectives', { frameworks: ['soc2'] }],
            ['cloud connection', '/cloud-connection', { provider: 'aws' }],
            ['complete', '/complete', undefined]
        ]) {
            it(`blocks unauthenticated POST /${url.slice(1)} with stable authentication code`, async () => {
                const res = await invokeWithMiddleware(onboardingChain, { method: 'POST', url, body });
                expect(res.statusCode).toBe(401);
                expect(res.body.code).toBe('AUTHENTICATION_REQUIRED');
                expect(res.body.error).toBe('Unauthorized');
                expect(res.body.message).toContain('Authentication required');
            });
        }

        it('allows authenticated state-changing requests when accompanied by valid session cookie', async () => {
            const res = await invokeWithMiddleware(onboardingChain, {
                method: 'POST', url: '/organization',
                headers: { cookie: `cf_session=${validSession.token}` },
                cookies: { cf_session: validSession.token },
                body: { name: 'Acme Protected Systems', industry: 'Fintech', companySize: '50-100' }
            });
            expect(res.statusCode).toBe(200);
            expect(res.body.success).toBe(true);
            expect(res.body.organization.name).toBe('Acme Protected Systems');
        });
    });
});
