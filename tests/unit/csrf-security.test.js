import { describe, it, expect, beforeEach } from 'vitest';
import authRouter from '../../api/auth.js';
import onboardingRouter from '../../api/onboarding.js';
import { requireAuth } from '../../core/auth_guard.js';
import { createSessionToken, ROLES } from '../../core/auth.js';

function invokeWithMiddleware(middlewareChain, { method = 'GET', url = '/', headers = {}, body = {}, cookies = {} }) {
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

        let idx = 0;
        function dispatch() {
            if (idx >= middlewareChain.length) {
                return resolve(res);
            }
            const fn = middlewareChain[idx++];
            fn(req, res, dispatch);
        }
        dispatch();
    });
}

describe('CSRF & Cookie Security Protection (Amendment 19)', () => {
    let validSession;

    beforeEach(async () => {
        validSession = await createSessionToken(
            { id: 'usr_csrf_test', email: 'csrf@acme.com', name: 'CSRF Tester' },
            { id: 'org_csrf', name: 'CSRF Org' },
            ROLES.ADMIN,
            1
        );
    });

    describe('Cookie Security Attributes', () => {
        it('ensures session cookies are issued with HttpOnly, Secure, and SameSite=Lax', async () => {
            const res = await invokeWithMiddleware([authRouter], {
                method: 'POST',
                url: '/dev-login',
                body: { role: 'ADMIN', email: 'admin@acme.com' }
            });

            expect(res.statusCode).toBe(200);
            const setCookies = res.headers['set-cookie'] || [];
            const sessionCookie = setCookies.find(c => c.startsWith('cf_session='));

            expect(sessionCookie).toBeDefined();
            expect(sessionCookie).toContain('HttpOnly');
            expect(sessionCookie).toContain('Secure');
            expect(sessionCookie).toContain('SameSite=Lax');
            // Amendment 2: Ensure non-HttpOnly email cookie is NOT set
            const emailCookie = setCookies.find(c => c.startsWith('cf_user_email='));
            expect(emailCookie).toBeUndefined();
        });
    });

    describe('State-Changing Endpoint Authorization & Cookie Requirements', () => {
        const onboardingChain = [requireAuth(), onboardingRouter];

        it('blocks unauthenticated POST /organization with 401', async () => {
            const res = await invokeWithMiddleware(onboardingChain, {
                method: 'POST',
                url: '/organization',
                body: { name: 'Malicious Org Name' }
            });

            expect(res.statusCode).toBe(401);
            expect(res.body.error).toBe('Unauthorized');
        });

        it('blocks unauthenticated POST /objectives with 401', async () => {
            const res = await invokeWithMiddleware(onboardingChain, {
                method: 'POST',
                url: '/objectives',
                body: { frameworks: ['soc2'] }
            });

            expect(res.statusCode).toBe(401);
            expect(res.body.error).toBe('Unauthorized');
        });

        it('blocks unauthenticated POST /cloud-connection with 401', async () => {
            const res = await invokeWithMiddleware(onboardingChain, {
                method: 'POST',
                url: '/cloud-connection',
                body: { provider: 'aws' }
            });

            expect(res.statusCode).toBe(401);
            expect(res.body.error).toBe('Unauthorized');
        });

        it('blocks unauthenticated POST /complete with 401', async () => {
            const res = await invokeWithMiddleware(onboardingChain, {
                method: 'POST',
                url: '/complete'
            });

            expect(res.statusCode).toBe(401);
            expect(res.body.error).toBe('Unauthorized');
        });

        it('allows authenticated state-changing requests when accompanied by valid session cookie', async () => {
            const res = await invokeWithMiddleware(onboardingChain, {
                method: 'POST',
                url: '/organization',
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
