import { describe, it, expect, beforeEach } from 'vitest';
import onboardingRouter from '../../api/onboarding.js';
import { requireAuth } from '../../core/auth_guard.js';
import { createSessionToken, ROLES } from '../../core/auth.js';

function invokeOnboarding({ method = 'GET', url = '/', body = {}, sessionToken = null }) {
    return new Promise((resolve) => {
        const [path, queryString] = url.split('?');
        const query = {};
        if (queryString) {
            new URLSearchParams(queryString).forEach((val, key) => {
                query[key] = val;
            });
        }

        const headers = {};
        const cookies = {};
        if (sessionToken) {
            headers['cookie'] = `cf_session=${sessionToken}`;
            cookies['cf_session'] = sessionToken;
        }

        const req = {
            method,
            url,
            path,
            query,
            headers,
            cookies,
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
            end() { resolve(res); return res; }
        };

        const chain = [requireAuth(), onboardingRouter];
        let idx = 0;
        function dispatch() {
            if (idx >= chain.length) return resolve(res);
            const fn = chain[idx++];
            fn(req, res, dispatch);
        }
        dispatch();
    });
}

describe('Authoritative Onboarding State Engine', () => {
    let session;
    const testOrgId = 'org_onboarding_test_99';
    const testUserId = 'usr_onboarding_test_99';

    beforeEach(() => {
        session = createSessionToken(
            { id: testUserId, email: 'founder@cyberco.io', name: 'CyberCo Founder' },
            { id: testOrgId, name: 'CyberCo' },
            ROLES.ADMIN,
            1
        );
    });

    it('retrieves initial onboarding status (AUTHENTICATED) with truthful guidance', async () => {
        const res = await invokeOnboarding({
            method: 'GET',
            url: '/status',
            sessionToken: session.token
        });

        expect(res.statusCode).toBe(200);
        expect(res.body.onboardingStatus).toBeDefined();
        expect(res.body.complianceGuidance).toContain('Compflow will use these objectives');
        expect(res.body.complianceGuidance).not.toContain('% compliant');
    });

    it('progresses to ORGANIZATION_CREATED upon saving organization profile', async () => {
        const res = await invokeOnboarding({
            method: 'POST',
            url: '/organization',
            sessionToken: session.token,
            body: {
                name: 'CyberCo Global',
                website: 'https://cyberco.io',
                industry: 'Cloud Security',
                companySize: '10-50'
            }
        });

        expect(res.statusCode).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.status).toBe('ORGANIZATION_CREATED');
        expect(res.body.organization.name).toBe('CyberCo Global');
    });

    it('progresses to OBJECTIVES_SELECTED upon selecting compliance frameworks', async () => {
        const res = await invokeOnboarding({
            method: 'POST',
            url: '/objectives',
            sessionToken: session.token,
            body: {
                frameworks: ['soc2', 'iso27001']
            }
        });

        expect(res.statusCode).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.status).toBe('OBJECTIVES_SELECTED');
        expect(res.body.selectedFrameworks).toContain('soc2');
        expect(res.body.selectedFrameworks).toContain('iso27001');
        expect(res.body.guidance).toContain('prioritize relevant controls');
    });

    it('registers cloud connection with PENDING status and does not leak credentials in response', async () => {
        const res = await invokeOnboarding({
            method: 'POST',
            url: '/cloud-connection',
            sessionToken: session.token,
            body: {
                provider: 'aws',
                displayName: 'CyberCo AWS Production',
                accountIdentifier: '123456789012',
                region: 'us-east-1',
                credentials: {
                    roleArn: 'arn:aws:iam::123456789012:role/CompflowAuditRole',
                    externalId: 'ext-cyberco-123'
                }
            }
        });

        expect(res.statusCode).toBe(201);
        expect(res.body.success).toBe(true);
        expect(res.body.connectionId).toBeDefined();
        expect(res.body.status).toBe('PENDING');
        // Critical: credentials must NOT be present in API response
        expect(res.body.credentials).toBeUndefined();
        expect(res.body.roleArn).toBeUndefined();
    });

    it('verifies connection, transitions to CLOUD_CONNECTED, and returns async scan reference', async () => {
        // 1. Create connection
        const connRes = await invokeOnboarding({
            method: 'POST',
            url: '/cloud-connection',
            sessionToken: session.token,
            body: {
                provider: 'aws',
                displayName: 'CyberCo AWS Staging',
                credentials: {
                    roleArn: 'arn:aws:iam::123456789012:role/CompflowAuditRole'
                }
            }
        });

        const connId = connRes.body.connectionId;

        // 2. Verify connection
        const verifyRes = await invokeOnboarding({
            method: 'POST',
            url: `/cloud-connection/${connId}/verify`,
            sessionToken: session.token
        });

        expect(verifyRes.statusCode).toBe(200);
        expect(verifyRes.body.verified).toBe(true);
        expect(verifyRes.body.status).toBe('VERIFIED');
        expect(verifyRes.body.onboardingStatus).toBe('CLOUD_CONNECTED');
        expect(verifyRes.body.scanId).toBeDefined();
        expect(verifyRes.body.message).toContain('You can wait here or go to your dashboard');
    });

    it('handles connection failure safely with retry flag and does not trap user', async () => {
        // Create connection with empty credentials to force verification failure
        const connRes = await invokeOnboarding({
            method: 'POST',
            url: '/cloud-connection',
            sessionToken: session.token,
            body: {
                provider: 'azure',
                credentials: {}
            }
        });

        const connId = connRes.body.connectionId;

        const verifyRes = await invokeOnboarding({
            method: 'POST',
            url: `/cloud-connection/${connId}/verify`,
            sessionToken: session.token
        });

        expect(verifyRes.statusCode).toBe(400);
        expect(verifyRes.body.verified).toBe(false);
        expect(verifyRes.body.status).toBe('FAILED');
        expect(verifyRes.body.retryable).toBe(true);
    });

    it('completes onboarding and transitions state to ONBOARDING_COMPLETED', async () => {
        const res = await invokeOnboarding({
            method: 'POST',
            url: '/complete',
            sessionToken: session.token
        });

        expect(res.statusCode).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.status).toBe('ONBOARDING_COMPLETED');
    });

    it('returns compliance summary with truthful control assessment metrics (Amendment 14)', async () => {
        const res = await invokeOnboarding({
            method: 'GET',
            url: '/summary',
            sessionToken: session.token
        });

        expect(res.statusCode).toBe(200);
        expect(res.body.cloud).toBeDefined();
        expect(res.body.compliance).toBeDefined();
        expect(Array.isArray(res.body.compliance.frameworks)).toBe(true);
        
        for (const fw of res.body.compliance.frameworks) {
            expect(fw.assessmentLabel).toContain('controls assessed');
            expect(fw.assessmentLabel).not.toContain('% compliant');
        }
    });
});
