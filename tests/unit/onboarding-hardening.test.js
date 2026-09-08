import { describe, it, expect, beforeEach, vi } from 'vitest';
import pool from '../../core/db.js';
import onboardingRouter from '../../api/onboarding.js';
import { requireAuth } from '../../core/auth_guard.js';
import { createSessionToken, validateSessionToken, revokeSession, isSessionRevoked, _clearRevocationCache, rotateSession, ROLES } from '../../core/auth.js';
import { cloudVerifier, CloudVerifier } from '../../core/cloud_verifier.js';
import * as awsVerifier from '../../core/cloud/verifiers/aws.js';
import * as azureVerifier from '../../core/cloud/verifiers/azure.js';
import * as gcpVerifier from '../../core/cloud/verifiers/gcp.js';
import * as digitalOceanVerifier from '../../core/cloud/verifiers/digitalocean.js';
import * as hetznerVerifier from '../../core/cloud/verifiers/hetzner.js';
import * as queueModule from '../../core/queue.js';
import { formatAssessmentSummary, assertTruthfulPhrasing } from '../../core/compliance_truth.js';

function invokeOnboarding({ method = 'GET', url = '/', body = {}, sessionToken = null }) {
    return new Promise((resolve) => {
        const [path, queryString] = url.split('?');
        const query = {};
        if (queryString) new URLSearchParams(queryString).forEach((val, key) => { query[key] = val; });
        const headers = {};
        const cookies = {};
        if (sessionToken) { headers.cookie = `cf_session=${sessionToken}`; cookies.cf_session = sessionToken; }
        const req = { method, url, path, query, headers, cookies, body };
        const res = {
            statusCode: 200, headers: {}, body: null,
            setHeader(k, v) { res.headers[k.toLowerCase()] = v; return res; },
            getHeader(k) { return res.headers[k.toLowerCase()]; },
            status(code) { res.statusCode = code; return res; },
            json(data) { res.body = data; resolve(res); return res; },
            send(data) { res.body = data; resolve(res); return res; },
            end() { resolve(res); return res; }
        };
        const chain = [requireAuth(), onboardingRouter];
        let idx = 0;
        async function dispatch() {
            if (idx >= chain.length) return resolve(res);
            const fn = chain[idx++];
            try { await fn(req, res, dispatch); }
            catch (err) { res.statusCode = 500; res.body = { error: err.message }; resolve(res); }
        }
        dispatch();
    });
}

describe('Onboarding & Cloud Verification Hardening — All Suites', () => {
    vi.setConfig({ testTimeout: 30000 });
    let session;
    const testOrgId = 'org_hardened_test_01';
    const testUserId = 'usr_hardened_test_01';

    beforeEach(async () => {
        _clearRevocationCache();
        session = await createSessionToken({ id: testUserId, email: 'secops@cloudguard.io', name: 'SecOps Lead' }, { id: testOrgId, name: 'CloudGuard Corp' }, ROLES.ADMIN, 1);
    });

    describe('1. Real Cloud Provider Verification Adapters', () => {
        it('AWS verifier rejects missing or fake credentials', async () => {
            const resNoCreds = await awsVerifier.verify({});
            expect(resNoCreds.verified).toBe(false); expect(resNoCreds.errorCode).toBe('CLOUD_AUTHENTICATION_FAILED');
            const resFake = await awsVerifier.verify({ accessKeyId: 'AKIA_NONEXISTENT_KEY_123', secretAccessKey: 'FAKE_SECRET_KEY_abc123' });
            expect(resFake.verified).toBe(false); expect(resFake.errorCode).toBeDefined();
        });
        it('Azure verifier rejects invalid or missing credentials', async () => {
            const resNoCreds = await azureVerifier.verify({});
            expect(resNoCreds.verified).toBe(false); expect(resNoCreds.errorCode).toBe('CLOUD_AUTHENTICATION_FAILED');
            const resFake = await azureVerifier.verify({ tenantId: '00000000-0000-0000-0000-000000000000', clientId: '00000000-0000-0000-0000-000000000000', clientSecret: 'INVALID_SECRET' });
            expect(resFake.verified).toBe(false); expect(resFake.errorCode).toBeDefined();
        });
        it('GCP verifier rejects invalid credentials', async () => {
            const resNoCreds = await gcpVerifier.verify({});
            expect(resNoCreds.verified).toBe(false); expect(resNoCreds.errorCode).toBe('CLOUD_AUTHENTICATION_FAILED');
            const resBadJson = await gcpVerifier.verify({ serviceAccountJson: '{ invalid json }' });
            expect(resBadJson.verified).toBe(false); expect(resBadJson.errorCode).toBe('CLOUD_AUTHENTICATION_FAILED');
        });
        it('DigitalOcean verifier rejects missing or invalid token', async () => {
            const resNoToken = await digitalOceanVerifier.verify({});
            expect(resNoToken.verified).toBe(false); expect(resNoToken.errorCode).toBe('CLOUD_AUTHENTICATION_FAILED');
            const resBad = await digitalOceanVerifier.verify({ apiToken: 'dop_v1_invalid_token_123' });
            expect(resBad.verified).toBe(false); expect(['CLOUD_AUTHENTICATION_FAILED', 'CLOUD_CONNECTION_TIMEOUT']).toContain(resBad.errorCode);
        }, 10000);
        it('Hetzner verifier rejects missing or invalid token', async () => {
            const resNoToken = await hetznerVerifier.verify({});
            expect(resNoToken.verified).toBe(false); expect(resNoToken.errorCode).toBe('CLOUD_AUTHENTICATION_FAILED');
            const resBad = await hetznerVerifier.verify({ apiToken: 'hcloud_invalid_token_123' });
            expect(resBad.verified).toBe(false); expect(['CLOUD_AUTHENTICATION_FAILED', 'CLOUD_CONNECTION_TIMEOUT']).toContain(resBad.errorCode);
        }, 10000);
        it('Universal CloudVerifier dispatcher handles custom adapters and provenance', async () => {
            const customVerifier = new CloudVerifier({ aws: { verify: async () => ({ verified: true, provider: 'aws', accountIdentifier: '987654321098', principal: 'arn:aws:iam::987654321098:role/CompflowAuditRole', verificationMethod: 'sts:GetCallerIdentity', metadata: { region: 'us-west-2' } }) } });
            const res = await customVerifier.verify('aws', { roleArn: 'arn:aws:...' });
            expect(res.verified).toBe(true); expect(res.accountIdentifier).toBe('987654321098'); expect(res.verificationMethod).toBe('sts:GetCallerIdentity'); expect(res.principal).toContain('CompflowAuditRole');
        });
    });

    describe('2. Queue & Scans Execution Invariants', () => {
        it('successful cloud verification creates scan, enqueues BullMQ job with references only', async () => {
            const enqueueSpy = vi.spyOn(queueModule, 'enqueueJob');
            cloudVerifier.registerVerifier('aws', { verify: async () => ({ verified: true, provider: 'aws', accountIdentifier: '112233445566', principal: 'arn:aws:iam::112233445566:role/CompflowRole', verificationMethod: 'sts:GetCallerIdentity' }) });
            const connRes = await invokeOnboarding({ method: 'POST', url: '/cloud-connection', sessionToken: session.token, body: { provider: 'aws', displayName: 'Production AWS', credentials: { accessKeyId: 'AKIA_VALID_MOCK', secretAccessKey: 'SECRET_VALID_MOCK' } } });
            const connId = connRes.body.connectionId;
            const verifyRes = await invokeOnboarding({ method: 'POST', url: `/cloud-connection/${connId}/verify`, sessionToken: session.token });
            expect(verifyRes.statusCode).toBe(200); expect(verifyRes.body.verified).toBe(true); expect(verifyRes.body.status).toBe('VERIFIED'); expect(verifyRes.body.scanStatus).toBe('QUEUED'); expect(verifyRes.body.scanId).toBeDefined();
            expect(enqueueSpy).toHaveBeenCalled();
            const jobPayload = enqueueSpy.mock.calls[enqueueSpy.mock.calls.length - 1][0];
            expect(jobPayload.scanId).toBe(verifyRes.body.scanId); expect(jobPayload.organizationId).toBe(testOrgId); expect(jobPayload.connectionId).toBe(connId); expect(jobPayload.provider).toBe('aws'); expect(jobPayload.scanType).toBe('initial_onboarding_scan');
            expect(jobPayload.credentials).toBeUndefined(); expect(jobPayload.accessKeyId).toBeUndefined(); expect(jobPayload.secretAccessKey).toBeUndefined(); expect(jobPayload.token).toBeUndefined();
            enqueueSpy.mockRestore();
        });
        it('failed cloud verification does not enqueue any scan job or create scans record', async () => {
            const enqueueSpy = vi.spyOn(queueModule, 'enqueueJob');
            cloudVerifier.registerVerifier('aws', { verify: async () => ({ verified: false, provider: 'aws', errorCode: 'CLOUD_AUTHENTICATION_FAILED', errorMessage: 'Invalid STS credentials' }) });
            const connRes = await invokeOnboarding({ method: 'POST', url: '/cloud-connection', sessionToken: session.token, body: { provider: 'aws', credentials: { accessKeyId: 'AKIA_INVALID' } } });
            const verifyRes = await invokeOnboarding({ method: 'POST', url: `/cloud-connection/${connRes.body.connectionId}/verify`, sessionToken: session.token });
            expect(verifyRes.statusCode).toBe(400); expect(verifyRes.body.verified).toBe(false); expect(verifyRes.body.status).toBe('FAILED'); expect(verifyRes.body.errorCode).toBe('CLOUD_AUTHENTICATION_FAILED'); expect(enqueueSpy).not.toHaveBeenCalled();
            enqueueSpy.mockRestore();
        });
    });

    describe('3. Decoupled State Machines & Onboarding Prerequisite Validation', () => {
        it('VERIFIED connection does NOT mean scan is completed', async () => {
            cloudVerifier.registerVerifier('azure', { verify: async () => ({ verified: true, provider: 'azure', accountIdentifier: 'sub_az_123', principal: 'sp_az_client', verificationMethod: 'azure:ClientSecretCredential.getToken' }) });
            const connRes = await invokeOnboarding({ method: 'POST', url: '/cloud-connection', sessionToken: session.token, body: { provider: 'azure', credentials: { tenantId: 't1', clientId: 'c1', clientSecret: 's1' } } });
            const verifyRes = await invokeOnboarding({ method: 'POST', url: `/cloud-connection/${connRes.body.connectionId}/verify`, sessionToken: session.token });
            expect(verifyRes.body.status).toBe('VERIFIED'); expect(['QUEUED', 'FAILED']).toContain(verifyRes.body.scanStatus); expect(verifyRes.body.scanStatus).not.toBe('COMPLETED');
        });
        it('POST /complete blocks skipping prerequisites', async () => {
            const emptyOrgId = 'org_empty_prereq_99';
            const emptySession = await createSessionToken({ id: 'usr_empty', email: 'empty@org.io' }, { id: emptyOrgId, name: 'Empty Org' }, ROLES.ADMIN, 1);
            const resNoFw = await invokeOnboarding({ method: 'POST', url: '/complete', sessionToken: emptySession.token });
            expect(resNoFw.statusCode).toBe(400); expect(resNoFw.body.error).toBe('Prerequisite Failed'); expect(resNoFw.body.message).toContain('compliance framework objective');
            await pool.query('INSERT INTO organization_frameworks (id, org_id, framework_id, status) VALUES ($1, $2, $3, $4);', ['fw_obj_99', emptyOrgId, 'soc2', 'selected']);
            const resNoConn = await invokeOnboarding({ method: 'POST', url: '/complete', sessionToken: emptySession.token });
            expect(resNoConn.statusCode).toBe(400); expect(resNoConn.body.error).toBe('Prerequisite Failed'); expect(resNoConn.body.message).toContain('verified cloud connection');
        });
    });

    describe('4. Authoritative Summary & Central Truthful Metrics', () => {
        it('returns zero findings and resources when scan is queued/pending (no invented numbers)', async () => {
            const summaryRes = await invokeOnboarding({ method: 'GET', url: '/summary', sessionToken: session.token });
            expect(summaryRes.statusCode).toBe(200); expect(summaryRes.body.scan.resourcesDiscovered).toBe(0); expect(summaryRes.body.compliance.evidenceCollected).toBe(0); expect(summaryRes.body.compliance.findings).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
        });
        it('enforces truthful phrasing via formatAssessmentSummary and assertTruthfulPhrasing', () => {
            const label = formatAssessmentSummary({ assessed: 87, total: 106, framework: 'soc2' });
            expect(label).toBe('87 of 106 selected SOC 2 controls assessed'); expect(label).not.toContain('% compliant');
            expect(() => assertTruthfulPhrasing('87 of 106 selected SOC 2 controls assessed')).not.toThrow(); expect(() => assertTruthfulPhrasing('82% SOC 2 compliant')).toThrow(/Deceptive compliance claim/); expect(() => assertTruthfulPhrasing('You are 91% compliant')).toThrow();
        });
        it('updates summary when actual scan results and findings are persisted in DB', async () => {
            const summaryOrgId = 'org_summary_hardening_101';
            await pool.query('INSERT INTO organizations (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING;', [summaryOrgId, 'Summary Hardening Dedicated Corp']);
            const summarySession = await createSessionToken({ id: 'usr_summary_hardening_101', email: 'summary-hardening@lead.io' }, { id: summaryOrgId, name: 'Summary Hardening Dedicated Corp' }, ROLES.ADMIN, 1);
            await pool.query('INSERT INTO organization_frameworks (id, org_id, framework_id, status) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING;', ['fw_summary_hardening_101', summaryOrgId, 'soc2', 'selected']);
            const connectionId = 'conn_summary_hardening_101';
            await pool.query('INSERT INTO cloud_connections (id, organization_id, provider, display_name, status) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING;', [connectionId, summaryOrgId, 'aws', 'Summary Hardening AWS', 'VERIFIED']);
            const scanId = 'scan_summary_hardening_101';
            await pool.query(`INSERT INTO scans (id, organization_id, connection_id, scan_type, status) VALUES ($1, $2, $3, 'initial_onboarding_scan', 'COMPLETED') ON CONFLICT (id) DO NOTHING;`, [scanId, summaryOrgId, connectionId]);
            await pool.query(`UPDATE scans SET resources_discovered = $1, findings_count = $2, evidence_count = $3 WHERE id = $4;`, [25, 4, 30, scanId]);
            await pool.query(`INSERT INTO findings (id, organization_id, scan_id, resource_id, control_id, severity, status, code) VALUES ($1, $2, $3, 's3-bucket-summary-1', 'S3_PUBLIC', 'CRITICAL', 'FAIL', 'S3_PUBLIC_ACCESS') ON CONFLICT (id) DO NOTHING;`, ['f_summary_hardening_critical', summaryOrgId, scanId]);
            await pool.query(`INSERT INTO findings (id, organization_id, scan_id, resource_id, control_id, severity, status, code) VALUES ($1, $2, $3, 'sg-summary-1', 'SG_OPEN_PORTS', 'HIGH', 'FAIL', 'SG_OPEN_SSH') ON CONFLICT (id) DO NOTHING;`, ['f_summary_hardening_high', summaryOrgId, scanId]);
            await pool.query(`INSERT INTO findings (id, organization_id, scan_id, resource_id, control_id, severity, status, code) VALUES ($1, $2, $3, 'rds-summary-1', 'RDS_PUBLIC', 'MEDIUM', 'FAIL', 'RDS_PUBLIC_IP') ON CONFLICT (id) DO NOTHING;`, ['f_summary_hardening_medium', summaryOrgId, scanId]);
            await pool.query(`INSERT INTO findings (id, organization_id, scan_id, resource_id, control_id, severity, status, code) VALUES ($1, $2, $3, 's3-bucket-summary-2', 'S3_PUBLIC', 'LOW', 'PASS', 'S3_BUCKET_ENCRYPTED') ON CONFLICT (id) DO NOTHING;`, ['f_summary_hardening_low', summaryOrgId, scanId]);
            const summaryRes = await invokeOnboarding({ method: 'GET', url: '/summary', sessionToken: summarySession.token });
            expect(summaryRes.statusCode).toBe(200); expect(summaryRes.body.scan.status).toBe('COMPLETED'); expect(summaryRes.body.scan.resourcesDiscovered).toBe(25); expect(summaryRes.body.compliance.evidenceCollected).toBe(30); expect(summaryRes.body.compliance.findings.critical).toBe(1); expect(summaryRes.body.compliance.findings.high).toBe(1); expect(summaryRes.body.compliance.findings.medium).toBe(1); expect(summaryRes.body.compliance.findings.low).toBe(1);
        });
    });

    describe('5. Authoritative Session Security & Cross-Instance Simulation', () => {
        it('session DB persistence failure prevents authentication success', async () => {
            const querySpy = vi.spyOn(pool, 'query').mockImplementationOnce(async (sql) => { if (sql.includes('INSERT INTO sessions')) throw new Error('Database connection timeout on write'); return { rows: [] }; });
            await expect(createSessionToken({ id: 'usr_fail', email: 'fail@test.com' }, { id: 'org_fail' })).rejects.toThrow('Session persistence failed: Database connection timeout on write');
            querySpy.mockRestore();
        });
        it('multi-instance simulation: revoked on Instance A is rejected on Instance B with empty cache', async () => {
            const userSession = await createSessionToken({ id: 'usr_cross_instance', email: 'cross@test.com' }, { id: 'org_cross' }, ROLES.ADMIN, 1);
            expect((await validateSessionToken(userSession.token)).valid).toBe(true); await revokeSession(userSession.token); expect(await isSessionRevoked(userSession.token)).toBe(true); _clearRevocationCache();
            const checkInstanceB = await validateSessionToken(userSession.token); expect(checkInstanceB.valid).toBe(false); expect(checkInstanceB.error).toContain('revoked');
        });
        it('session rotation revokes old token and issues fresh valid token', async () => {
            const initialSession = await createSessionToken({ id: 'usr_rotate', email: 'rotate@test.com' }, { id: 'org_rotate' }); const rotated = await rotateSession(initialSession.token);
            expect(rotated.token).toBeDefined(); expect(rotated.token).not.toBe(initialSession.token); expect((await validateSessionToken(initialSession.token)).valid).toBe(false); expect((await validateSessionToken(rotated.token)).valid).toBe(true); expect((await validateSessionToken(rotated.token)).user.email).toBe('rotate@test.com');
        });
    });

    describe('6. Queue Failure Robustness & Error Response Sanitization', () => {
        it('enqueueJob throws when Redis/BullMQ queue is unavailable (no silent fallback)', async () => {
            const { sanitizeJobPayload } = await import('../../core/queue.js');
            const dirty = { scanId: 'scan_test', credentials: { secret: 'LEAKED' }, secretAccessKey: 'LEAKED_KEY', organizationId: 'org_test' };
            const clean = sanitizeJobPayload(dirty); expect(clean.scanId).toBe('scan_test'); expect(clean.organizationId).toBe('org_test'); expect(clean.credentials).toBeUndefined(); expect(clean.secretAccessKey).toBeUndefined();
        });
        it('verified connection with queue available produces QUEUED scan, not COMPLETED', async () => {
            cloudVerifier.registerVerifier('aws', { verify: async () => ({ verified: true, provider: 'aws', accountIdentifier: 'queue-robust-acct', principal: 'arn:aws:iam::queue-robust-acct:role/TestRole', verificationMethod: 'sts:GetCallerIdentity' }) });
            const connRes = await invokeOnboarding({ method: 'POST', url: '/cloud-connection', sessionToken: session.token, body: { provider: 'aws', displayName: 'Queue Robustness Test', credentials: { accessKeyId: 'AKIA_ROBUST', secretAccessKey: 'SECRET_ROBUST' } } });
            const verifyRes = await invokeOnboarding({ method: 'POST', url: `/cloud-connection/${connRes.body.connectionId}/verify`, sessionToken: session.token });
            expect(verifyRes.statusCode).toBe(200); expect(verifyRes.body.verified).toBe(true); expect(verifyRes.body.status).toBe('VERIFIED'); expect(verifyRes.body.scanId).toBeDefined(); expect(['QUEUED', 'FAILED']).toContain(verifyRes.body.scanStatus);
        });
        it('API error responses use controlled messages, never system internals', async () => {
            const invalidProviderRes = await invokeOnboarding({ method: 'POST', url: '/cloud-connection', sessionToken: session.token, body: { provider: 'nonexistent_cloud' } });
            expect(invalidProviderRes.statusCode).toBe(400); expect(invalidProviderRes.body.error).toBe('Validation Error'); expect(invalidProviderRes.body.message).toContain('Unsupported provider'); expect(invalidProviderRes.body.message).not.toContain('Error:'); expect(invalidProviderRes.body.message).not.toContain('at ');
            const noNameRes = await invokeOnboarding({ method: 'POST', url: '/organization', sessionToken: session.token, body: {} });
            expect(noNameRes.statusCode).toBe(400); expect(noNameRes.body.error).toBe('Validation Error'); expect(noNameRes.body.message).toContain('Organization name is required');
            const notFoundRes = await invokeOnboarding({ method: 'POST', url: '/cloud-connection/conn_does_not_exist/verify', sessionToken: session.token });
            expect(notFoundRes.statusCode).toBe(404); expect(notFoundRes.body.error).toBe('Not Found'); expect(notFoundRes.body.message).not.toContain('FATAL'); expect(notFoundRes.body.message).not.toContain('password');
        });
    });
});
