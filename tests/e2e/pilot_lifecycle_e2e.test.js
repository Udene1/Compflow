import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { createSessionToken, ROLES } from '../../core/auth.js';

const { Client } = pg;
const PORT = 43123;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const adminEmail = `pilot-admin-${randomUUID()}@example.test`;
const adminUserId = `usr_e2e_admin_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
const adminOrgId = `org_e2e_admin_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
let adminBearer;
let serverProcess;

async function db(query, params = []) {
    const client = new Client({ connectionString: process.env.DATABASE_URL });
    await client.connect();
    try { return await client.query(query, params); } finally { await client.end(); }
}

async function waitForReady(timeoutMs = 30000) {
    const deadline = Date.now() + timeoutMs;
    let lastError;
    while (Date.now() < deadline) {
        try {
            const response = await fetch(`${BASE_URL}/health/ready`);
            if (response.ok) return;
            lastError = new Error(`readiness returned ${response.status}`);
        } catch (error) { lastError = error; }
        await new Promise(resolve => setTimeout(resolve, 250));
    }
    throw lastError || new Error('server readiness timed out');
}

function sessionCookie(response) {
    const setCookie = response.headers.get('set-cookie') || '';
    const match = setCookie.match(/(?:^|,\s*)cf_session=([^;]+)/);
    if (!match) throw new Error('pilot login did not set cf_session');
    return `cf_session=${match[1]}`;
}

async function pilotLogin(code, email, name) {
    const response = await fetch(`${BASE_URL}/api/pilot/redeem`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code, email, name })
    });
    const body = await response.json();
    return { response, body, cookie: response.ok ? sessionCookie(response) : null };
}

beforeAll(async () => {
    await db('INSERT INTO users(id,email,name) VALUES($1,$2,$3) ON CONFLICT (id) DO NOTHING', [adminUserId, adminEmail, 'E2E Platform Admin']);
    await db('INSERT INTO organizations(id,name,domain,sso_provider) VALUES($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING', [adminOrgId, 'E2E Admin Organization', 'example.test', 'e2e']);
    await db('INSERT INTO org_memberships(user_id,org_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [adminUserId, adminOrgId, ROLES.OWNER]);
    const session = await createSessionToken({ id: adminUserId, email: adminEmail, name: 'E2E Platform Admin' }, { id: adminOrgId, name: 'E2E Admin Organization' }, ROLES.OWNER, 1);
    adminBearer = session.token;

    serverProcess = spawn(process.execPath, ['server.js'], {
        cwd: process.cwd(),
        env: { ...process.env, NODE_ENV: 'test', PORT: String(PORT) },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    await waitForReady();
}, 60000);

afterAll(async () => {
    if (serverProcess && !serverProcess.killed) {
        serverProcess.kill('SIGTERM');
        await new Promise(resolve => {
            const timer = setTimeout(resolve, 5000);
            serverProcess.once('exit', () => { clearTimeout(timer); resolve(); });
        });
    }
    await db('DELETE FROM sessions WHERE user_id=$1', [adminUserId]);
    await db('DELETE FROM org_memberships WHERE user_id=$1', [adminUserId]);
    await db('DELETE FROM users WHERE id=$1', [adminUserId]);
    await db('DELETE FROM organizations WHERE id=$1', [adminOrgId]);
}, 30000);

describe('Pilot customer lifecycle — real HTTP + PostgreSQL', () => {
    it('creates, activates, re-authenticates, expires and revokes a pilot credential', async () => {
        const email = `pilot-${randomUUID()}@example.test`;
        const companyName = `E2E Pilot ${randomUUID().slice(0, 8)}`;

        const createResponse = await fetch(`${BASE_URL}/api/admin/pilots`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${adminBearer}` },
            body: JSON.stringify({ companyName, email, days: 30 })
        });
        expect(createResponse.status).toBe(201);
        const created = await createResponse.json();
        expect(created.code).toMatch(/^CFP-[A-Z0-9]{4}(?:-[A-Z0-9]{4}){4}$/);
        expect(created.invitation.status).toBe('PENDING');

        const first = await pilotLogin(created.code, email, 'Real Pilot User');
        expect(first.response.status).toBe(200);
        expect(first.body.firstActivation).toBe(true);
        expect(first.body.org.name).toBe(companyName);
        expect(first.body.role).toBe(ROLES.OWNER);

        const serviceBefore = await fetch(`${BASE_URL}/api/tenants`, { headers: { cookie: first.cookie } });
        expect(serviceBefore.status).toBe(200);

        const second = await pilotLogin(created.code, email, 'Ignored On Repeat Login');
        expect(second.response.status).toBe(200);
        expect(second.body.firstActivation).toBe(false);
        expect(second.body.user.id).toBe(first.body.user.id);
        expect(second.body.org.id).toBe(first.body.org.id);

        await db("UPDATE pilot_invitations SET expires_at=CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE id=$1", [created.invitation.id]);
        const expired = await pilotLogin(created.code, email, 'Real Pilot User');
        expect(expired.response.status).toBe(410);
        expect(expired.body.error).toBe('PILOT_INVITATION_UNAVAILABLE');

        const revokeEmail = `revoke-${randomUUID()}@example.test`;
        const revokeCreate = await fetch(`${BASE_URL}/api/admin/pilots`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${adminBearer}` },
            body: JSON.stringify({ companyName: 'E2E Revoke Pilot', email: revokeEmail, days: 30 })
        });
        expect(revokeCreate.status).toBe(201);
        const revokeInvitation = await revokeCreate.json();
        const revokeFirst = await pilotLogin(revokeInvitation.code, revokeEmail, 'Revocable Pilot');
        expect(revokeFirst.response.status).toBe(200);

        const revokeResponse = await fetch(`${BASE_URL}/api/admin/pilots/${encodeURIComponent(revokeInvitation.invitation.id)}/revoke`, {
            method: 'POST',
            headers: { authorization: `Bearer ${adminBearer}` }
        });
        expect(revokeResponse.status).toBe(200);
        const revoked = await revokeResponse.json();
        expect(revoked.invitation.status).toBe('REVOKED');

        const revokedLogin = await pilotLogin(revokeInvitation.code, revokeEmail, 'Revocable Pilot');
        expect(revokedLogin.response.status).toBe(410);
        expect(revokedLogin.body.error).toBe('PILOT_INVITATION_UNAVAILABLE');

        const serviceAfter = await fetch(`${BASE_URL}/api/tenants`, { headers: { cookie: revokeFirst.cookie } });
        expect(serviceAfter.status).toBe(402);
    }, 90000);
});
