import { describe, it, expect } from 'vitest';
import { 
    createSessionToken, 
    validateSessionToken, 
    hasRole, 
    ROLES, 
    upsertUserFromOAuth, 
    signAuthPayload 
} from '../../core/auth.js';
import { requireAuth, optionalAuth } from '../../core/auth_guard.js';

describe('Auth Engine — Session & Token Management', () => {
    const mockUser = { id: 'usr_test_123', email: 'alice@acme-corp.com', name: 'Alice Smith', avatarUrl: 'https://example.com/avatar.png' };
    const mockOrg = { id: 'org_acme', name: 'Acme Security', domain: 'acme-corp.com' };
    it('generates a valid, cryptographically signed session token', async () => {
        const session = await createSessionToken(mockUser, mockOrg, ROLES.ADMIN, 7);
        expect(session).toBeDefined(); expect(typeof session.token).toBe('string');
        expect(session.payload.email).toBe('alice@acme-corp.com'); expect(session.payload.role).toBe(ROLES.ADMIN); expect(session.payload.orgId).toBe('org_acme');
        const result = await validateSessionToken(session.token); expect(result.valid).toBe(true); expect(result.user.email).toBe('alice@acme-corp.com'); expect(result.user.role).toBe(ROLES.ADMIN);
    });
    it('rejects tampered or forged session tokens', async () => {
        const session = await createSessionToken(mockUser, mockOrg, ROLES.ENGINEER, 7); const decoded = JSON.parse(Buffer.from(session.token, 'base64url').toString('utf8')); decoded.payload.role = ROLES.OWNER;
        const result = await validateSessionToken(Buffer.from(JSON.stringify(decoded)).toString('base64url')); expect(result.valid).toBe(false); expect(result.error).toContain('Invalid or forged session token signature');
    });
    it('rejects expired session tokens', async () => { const session = await createSessionToken(mockUser, mockOrg, ROLES.ENGINEER, -1); const result = await validateSessionToken(session.token); expect(result.valid).toBe(false); expect(result.error).toContain('expired'); });
});

describe('Auth Engine — Role-Based Access Control (RBAC)', () => {
    it('enforces role hierarchy correctly', () => {
        expect(hasRole(ROLES.OWNER, [ROLES.OWNER])).toBe(true); expect(hasRole(ROLES.OWNER, [ROLES.ADMIN])).toBe(true); expect(hasRole(ROLES.OWNER, [ROLES.ENGINEER])).toBe(true); expect(hasRole(ROLES.OWNER, [ROLES.AUDITOR])).toBe(true); expect(hasRole(ROLES.OWNER, [ROLES.VIEWER])).toBe(true);
        expect(hasRole(ROLES.ADMIN, [ROLES.ADMIN])).toBe(true); expect(hasRole(ROLES.ADMIN, [ROLES.ENGINEER])).toBe(true); expect(hasRole(ROLES.ADMIN, [ROLES.VIEWER])).toBe(true); expect(hasRole(ROLES.ADMIN, [ROLES.OWNER])).toBe(false);
        expect(hasRole(ROLES.ENGINEER, [ROLES.ENGINEER])).toBe(true); expect(hasRole(ROLES.ENGINEER, [ROLES.ADMIN])).toBe(false); expect(hasRole(ROLES.AUDITOR, [ROLES.AUDITOR])).toBe(true); expect(hasRole(ROLES.AUDITOR, [ROLES.ENGINEER])).toBe(false); expect(hasRole(ROLES.VIEWER, [ROLES.VIEWER])).toBe(true); expect(hasRole(ROLES.VIEWER, [ROLES.ENGINEER])).toBe(false); expect(hasRole(ROLES.VIEWER, [ROLES.ADMIN])).toBe(false);
    });
});

describe('Auth Engine — User Provisioning & Identity Model', () => {
    it('provisions user and organization from corporate email', async () => {
        const result = await upsertUserFromOAuth({ id: 'google-sub-bob-123', email: 'bob@enterprise-fintech.io', name: 'Bob Jenkins', picture: 'https://lh3.googleusercontent.com/a/mock' }, 'google', 'google-sub-bob-123');
        expect(result.user.email).toBe('bob@enterprise-fintech.io'); expect(result.user.name).toBe('Bob Jenkins'); expect(result.org.domain).toBe('enterprise-fintech.io'); expect(result.role).toBe(ROLES.OWNER);
    });
    it('recognizes existing identity on subsequent login preserving user ID (Amendment 4)', async () => {
        const result = await upsertUserFromOAuth({ id: 'google-sub-bob-123', email: 'bob@enterprise-fintech.io', name: 'Bob Jenkins Updated', picture: 'https://lh3.googleusercontent.com/a/mock' }, 'google', 'google-sub-bob-123');
        expect(result.user.email).toBe('bob@enterprise-fintech.io'); expect(result.user.id).toBeDefined();
    });
    it('rejects email collision from a different provider without auto-merging (Amendment 5)', async () => {
        await expect(upsertUserFromOAuth({ id: 'gh-45678', email: 'bob@enterprise-fintech.io', name: 'Bob GitHub' }, 'github', 'gh-45678')).rejects.toThrow('This email is already associated with a Compflow account');
    });
});

describe('Auth Guard Middleware', () => {
    const mockUser = { id: 'usr_1', email: 'secops@org.com', name: 'SecOps' }; const mockOrg = { id: 'org_1', name: 'Org 1' };
    it('allows requests with valid session cookie and sufficient role', async () => {
        const session = await createSessionToken(mockUser, mockOrg, ROLES.ADMIN, 7); const middleware = requireAuth([ROLES.ENGINEER]);
        const req = { headers: { cookie: `cf_session=${session.token}` } }; let nextCalled = false; const res = { status: () => ({ json: () => {} }) };
        await middleware(req, res, () => { nextCalled = true; }); expect(nextCalled).toBe(true); expect(req.user).toBeDefined(); expect(req.user.email).toBe('secops@org.com');
    });
    it('returns a stable authentication error code for unauthenticated requests', async () => {
        const middleware = requireAuth([ROLES.ENGINEER]); const req = { headers: {} }; let statusCode = 0; let responseJson = {};
        const res = { status: (code) => { statusCode = code; return { json: (data) => { responseJson = data; } }; } }; await middleware(req, res, () => {});
        expect(statusCode).toBe(401); expect(responseJson.code).toBe('AUTHENTICATION_REQUIRED'); expect(responseJson.error).toBe('Unauthorized'); expect(responseJson.message).toContain('Authentication required');
    });
    it('returns a stable authorization error code for insufficient roles', async () => {
        const session = await createSessionToken(mockUser, mockOrg, ROLES.VIEWER, 7); const middleware = requireAuth([ROLES.ADMIN]); const req = { headers: { cookie: `cf_session=${session.token}` } }; let statusCode = 0; let responseJson = {};
        const res = { status: (code) => { statusCode = code; return { json: (data) => { responseJson = data; } }; } }; await middleware(req, res, () => {});
        expect(statusCode).toBe(403); expect(responseJson.code).toBe('INSUFFICIENT_PERMISSIONS'); expect(responseJson.error).toBe('Forbidden'); expect(responseJson.message).toBe('Insufficient permissions.');
    });
});
