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
    const mockUser = {
        id: 'usr_test_123',
        email: 'alice@acme-corp.com',
        name: 'Alice Smith',
        avatarUrl: 'https://example.com/avatar.png'
    };

    const mockOrg = {
        id: 'org_acme',
        name: 'Acme Security',
        domain: 'acme-corp.com'
    };

    it('generates a valid, cryptographically signed session token', () => {
        const session = createSessionToken(mockUser, mockOrg, ROLES.ADMIN, 7);

        expect(session).toBeDefined();
        expect(typeof session.token).toBe('string');
        expect(session.payload.email).toBe('alice@acme-corp.com');
        expect(session.payload.role).toBe(ROLES.ADMIN);
        expect(session.payload.orgId).toBe('org_acme');

        // Validation test
        const result = validateSessionToken(session.token);
        expect(result.valid).toBe(true);
        expect(result.user.email).toBe('alice@acme-corp.com');
        expect(result.user.role).toBe(ROLES.ADMIN);
    });

    it('rejects tampered or forged session tokens', () => {
        const session = createSessionToken(mockUser, mockOrg, ROLES.ENGINEER, 7);
        
        // Tamper with payload by changing role to OWNER without updating signature
        const decoded = JSON.parse(Buffer.from(session.token, 'base64url').toString('utf8'));
        decoded.payload.role = ROLES.OWNER;
        const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString('base64url');

        const result = validateSessionToken(tamperedToken);
        expect(result.valid).toBe(false);
        expect(result.error).toContain('Invalid or forged session token signature');
    });

    it('rejects expired session tokens', () => {
        // Create an expired session (0 days)
        const session = createSessionToken(mockUser, mockOrg, ROLES.ENGINEER, -1);
        const result = validateSessionToken(session.token);

        expect(result.valid).toBe(false);
        expect(result.error).toContain('expired');
    });
});

describe('Auth Engine — Role-Based Access Control (RBAC)', () => {
    it('enforces role hierarchy correctly', () => {
        // OWNER satisfies all roles
        expect(hasRole(ROLES.OWNER, [ROLES.OWNER])).toBe(true);
        expect(hasRole(ROLES.OWNER, [ROLES.ADMIN])).toBe(true);
        expect(hasRole(ROLES.OWNER, [ROLES.ENGINEER])).toBe(true);
        expect(hasRole(ROLES.OWNER, [ROLES.AUDITOR])).toBe(true);
        expect(hasRole(ROLES.OWNER, [ROLES.VIEWER])).toBe(true);

        // ADMIN satisfies ENGINEER and VIEWER
        expect(hasRole(ROLES.ADMIN, [ROLES.ADMIN])).toBe(true);
        expect(hasRole(ROLES.ADMIN, [ROLES.ENGINEER])).toBe(true);
        expect(hasRole(ROLES.ADMIN, [ROLES.VIEWER])).toBe(true);
        expect(hasRole(ROLES.ADMIN, [ROLES.OWNER])).toBe(false);

        // ENGINEER cannot access ADMIN-only routes
        expect(hasRole(ROLES.ENGINEER, [ROLES.ENGINEER])).toBe(true);
        expect(hasRole(ROLES.ENGINEER, [ROLES.ADMIN])).toBe(false);

        // AUDITOR can access AUDITOR and VIEWER
        expect(hasRole(ROLES.AUDITOR, [ROLES.AUDITOR])).toBe(true);
        expect(hasRole(ROLES.AUDITOR, [ROLES.ENGINEER])).toBe(false);

        // VIEWER cannot perform ENGINEER or ADMIN actions
        expect(hasRole(ROLES.VIEWER, [ROLES.VIEWER])).toBe(true);
        expect(hasRole(ROLES.VIEWER, [ROLES.ENGINEER])).toBe(false);
        expect(hasRole(ROLES.VIEWER, [ROLES.ADMIN])).toBe(false);
    });
});

describe('Auth Engine — User Provisioning from OAuth Profile', () => {
    it('provisions user and organization from corporate email', async () => {
        const profile = {
            email: 'bob@enterprise-fintech.io',
            name: 'Bob Jenkins',
            picture: 'https://lh3.googleusercontent.com/a/mock'
        };

        const result = await upsertUserFromOAuth(profile, 'google');

        expect(result.user.email).toBe('bob@enterprise-fintech.io');
        expect(result.user.name).toBe('Bob Jenkins');
        expect(result.org.domain).toBe('enterprise-fintech.io');
        expect(result.role).toBe(ROLES.OWNER); // first user is OWNER
    });
});

describe('Auth Guard Middleware', () => {
    const mockUser = { id: 'usr_1', email: 'secops@org.com', name: 'SecOps' };
    const mockOrg = { id: 'org_1', name: 'Org 1' };

    it('allows requests with valid session cookie and sufficient role', () => {
        const session = createSessionToken(mockUser, mockOrg, ROLES.ADMIN, 7);
        const middleware = requireAuth([ROLES.ENGINEER]); // ADMIN >= ENGINEER

        const req = {
            headers: { cookie: `cf_session=${session.token}` }
        };
        let nextCalled = false;
        const res = {
            status: () => ({ json: () => {} })
        };
        const next = () => { nextCalled = true; };

        middleware(req, res, next);
        expect(nextCalled).toBe(true);
        expect(req.user).toBeDefined();
        expect(req.user.email).toBe('secops@org.com');
    });

    it('blocks unauthenticated requests with 401', () => {
        const middleware = requireAuth([ROLES.ENGINEER]);
        const req = { headers: {} };
        let statusCode = 0;
        let responseJson = {};

        const res = {
            status: (code) => {
                statusCode = code;
                return { json: (data) => { responseJson = data; } };
            }
        };

        middleware(req, res, () => {});
        expect(statusCode).toBe(401);
        expect(responseJson.error).toBe('Unauthorized');
    });

    it('blocks insufficient roles with 403 Forbidden', () => {
        const session = createSessionToken(mockUser, mockOrg, ROLES.VIEWER, 7);
        const middleware = requireAuth([ROLES.ADMIN]); // VIEWER < ADMIN

        const req = {
            headers: { cookie: `cf_session=${session.token}` }
        };
        let statusCode = 0;
        let responseJson = {};

        const res = {
            status: (code) => {
                statusCode = code;
                return { json: (data) => { responseJson = data; } };
            }
        };

        middleware(req, res, () => {});
        expect(statusCode).toBe(403);
        expect(responseJson.error).toBe('Forbidden');
    });
});
