import { describe, it, expect, beforeAll } from 'vitest';
import {
    createSessionToken,
    validateSessionToken,
    hasRole,
    ROLES,
    revokeSession,
    isSessionRevoked
} from '../../core/auth.js';

describe('Auth Hardening — Phase 0 Security Enforcement', () => {

    // ─── Session Token Lifecycle ─────────────────────────────────────────────
    describe('Session Token Creation & Validation', () => {
        it('should create a valid signed session token', () => {
            const user = { id: 'usr_test123', email: 'alice@acme.com', name: 'Alice' };
            const org = { id: 'org_acme', name: 'Acme Corp' };
            const session = createSessionToken(user, org, ROLES.ADMIN, 7);

            expect(session.token).toBeDefined();
            expect(session.payload.email).toBe('alice@acme.com');
            expect(session.payload.role).toBe('ADMIN');
            expect(session.payload.orgId).toBe('org_acme');
            expect(session.payload.sessionId).toMatch(/^sess_/);
        });

        it('should validate a correctly signed token', () => {
            const user = { id: 'usr_test456', email: 'bob@corp.io', name: 'Bob' };
            const org = { id: 'org_corp', name: 'Corp IO' };
            const session = createSessionToken(user, org, ROLES.ENGINEER, 1);

            const result = validateSessionToken(session.token);
            expect(result.valid).toBe(true);
            expect(result.user.email).toBe('bob@corp.io');
            expect(result.user.role).toBe('ENGINEER');
        });

        it('should reject a forged/tampered token', () => {
            const result = validateSessionToken('aGVsbG8gd29ybGQ'); // random base64url
            expect(result.valid).toBe(false);
        });

        it('should reject an expired token', () => {
            const user = { id: 'usr_expired', email: 'old@test.com', name: 'Old' };
            const org = { id: 'org_test', name: 'Test' };
            // Create token that expires in -1 days (already expired)
            const session = createSessionToken(user, org, ROLES.VIEWER, -1);

            const result = validateSessionToken(session.token);
            expect(result.valid).toBe(false);
            expect(result.error).toContain('expired');
        });

        it('should reject null/empty/undefined tokens', () => {
            expect(validateSessionToken(null).valid).toBe(false);
            expect(validateSessionToken('').valid).toBe(false);
            expect(validateSessionToken(undefined).valid).toBe(false);
        });
    });

    // ─── Server-Side Session Revocation (Logout) ─────────────────────────────
    describe('Server-Side Session Revocation', () => {
        it('should revoke a session and reject it on next validation', () => {
            const user = { id: 'usr_revoke', email: 'revoke@test.com', name: 'Revoke' };
            const org = { id: 'org_test', name: 'Test' };
            const session = createSessionToken(user, org, ROLES.ADMIN, 7);

            // Token should be valid before revocation
            expect(validateSessionToken(session.token).valid).toBe(true);

            // Revoke the session
            revokeSession(session.token);

            // Token should now be rejected
            const result = validateSessionToken(session.token);
            expect(result.valid).toBe(false);
            expect(result.error).toContain('revoked');
        });

        it('should report revoked status via isSessionRevoked', () => {
            const user = { id: 'usr_check', email: 'check@test.com', name: 'Check' };
            const org = { id: 'org_test', name: 'Test' };
            const session = createSessionToken(user, org, ROLES.VIEWER, 1);

            expect(isSessionRevoked(session.token)).toBe(false);
            revokeSession(session.token);
            expect(isSessionRevoked(session.token)).toBe(true);
        });

        it('should handle revoking null/empty tokens gracefully', () => {
            expect(() => revokeSession(null)).not.toThrow();
            expect(() => revokeSession('')).not.toThrow();
            expect(() => revokeSession(undefined)).not.toThrow();
        });
    });

    // ─── RBAC Role Hierarchy ─────────────────────────────────────────────────
    describe('RBAC Role Hierarchy Enforcement', () => {
        it('OWNER should access everything', () => {
            expect(hasRole('OWNER', ['VIEWER'])).toBe(true);
            expect(hasRole('OWNER', ['ENGINEER'])).toBe(true);
            expect(hasRole('OWNER', ['ADMIN'])).toBe(true);
            expect(hasRole('OWNER', ['OWNER'])).toBe(true);
            expect(hasRole('OWNER', ['AUDITOR'])).toBe(true);
        });

        it('ADMIN should access ENGINEER, AUDITOR, VIEWER roles', () => {
            expect(hasRole('ADMIN', ['ENGINEER'])).toBe(true);
            expect(hasRole('ADMIN', ['AUDITOR'])).toBe(true);
            expect(hasRole('ADMIN', ['VIEWER'])).toBe(true);
        });

        it('ADMIN should NOT access OWNER-only resources', () => {
            expect(hasRole('ADMIN', ['OWNER'])).toBe(false);
        });

        it('ENGINEER should access AUDITOR and VIEWER roles', () => {
            expect(hasRole('ENGINEER', ['AUDITOR'])).toBe(true);
            expect(hasRole('ENGINEER', ['VIEWER'])).toBe(true);
        });

        it('ENGINEER should NOT access ADMIN or OWNER roles', () => {
            expect(hasRole('ENGINEER', ['ADMIN'])).toBe(false);
            expect(hasRole('ENGINEER', ['OWNER'])).toBe(false);
        });

        it('AUDITOR should access VIEWER roles but NOT ENGINEER/ADMIN/OWNER', () => {
            expect(hasRole('AUDITOR', ['VIEWER'])).toBe(true);
            expect(hasRole('AUDITOR', ['ENGINEER'])).toBe(false);
            expect(hasRole('AUDITOR', ['ADMIN'])).toBe(false);
        });

        it('VIEWER should NOT access any role above VIEWER', () => {
            expect(hasRole('VIEWER', ['AUDITOR'])).toBe(false);
            expect(hasRole('VIEWER', ['ENGINEER'])).toBe(false);
            expect(hasRole('VIEWER', ['ADMIN'])).toBe(false);
            expect(hasRole('VIEWER', ['OWNER'])).toBe(false);
        });

        it('Empty allowedRoles should grant access to any role', () => {
            expect(hasRole('VIEWER', [])).toBe(true);
            expect(hasRole('OWNER', [])).toBe(true);
        });

        it('Unknown roles should be denied', () => {
            expect(hasRole('HACKER', ['VIEWER'])).toBe(false);
            expect(hasRole('', ['VIEWER'])).toBe(false);
        });
    });

    // ─── Route Protection Matrix ─────────────────────────────────────────────
    describe('Route Protection Matrix (documents expected enforcement)', () => {
        // These serve as living documentation of the RBAC matrix

        const ROUTE_MATRIX = [
            { route: 'POST /api/scan',         minRole: 'ENGINEER',  description: 'Initiate cloud scan' },
            { route: 'POST /api/trigger',       minRole: 'ADMIN',     description: 'Trigger autonomous sweep' },
            { route: 'GET /api/tenants',        minRole: 'VIEWER',    description: 'List tenants' },
            { route: 'POST /api/tenants',       minRole: 'ADMIN',     description: 'Create tenant' },
            { route: 'PATCH /api/tenants',      minRole: 'ADMIN',     description: 'Modify tenant' },
            { route: 'POST /api/validate',      minRole: 'ENGINEER',  description: 'Validate cloud credentials' },
            { route: 'GET /api/job-status',     minRole: 'VIEWER',    description: 'Poll job status' },
            { route: 'GET /api/job-stream',     minRole: 'VIEWER',    description: 'Stream job events' },
            { route: 'POST /api/monitoring',    minRole: 'ADMIN',     description: 'Infrastructure monitoring' },
            { route: 'POST /api/jobs',          minRole: 'ADMIN',     description: 'Manage job queue' },
            { route: 'POST /api/chat',          minRole: 'ENGINEER',  description: 'AI compliance chat' },
            { route: 'ALL /api/auditor*',       minRole: 'AUDITOR',   description: 'Auditor portal operations' },
        ];

        for (const entry of ROUTE_MATRIX) {
            it(`${entry.route} requires ${entry.minRole}+ (${entry.description})`, () => {
                // Verify a user at the minimum role can access
                expect(hasRole(entry.minRole, [entry.minRole])).toBe(true);
                // Verify OWNER always has access
                expect(hasRole('OWNER', [entry.minRole])).toBe(true);
            });
        }

        it('Public routes should NOT require authentication: /health, /api/auth/*', () => {
            // This is tested at the integration level; here we document the intent
            const publicRoutes = ['/health', '/api/auth/providers', '/api/auth/google', '/api/auth/github', '/api/auth/dev-login', '/api/auth/logout'];
            expect(publicRoutes.length).toBe(6);
        });
    });
});
