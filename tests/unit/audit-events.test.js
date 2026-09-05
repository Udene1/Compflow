import { describe, it, expect } from 'vitest';
import { recordAuditEvent, getAuditEvents } from '../../core/audit_events.js';

describe('Lean PostgreSQL Audit Engine (Amendment 16)', () => {
    const orgId = 'org_audit_test_101';
    const actorId = 'usr_auditor_101';

    it('records a lean audit event containing WHO, WHAT, WHEN, WHERE, TO WHAT, RESULT', async () => {
        const mockReq = {
            ip: '192.168.1.50',
            headers: { 'user-agent': 'CompflowSecOps/2.0' }
        };

        const event = await recordAuditEvent(
            orgId,
            actorId,
            'cloud_connection_verified',
            'cloud_connection',
            'conn_aws_prod_1',
            { provider: 'AWS', region: 'us-east-1', result: 'success' },
            mockReq
        );

        expect(event).toBeDefined();
        expect(event.organization_id).toBe(orgId);
        expect(event.actor_user_id).toBe(actorId);
        expect(event.event_type).toBe('cloud_connection_verified');
        expect(event.resource_type).toBe('cloud_connection');
        expect(event.resource_id).toBe('conn_aws_prod_1');
        expect(event.ip_address).toBe('192.168.1.50');
        expect(event.user_agent).toBe('CompflowSecOps/2.0');
        expect(event.metadata.result).toBe('success');
    });

    it('strictly sanitizes and omits sensitive keys (secrets, tokens, passwords, keys) from metadata', async () => {
        const dangerousMetadata = {
            result: 'success',
            provider: 'AWS',
            secretKey: 'VERY_SECRET_KEY_NEVER_LOG',
            clientSecret: 'SECRET_OAUTH_KEY',
            accessToken: 'BEARER_TOKEN_VALUE',
            password: 'SUPER_SECRET_PASSWORD',
            codeVerifier: 'PKCE_SECRET_VERIFIER'
        };

        const event = await recordAuditEvent(
            orgId,
            actorId,
            'secret_accessed',
            'secret',
            'conn_123',
            dangerousMetadata
        );

        expect(event).toBeDefined();
        expect(event.metadata.result).toBe('success');
        expect(event.metadata.provider).toBe('AWS');

        // Verify none of the sensitive values or keys were preserved
        expect(event.metadata.secretKey).toBeUndefined();
        expect(event.metadata.clientSecret).toBeUndefined();
        expect(event.metadata.accessToken).toBeUndefined();
        expect(event.metadata.password).toBeUndefined();
        expect(event.metadata.codeVerifier).toBeUndefined();
    });

    it('retrieves recorded audit events for an organization', async () => {
        const events = await getAuditEvents(orgId, 10);
        expect(Array.isArray(events)).toBe(true);
        expect(events.length).toBeGreaterThanOrEqual(1);
    });
});
