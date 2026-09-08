import { describe, it, expect } from 'vitest';
import {
    generateAuditorToken,
    validateAuditorToken,
    generateAuditorEvidencePackage,
    verifyAuditorPackage,
    computeSha256,
    signPayload,
    verifySignature
} from '../../core/auditor_portal.js';

describe('SOC2 Third-Party Auditor Evidence Portal', () => {
    const mockTenantId = 'tenant-acme-corp-01';
    const mockAuditorEmail = 'lead.auditor@schellmancpa.com';

    it('generates a valid, cryptographically signed auditor access token', () => {
        const tokenResult = generateAuditorToken(mockTenantId, mockAuditorEmail, 48);
        expect(tokenResult).toBeDefined();
        expect(tokenResult.token).toBeDefined();
        expect(tokenResult.auditorEmail).toBe(mockAuditorEmail);
        expect(tokenResult.role).toBe('AUDITOR_READONLY');
        const validation = validateAuditorToken(tokenResult.token);
        expect(validation.valid).toBe(true);
        expect(validation.payload.tenantId).toBe(mockTenantId);
        expect(validation.payload.auditorEmail).toBe(mockAuditorEmail);
    });

    it('rejects forged or tampered auditor access tokens', () => {
        const tokenResult = generateAuditorToken(mockTenantId, mockAuditorEmail, 24);
        const decoded = JSON.parse(Buffer.from(tokenResult.token, 'base64url').toString('utf8'));
        decoded.payload.tenantId = 'hacked-tenant-id';
        const forgedToken = Buffer.from(JSON.stringify(decoded)).toString('base64url');
        const validation = validateAuditorToken(forgedToken);
        expect(validation.valid).toBe(false);
        expect(validation.error).toContain('Invalid or forged');
    });

    it('rejects invalid auditor token signatures without throwing on malformed signature lengths', () => {
        const payload = { tenantId: mockTenantId, auditorEmail: mockAuditorEmail };
        expect(verifySignature(payload, '')).toBe(false);
        expect(verifySignature(payload, '00')).toBe(false);
        expect(verifySignature(payload, 'not-hex')).toBe(false);
        const signature = signPayload(payload);
        expect(verifySignature(payload, signature)).toBe(true);
        expect(verifySignature({ ...payload, tenantId: 'other-tenant' }, signature)).toBe(false);
    });

    it('rejects invalid token expiry configuration', () => {
        expect(() => generateAuditorToken(mockTenantId, mockAuditorEmail, 0)).toThrow('AUDITOR_TOKEN_INPUT_INVALID');
        expect(() => generateAuditorToken(mockTenantId, mockAuditorEmail, 169)).toThrow('AUDITOR_TOKEN_INPUT_INVALID');
    });

    it('compiles an evidence bundle with SHA-256 fingerprints and multi-framework control proofs', async () => {
        const mockResources = [
            { name: 'prod-secrets-vault', type: 'Azure Key Vault', region: 'eastus', severity: 'pass', issue: null, controls: { soc2: ['CC6.1'], iso27001: ['A.9.1.1'], hipaa: ['§164.312(a)(1)'] } },
            { name: 'app-ingress-nsg', type: 'Azure NSG', region: 'eastus', severity: 'critical', issue: 'NSG rule allows public SSH (port 22) access', controls: { soc2: ['CC6.6'], iso27001: ['A.9.1.2'] } }
        ];
        const auditLogs = [{ timestamp: new Date().toISOString(), action: 'SCAN_COMPLETE', details: 'Full scan evaluated 2 assets' }];
        const evidencePackage = await generateAuditorEvidencePackage('Acme Corp', mockResources, auditLogs, { auditorName: 'Lead Auditor Jane Doe', auditorFirm: 'Schellman & Company, LLC' });
        expect(evidencePackage.packageMetadata).toBeDefined();
        expect(evidencePackage.packageMetadata.digitalSignature).toBeDefined();
        expect(evidencePackage.packageMetadata.totalAssetsEvaluated).toBe(2);
        expect(evidencePackage.packageMetadata.totalDeficiencies).toBe(1);
        expect(evidencePackage.files['evidence_manifest.json']).toHaveLength(2);
        expect(evidencePackage.files['evidence_manifest.json'][0].sha256Fingerprint).toBeDefined();
        expect(evidencePackage.files['control_proof_soc2.json']).toBeDefined();
        expect(evidencePackage.files['control_proof_iso27001.json']).toBeDefined();
        expect(evidencePackage.files['control_proof_hipaa.json']).toBeDefined();
    });

    it('cryptographically verifies untampered packages and detects modifications', async () => {
        const originalPackage = await generateAuditorEvidencePackage('Secure Corp', [{ name: 's3-audit-data', type: 'S3 Bucket', region: 'us-east-1', severity: 'pass' }], []);
        const validResult = verifyAuditorPackage(originalPackage);
        expect(validResult.verified).toBe(true);
        expect(validResult.message).toContain('Cryptographic proof verified');
        const tamperedPackage = JSON.parse(JSON.stringify(originalPackage));
        tamperedPackage.files['evidence_manifest.json'][0].status = 'MODIFIED_BY_ATTACKER';
        const tamperedResult = verifyAuditorPackage(tamperedPackage);
        expect(tamperedResult.verified).toBe(false);
        expect(tamperedResult.reason).toContain('checksum mismatch');
    });

    it('fails closed outside test mode when no production signing secret is configured', async () => {
        const previousNodeEnv = process.env.NODE_ENV;
        const previousSecret = process.env.AUDITOR_SIGNING_SECRET;
        delete process.env.AUDITOR_SIGNING_SECRET;
        process.env.NODE_ENV = 'production';
        try {
            expect(() => signPayload({ test: true })).toThrow('AUDITOR_SIGNING_SECRET_REQUIRED');
        } finally {
            if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
            else process.env.NODE_ENV = previousNodeEnv;
            if (previousSecret === undefined) delete process.env.AUDITOR_SIGNING_SECRET;
            else process.env.AUDITOR_SIGNING_SECRET = previousSecret;
        }
    });

    it('computes deterministic SHA-256 fingerprints', () => {
        expect(computeSha256({ a: 1 })).toBe(computeSha256({ a: 1 }));
        expect(computeSha256({ a: 1 })).not.toBe(computeSha256({ a: 2 }));
    });
});
