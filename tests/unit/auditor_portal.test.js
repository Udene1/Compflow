import { describe, it, expect } from 'vitest';
import { 
    generateAuditorToken, 
    validateAuditorToken, 
    generateAuditorEvidencePackage, 
    verifyAuditorPackage,
    computeSha256
} from '../../core/auditor_portal.js';

describe('SOC2 Third-Party Auditor Evidence Portal', () => {

    const mockTenantId = 'tenant-acme-corp-01';
    const mockAuditorEmail = 'lead.auditor@schellmancpa.com';

    it('should generate a valid, cryptographically signed auditor access token', () => {
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

    it('should reject forged or tampered auditor access tokens', () => {
        const tokenResult = generateAuditorToken(mockTenantId, mockAuditorEmail, 24);
        
        // Tamper with payload by replacing tenantId in encoded string
        const decoded = JSON.parse(Buffer.from(tokenResult.token, 'base64url').toString('utf8'));
        decoded.payload.tenantId = 'hacked-tenant-id';
        const forgedToken = Buffer.from(JSON.stringify(decoded)).toString('base64url');

        const validation = validateAuditorToken(forgedToken);
        expect(validation.valid).toBe(false);
        expect(validation.error).toContain('Invalid or forged');
    });

    it('should compile an evidence bundle with SHA-256 fingerprints and multi-framework control proofs', async () => {
        const mockResources = [
            {
                name: 'prod-secrets-vault',
                type: 'Azure Key Vault',
                region: 'eastus',
                severity: 'pass',
                issue: null,
                controls: { soc2: ['CC6.1'], iso27001: ['A.9.1.1'], hipaa: ['§164.312(a)(1)'] }
            },
            {
                name: 'app-ingress-nsg',
                type: 'Azure NSG',
                region: 'eastus',
                severity: 'critical',
                issue: 'NSG rule allows public SSH (port 22) access',
                controls: { soc2: ['CC6.6'], iso27001: ['A.9.1.2'] }
            }
        ];

        const auditLogs = [
            { timestamp: new Date().toISOString(), action: 'SCAN_COMPLETE', details: 'Full scan evaluated 2 assets' }
        ];

        const evidencePackage = await generateAuditorEvidencePackage('Acme Corp', mockResources, auditLogs, {
            auditorName: 'Lead Auditor Jane Doe',
            auditorFirm: 'Schellman & Company, LLC'
        });

        expect(evidencePackage.packageMetadata).toBeDefined();
        expect(evidencePackage.packageMetadata.digitalSignature).toBeDefined();
        expect(evidencePackage.packageMetadata.totalAssetsEvaluated).toBe(2);
        expect(evidencePackage.packageMetadata.totalDeficiencies).toBe(1);

        // Check manifest files
        expect(evidencePackage.files['evidence_manifest.json']).toHaveLength(2);
        expect(evidencePackage.files['evidence_manifest.json'][0].sha256Fingerprint).toBeDefined();
        expect(evidencePackage.files['control_proof_soc2.json']).toBeDefined();
        expect(evidencePackage.files['control_proof_iso27001.json']).toBeDefined();
        expect(evidencePackage.files['control_proof_hipaa.json']).toBeDefined();
    });

    it('should cryptographically verify untampered packages and detect modifications', async () => {
        const mockResources = [
            { name: 's3-audit-data', type: 'S3 Bucket', region: 'us-east-1', severity: 'pass' }
        ];

        const originalPackage = await generateAuditorEvidencePackage('Secure Corp', mockResources, []);
        
        // 1. Verify original package
        const validResult = verifyAuditorPackage(originalPackage);
        expect(validResult.verified).toBe(true);
        expect(validResult.message).toContain('Cryptographic proof verified');

        // 2. Modify manifest content (tamper attempt)
        const tamperedPackage = JSON.parse(JSON.stringify(originalPackage));
        tamperedPackage.files['evidence_manifest.json'][0].status = 'MODIFIED_BY_ATTACKER';

        const tamperedResult = verifyAuditorPackage(tamperedPackage);
        expect(tamperedResult.verified).toBe(false);
        expect(tamperedResult.reason).toContain('checksum mismatch');
    });

});
