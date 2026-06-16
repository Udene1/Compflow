import { describe, it, expect } from 'vitest';
import { enrichFinding, generateComplianceMatrix } from '../../core/compliance_mapper.js';

describe('Compliance Mapper - Intelligence Logic', () => {
    
    it('should correctly enrich a finding with multi-framework mappings', () => {
        const finding = {
            name: 'test-bucket',
            type: 'S3 Bucket',
            severity: 'critical',
            issue: 'Public access enabled'
        };

        const enriched = enrichFinding(finding);
        
        expect(enriched.framework_mappings).toBeDefined();
        expect(enriched.framework_mappings.soc2.control).toBe('CC6.1');
        expect(enriched.framework_mappings.gdpr.control).toBe('Art. 32');
        expect(enriched.evidence_hash).toBeDefined();
    });

    it('should detect legal conflicts between GDPR and HIPAA timelines', () => {
        const finding = {
            name: 'pii-leak',
            type: 'S3 Bucket',
            severity: 'critical',
            issue: 'Public access enabled'
        };

        const enriched = enrichFinding(finding);
        
        expect(enriched.requires_legal_review).toBe(true);
        expect(enriched.legal_review_reason).toContain('GDPR (72h) vs HIPAA (60 days)');
    });

    it('should generate a valid compliance matrix for reporting', () => {
        const findings = [
            {
                name: 'bucket-01',
                issue: 'Public access enabled',
                framework_mappings: {
                    soc2: { control: 'CC6.1', status: 'gap' },
                    gdpr: { article: 'Art. 32', status: 'gap' }
                }
            }
        ];

        const matrix = generateComplianceMatrix(findings);
        
        expect(matrix.headers).toContain('SOC2 Type II');
        expect(matrix.headers).toContain('GDPR');
        expect(matrix.rows[0][0]).toBe('bucket-01');
    });

    it('should handle N/A cases gracefully', () => {
        const finding = {
            name: 'tagging-issue',
            type: 'S3 Bucket',
            severity: 'warning',
            issue: 'Versioning not enabled'
        };

        const enriched = enrichFinding(finding);
        
        // GDPR doesn't strictly have a versioning control in our map
        expect(enriched.framework_mappings.gdpr.status).toBe('not_applicable');
    });
});
