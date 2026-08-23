import { describe, it, expect } from 'vitest';
import { evaluateCustomPolicies, BUILT_IN_POLICY_TEMPLATES } from '../../core/policy_engine.js';

describe('Custom Governance Policy Rules Engine', () => {

    it('should expose built-in policy templates', () => {
        expect(BUILT_IN_POLICY_TEMPLATES.ALLOWED_REGIONS).toBeDefined();
        expect(BUILT_IN_POLICY_TEMPLATES.REQUIRED_TAGS).toBeDefined();
        expect(BUILT_IN_POLICY_TEMPLATES.PORT_WHITELIST).toBeDefined();
    });

    it('should flag resources deployed in disallowed regions', () => {
        const mockResources = [
            { name: 'compliant-vm', type: 'Azure VM', region: 'eastus', severity: 'pass' },
            { name: 'non-compliant-vm', type: 'Azure VM', region: 'ap-southeast-1', severity: 'pass' }
        ];

        const customPolicies = {
            allowedRegions: ['eastus', 'westus', 'centralus'],
            regionSeverity: 'critical'
        };

        const violations = evaluateCustomPolicies(mockResources, customPolicies);
        expect(violations.length).toBe(1);
        expect(violations[0].name).toBe('non-compliant-vm');
        expect(violations[0].technicalId).toBe('POLICY_UNAUTHORIZED_REGION');
        expect(violations[0].severity).toBe('critical');
    });

    it('should flag resources missing required organizational tags', () => {
        const mockResources = [
            {
                name: 'tagged-bucket',
                type: 'S3 Bucket',
                region: 'us-east-1',
                tags: { Environment: 'production', Owner: 'SecOps', DataClassification: 'Confidential' }
            },
            {
                name: 'untagged-bucket',
                type: 'S3 Bucket',
                region: 'us-east-1',
                tags: { Environment: 'production' }
            }
        ];

        const customPolicies = {
            requiredTags: ['Environment', 'Owner', 'DataClassification']
        };

        const violations = evaluateCustomPolicies(mockResources, customPolicies);
        expect(violations.length).toBe(1);
        expect(violations[0].name).toBe('untagged-bucket');
        expect(violations[0].technicalId).toBe('POLICY_MISSING_TAGS');
        expect(violations[0].issue).toContain('Owner');
        expect(violations[0].issue).toContain('DataClassification');
    });

    it('should flag public ports not present in the allowed port whitelist', () => {
        const mockResources = [
            {
                name: 'open-ssh-nsg',
                type: 'Azure NSG',
                region: 'eastus',
                severity: 'warning',
                issue: 'NSG permits inbound traffic on port 22'
            },
            {
                name: 'open-https-nsg',
                type: 'Azure NSG',
                region: 'eastus',
                severity: 'pass',
                issue: 'NSG permits inbound traffic on port 443'
            }
        ];

        const customPolicies = {
            allowedInboundPorts: [80, 443]
        };

        const violations = evaluateCustomPolicies(mockResources, customPolicies);
        expect(violations.length).toBe(1);
        expect(violations[0].name).toBe('open-ssh-nsg');
        expect(violations[0].technicalId).toBe('POLICY_DISALLOWED_PORT');
        expect(violations[0].issue).toContain('port "22"');
    });

});
