import { describe, it, expect } from 'vitest';
import path from 'path';
import { 
    discoverIaCFiles, 
    analyzeFile, 
    analyzeDirectory, 
    generateMarkdownReport 
} from '../../scripts/iac-compliance-check.js';

describe('IaC Compliance Gate Static Analyzer', () => {
    const fixturesDir = path.resolve(__dirname, '../fixtures');

    describe('File Discovery', () => {
        it('should discover all IaC fixture files (.tf, .yaml, etc.)', () => {
            const files = discoverIaCFiles(fixturesDir);
            expect(files.length).toBeGreaterThanOrEqual(5);
            
            const fileNames = files.map(f => path.basename(f));
            expect(fileNames).toContain('bad_s3.tf');
            expect(fileNames).toContain('bad_iam.tf');
            expect(fileNames).toContain('bad_security_group.tf');
            expect(fileNames).toContain('good_infra.tf');
            expect(fileNames).toContain('bad_template.yaml');
        });

        it('should ignore non-IaC files or excluded directories', () => {
            const files = discoverIaCFiles(path.resolve(__dirname, '../../'));
            const fileNames = files.map(f => path.basename(f));
            expect(fileNames).not.toContain('package.json');
            expect(fileNames).not.toContain('package-lock.json');
        });
    });

    describe('Security Rule Evaluations', () => {
        it('should detect public access, unencrypted storage, and region violations in bad_s3.tf', () => {
            const badS3Path = path.join(fixturesDir, 'bad_s3.tf');
            const findings = analyzeFile(badS3Path);

            expect(findings.length).toBeGreaterThan(0);
            
            // Check for public access finding
            const publicAccessFinding = findings.find(f => f.ruleId === 'TF-SEC-001');
            expect(publicAccessFinding).toBeDefined();
            expect(publicAccessFinding.severity).toBe('critical');

            // Check for unencrypted storage finding
            const encryptionFinding = findings.find(f => f.ruleId === 'TF-SEC-002');
            expect(encryptionFinding).toBeDefined();
            expect(encryptionFinding.severity).toBe('critical');

            // Check for region violation finding (ap-northeast-1 not in default approved list)
            const regionFinding = findings.find(f => f.ruleId === 'TF-GOV-001');
            expect(regionFinding).toBeDefined();
            expect(regionFinding.severity).toBe('warning');
        });

        it('should detect wildcard IAM policies and open principals in bad_iam.tf', () => {
            const badIamPath = path.join(fixturesDir, 'bad_iam.tf');
            const findings = analyzeFile(badIamPath);

            const wildcardFindings = findings.filter(f => f.ruleId === 'TF-IAM-001');
            expect(wildcardFindings.length).toBeGreaterThanOrEqual(2);
            expect(wildcardFindings.some(f => f.severity === 'critical')).toBe(true);
        });

        it('should detect open ports (0.0.0.0/0) in security groups in bad_security_group.tf', () => {
            const badSgPath = path.join(fixturesDir, 'bad_security_group.tf');
            const findings = analyzeFile(badSgPath);

            const portFindings = findings.filter(f => f.ruleId === 'TF-SEC-003');
            expect(portFindings.length).toBeGreaterThanOrEqual(1);
            expect(portFindings.every(f => f.severity === 'critical')).toBe(true);
        });

        it('should detect violations in CloudFormation templates in bad_template.yaml', () => {
            const badCfnPath = path.join(fixturesDir, 'bad_template.yaml');
            const findings = analyzeFile(badCfnPath);

            expect(findings.length).toBeGreaterThan(0);
            const ruleIds = findings.map(f => f.ruleId);
            expect(ruleIds).toContain('TF-SEC-003'); // 0.0.0.0/0
            expect(ruleIds).toContain('TF-IAM-001'); // Action: '*'
        });

        it('should produce ZERO critical/high findings for good_infra.tf', () => {
            const goodInfraPath = path.join(fixturesDir, 'good_infra.tf');
            const findings = analyzeFile(goodInfraPath);

            const criticalOrHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
            expect(criticalOrHigh.length).toBe(0);
        });
    });

    describe('Directory Analysis & Markdown Reporting', () => {
        it('should accurately aggregate directory scan metrics', () => {
            const summary = analyzeDirectory(fixturesDir);

            expect(summary.totalFiles).toBeGreaterThanOrEqual(5);
            expect(summary.totalFindings).toBeGreaterThan(0);
            expect(summary.critical).toBeGreaterThan(0);
            expect(summary.hasCritical).toBe(true);
        });

        it('should generate properly formatted Markdown report with blocker banner', () => {
            const summary = analyzeDirectory(fixturesDir);
            const report = generateMarkdownReport(summary);

            expect(report).toContain('ComplianceFlow IaC Compliance Gate');
            expect(report).toContain('BLOCKED');
            expect(report).toContain('Critical');
            expect(report).toContain('TF-SEC-001');
            expect(report).toContain('TF-IAM-001');
        });

        it('should generate a passing Markdown report when no critical findings exist', () => {
            const mockCleanSummary = {
                totalFiles: 3,
                totalFindings: 0,
                critical: 0,
                high: 0,
                warning: 0,
                hasCritical: false,
                files: ['infra/main.tf'],
                findings: []
            };

            const report = generateMarkdownReport(mockCleanSummary);
            expect(report).toContain('PASSED');
            expect(report).toContain('No compliance issues found');
        });
    });
});
