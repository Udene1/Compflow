import { describe, it, expect } from 'vitest';
import { FINDING_CODES, resolveFindingCode } from '../../core/finding_codes.js';
import { runRemediation as runAWSRemediation } from '../../core/providers/aws_remediator.js';
import { runRemediation as runAzureRemediation } from '../../core/providers/azure_remediator.js';
import { runRemediation } from '../../core/remediator.js';

describe('Phase 2 — Remediation Robustness Engine', () => {

    // ─── 1. Structured Finding Code Resolution ──────────────────────────────
    describe('Structured Finding Codes Resolver', () => {
        it('should resolve S3 findings to canonical codes', () => {
            expect(resolveFindingCode('S3 Bucket', 'Public access enabled')).toBe(FINDING_CODES.S3_PUBLIC_ACCESS);
            expect(resolveFindingCode('S3 Bucket', 'Versioning not enabled')).toBe(FINDING_CODES.S3_VERSIONING_DISABLED);
            expect(resolveFindingCode('S3 Bucket', 'Default encryption disabled')).toBe(FINDING_CODES.S3_ENCRYPTION_DISABLED);
            expect(resolveFindingCode('S3 Bucket', 'Lifecycle configuration missing')).toBe(FINDING_CODES.S3_LIFECYCLE_MISSING);
        });

        it('should resolve Network / SG findings to canonical codes', () => {
            expect(resolveFindingCode('Security Group', 'SSH port 22 open to 0.0.0.0/0')).toBe(FINDING_CODES.SG_OPEN_SSH_WORLD);
            expect(resolveFindingCode('Security Group', 'RDP port 3389 open')).toBe(FINDING_CODES.SG_OPEN_RDP_WORLD);
            expect(resolveFindingCode('Security Group', 'HTTP port 80 open to all')).toBe(FINDING_CODES.SG_OPEN_HTTP_WORLD);
            expect(resolveFindingCode('Security Group', 'Unused Security Group')).toBe(FINDING_CODES.SG_UNUSED);
        });

        it('should resolve Azure findings to canonical codes', () => {
            expect(resolveFindingCode('Azure Storage', 'Public blob access allowed')).toBe(FINDING_CODES.AZURE_STORAGE_PUBLIC_BLOB);
            expect(resolveFindingCode('Azure Storage', 'HTTP traffic allowed')).toBe(FINDING_CODES.AZURE_STORAGE_HTTP_ALLOWED);
            expect(resolveFindingCode('Azure App Service', 'HTTPS not enforced')).toBe(FINDING_CODES.AZURE_APPSERVICE_HTTP_ALLOWED);
            expect(resolveFindingCode('Azure KeyVault', 'Soft delete disabled')).toBe(FINDING_CODES.AZURE_KEYVAULT_NO_SOFTDELETE);
        });

        it('should preserve technicalId if already a valid FINDING_CODE', () => {
            expect(resolveFindingCode('Any', 'Any', FINDING_CODES.DYNAMODB_PITR_DISABLED)).toBe(FINDING_CODES.DYNAMODB_PITR_DISABLED);
        });
    });

    // ─── 2. AWS Dry-Run & Blast Radius Safety ────────────────────────────────
    describe('AWS Remediation Blast Radius & Dry-Run Safety', () => {
        const mockCredentials = {
            accessKeyId: 'AKIA_MOCK_TEST_KEY',
            secretAccessKey: 'MOCK_SECRET_ACCESS_KEY',
            region: 'us-east-1'
        };

        it('should execute dry-run for S3 Public Access with structured response', async () => {
            const res = await runAWSRemediation('aws', mockCredentials, 'S3 Bucket', 'my-corp-bucket', 'Public access enabled', true);
            expect(res.success).toBe(true);
            expect(res.dryRun).toBe(true);
            expect(res.findingCode).toBe(FINDING_CODES.S3_PUBLIC_ACCESS);
            expect(res.action).toBe('AUTO_REMEDIATE');
            expect(res.targetResource).toBe('my-corp-bucket');
        });

        it('should execute dry-run for SG open SSH with structured response', async () => {
            const res = await runAWSRemediation('aws', mockCredentials, 'Security Group', 'launch-wizard-1', 'port 22 open to 0.0.0.0/0', true);
            expect(res.success).toBe(true);
            expect(res.dryRun).toBe(true);
            expect(res.findingCode).toBe(FINDING_CODES.SG_OPEN_SSH_WORLD);
            expect(res.action).toBe('AUTO_REMEDIATE');
        });

        it('should block and escalate risky un-whitelisted findings to ADVISORY', async () => {
            const res = await runAWSRemediation(
                'aws', 
                mockCredentials, 
                'IAM Account', 
                'root', 
                'Delete all root credentials and rotate primary billing IAM keys', 
                false
            );
            expect(res.success).toBe(true);
            expect(res.advisory).toBe(true);
            expect(res.message).toContain('ADVISORY');
            expect(res.message).toContain('manual approval');
        });
    });

    // ─── 3. Azure Dry-Run & Blast Radius Safety ──────────────────────────────
    describe('Azure Remediation Blast Radius & Dry-Run Safety', () => {
        const mockAzureCredentials = {
            tenantId: 'mock-tenant-id',
            accessKeyId: 'mock-client-id',
            secretAccessKey: 'mock-client-secret',
            projectId: 'mock-sub-id'
        };

        it('should execute dry-run for Azure App Service HTTPS enforcement', async () => {
            const res = await runAzureRemediation('azure', mockAzureCredentials, 'Azure App Service', 'api-backend-app', 'HTTPS disabled', true);
            expect(res.success).toBe(true);
            expect(res.dryRun).toBe(true);
            expect(res.findingCode).toBe(FINDING_CODES.AZURE_APPSERVICE_HTTP_ALLOWED);
        });

        it('should execute dry-run for Azure Storage public access', async () => {
            const res = await runAzureRemediation('azure', mockAzureCredentials, 'Azure Storage', 'corpdatafiles', 'public access enabled', true);
            expect(res.success).toBe(true);
            expect(res.dryRun).toBe(true);
            expect(res.findingCode).toBe(FINDING_CODES.AZURE_STORAGE_PUBLIC_BLOB);
        });

        it('should execute dry-run for Azure NSG open inbound rule revocation', async () => {
            const res = await runAzureRemediation('azure', mockAzureCredentials, 'Azure NSG', 'app-subnet-nsg', 'port 22 open to internet', true);
            expect(res.success).toBe(true);
            expect(res.dryRun).toBe(true);
            expect(res.findingCode).toBe(FINDING_CODES.SG_OPEN_SSH_WORLD);
        });

        it('should execute dry-run for Azure SQL public network access disablement', async () => {
            const res = await runAzureRemediation('azure', mockAzureCredentials, 'Azure SQL', 'sql-primary-server', 'public network access enabled', true);
            expect(res.success).toBe(true);
            expect(res.dryRun).toBe(true);
            expect(res.findingCode).toBe(FINDING_CODES.AZURE_SQL_PUBLIC_ACCESS);
        });

        it('should block risky Azure actions outside whitelist and return ADVISORY', async () => {
            const res = await runAzureRemediation('azure', mockAzureCredentials, 'Azure SQL', 'production-db-server', 'Drop and destroy database instance', false);
            expect(res.success).toBe(true);
            expect(res.advisory).toBe(true);
            expect(res.message).toContain('ADVISORY');
        });
    });

    // ─── 4. Central Multi-Cloud Remediation Dispatcher ───────────────────────
    describe('Central Multi-Cloud Dispatcher', () => {
        it('should route AWS requests with options and return structured payload', async () => {
            const res = await runRemediation(
                'aws', 
                { accessKeyId: 'KEY', secretAccessKey: 'SEC' },
                'KMS Key',
                'arn:aws:kms:us-east-1:1111:key/1234',
                'Rotation disabled',
                true,
                { findingCode: FINDING_CODES.KMS_KEY_ROTATION_DISABLED }
            );

            expect(res.success).toBe(true);
            expect(res.dryRun).toBe(true);
            expect(res.findingCode).toBe(FINDING_CODES.KMS_KEY_ROTATION_DISABLED);
        });
    });
});
