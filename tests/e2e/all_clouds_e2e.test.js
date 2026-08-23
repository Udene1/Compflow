import { describe, it, expect, vi } from 'vitest';
import { runScan } from '../../core/scanner.js';
import { runRemediation } from '../../core/remediator.js';
import { evaluateWithGemini } from '../../core/gemini.js';
import { generatePdfReport, generateReport } from '../../core/reporter.js';

describe('Multi-Cloud End-to-End (E2E) Compliance Pipeline', () => {

    it('should complete E2E audit lifecycle for DigitalOcean', async () => {
        const finding = {
            name: 'prod-droplet-db',
            type: 'DO Droplet',
            severity: 'warning',
            issue: 'backups disabled',
            control: 'CC7.2',
            technicalId: 'DO_DROPLET_BACKUP'
        };

        const ai = await evaluateWithGemini(finding);
        expect(ai).toBeDefined();
        expect(ai.action).toMatch(/AUTO_FIX|ESCALATE/);

        const rem = await runRemediation('digitalocean', { apiToken: 'fake' }, finding.type, finding.name, finding.issue, false);
        expect(rem.success).toBe(true);

        const pdf = await generatePdfReport('DO Corp', [finding]);
        expect(pdf).toBeDefined();
        expect(pdf.length).toBeGreaterThan(500);
    });

    it('should complete E2E audit lifecycle for Hetzner', async () => {
        const finding = {
            name: 'node-01',
            type: 'Hetzner Server',
            severity: 'critical',
            issue: 'backups disabled',
            control: 'CC7.2',
            technicalId: 'HETZNER_BACKUP'
        };

        const ai = await evaluateWithGemini(finding);
        expect(ai.action).toBeDefined();

        const rem = await runRemediation('hetzner', { apiToken: 'fake' }, finding.type, finding.name, finding.issue, false);
        expect(rem.success).toBe(true);
    });

    it('should complete E2E audit lifecycle for GCP', async () => {
        const finding = {
            name: 'vault-bucket',
            type: 'GCP Bucket',
            severity: 'warning',
            issue: 'Uniform bucket-level access disabled',
            control: 'CC6.1',
            technicalId: 'GCS_UBR'
        };

        const ai = await evaluateWithGemini(finding);
        expect(ai.action).toBeDefined();

        const rem = await runRemediation('gcp', { projectId: 'p', apiToken: JSON.stringify({ project_id: 'p' }) }, finding.type, finding.name, finding.issue, true);
        expect(rem.success).toBe(true);
    });

    it('should complete E2E audit lifecycle for AWS', async () => {
        const finding = {
            name: 'public-data',
            type: 'S3 Bucket',
            severity: 'critical',
            issue: 'Public access enabled',
            control: 'CC6.6',
            technicalId: 'S3_PUBLIC'
        };

        const ai = await evaluateWithGemini(finding);
        expect(ai.action).toBeDefined();

        const rem = await runRemediation('aws', { accessKeyId: 'k', secretAccessKey: 's' }, finding.type, finding.name, finding.issue, true);
        expect(rem.success).toBe(true);
    });

    it('should complete E2E audit lifecycle for Azure', async () => {
        const finding = {
            name: 'app-portal',
            type: 'Azure App Service',
            severity: 'critical',
            issue: 'App Service does not enforce HTTPS-only traffic',
            control: 'CC6.6',
            technicalId: 'AZ_APP_HTTPS'
        };

        const ai = await evaluateWithGemini(finding);
        expect(ai.action).toBeDefined();

        const rem = await runRemediation('azure', { tenantId: 't', accessKeyId: 'c', secretAccessKey: 's', projectId: 'p' }, finding.type, finding.name, finding.issue, true);
        expect(rem.success).toBe(true);

        const html = generateReport('Azure Corp', [finding], { resolved: 1, escalated: 0, details: [{ name: finding.name, status: 'fixed', issue: finding.issue }] });
        expect(html).toContain('ComplianceFlow');
    });

});
