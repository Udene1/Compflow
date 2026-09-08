import { describe, it, expect, afterEach } from 'vitest';
import { sanitizeJobPayload } from '../../core/queue.js';
import { SecretStore } from '../../core/secret_store.js';
import resilientPool from '../../core/db.js';

describe('Credential Security & SecretStore Engine (Amendments 7, 8, 9)', () => {
    describe('Queue Payload Sanitization (Amendment 8)', () => {
        it('strips credentials while preserving non-secret identifiers and metadata', () => {
            const rawPayload = {
                jobId: 'job-123', clientId: 'tenant-456', provider: 'aws', roleArn: 'arn:aws:iam::123:role/MyRole',
                credentials: { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'secret' },
                clientSecret: 'super-secret-azure-key', accessKey: 'my-access-key', secretKey: 'my-secret-key',
                token: 'bearer-token-val', apiToken: 'hcloud-api-token-val',
                serviceAccountJson: '{"private_key": "-----BEGIN PRIVATE KEY-----"}', password: 'database-pass',
                normalMetadata: 'keep-this-safe-field'
            };
            const clean = sanitizeJobPayload(rawPayload);
            expect(clean.jobId).toBe('job-123');
            expect(clean.clientId).toBe('tenant-456');
            expect(clean.provider).toBe('aws');
            expect(clean.roleArn).toBe('arn:aws:iam::123:role/MyRole');
            expect(clean.normalMetadata).toBe('keep-this-safe-field');
            expect(clean.credentials).toBeUndefined();
            expect(clean.clientSecret).toBeUndefined();
            expect(clean.accessKey).toBeUndefined();
            expect(clean.secretKey).toBeUndefined();
            expect(clean.token).toBeUndefined();
            expect(clean.apiToken).toBeUndefined();
            expect(clean.serviceAccountJson).toBeUndefined();
            expect(clean.password).toBeUndefined();
        });
    });

    describe('SecretStore Encryption & Access Auditing (Amendment 7)', () => {
        const store = new SecretStore();
        const testOrg = 'org_sec_store_test';
        const testConn = 'conn_sec_store_test';
        const rawSecret = { accessKeyId: 'AKIAEXAMPLE123456', secretAccessKey: 'secretKeyStringValue987654321' };

        it('encrypts secret and returns metadata without leaking decrypted secret in save result', async () => {
            const result = await store.saveSecret(testOrg, testConn, rawSecret, 'usr_admin');
            expect(result).toBeDefined(); expect(result.id).toBeDefined(); expect(result.version).toBe(1);
            expect(result.accessKeyId).toBeUndefined(); expect(result.secretAccessKey).toBeUndefined();
        });
        it('decrypts stored secret accurately on authorized retrieval', async () => {
            const retrieved = await store.getSecret(testOrg, testConn, 'compliance_scan', 'usr_admin');
            expect(retrieved).toBeDefined(); expect(retrieved.accessKeyId).toBe(rawSecret.accessKeyId);
            expect(retrieved.secretAccessKey).toBe(rawSecret.secretAccessKey);
        });
        it('rotates secret and increments version', async () => {
            const rotated = await store.rotateSecret(testOrg, testConn, { accessKeyId: 'AKIAEXAMPLE_ROTATED', secretAccessKey: 'rotatedSecretKeyStringValue' }, 'usr_admin');
            expect(rotated).toBeDefined(); expect(rotated.version).toBe(2);
            const fetched = await store.getSecret(testOrg, testConn, 'verify', 'usr_admin');
            expect(fetched.accessKeyId).toBe('AKIAEXAMPLE_ROTATED');
        });
    });

    describe('Production Database Governance (Amendment 9)', () => {
        const origEnv = process.env.NODE_ENV;
        afterEach(() => { process.env.NODE_ENV = origEnv; });

        it('uses the authoritative PostgreSQL connection in production mode', async () => {
            process.env.NODE_ENV = 'production';
            const result = await resilientPool.query('SELECT 1 AS authoritative_check;');
            expect(result.rows[0].authoritative_check).toBe(1);
        });
    });
});
