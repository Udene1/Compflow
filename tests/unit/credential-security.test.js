import { describe, it, expect, afterEach } from 'vitest';
import { sanitizeJobPayload } from '../../core/queue.js';
import { SecretStore, defaultSecretStore } from '../../core/secret_store.js';
import resilientPool from '../../core/db.js';

describe('Credential Security & SecretStore Engine (Amendments 7, 8, 9)', () => {
    describe('Queue Payload Sanitization (Amendment 8)', () => {
        it('strips all credentials, secrets, tokens, and keys from queue payloads', () => {
            const rawPayload = {
                jobId: 'job-123',
                clientId: 'tenant-456',
                provider: 'aws',
                roleArn: 'arn:aws:iam::123:role/MyRole', // Allowed identifier
                credentials: { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
                clientSecret: 'super-secret-azure-key',
                accessKey: 'my-access-key',
                secretKey: 'my-secret-key',
                token: 'bearer-token-val',
                apiToken: 'hcloud-api-token-val',
                serviceAccountJson: '{"private_key": "-----BEGIN PRIVATE KEY-----"}',
                password: 'database-pass',
                normalMetadata: 'keep-this-safe-field'
            };

            const clean = sanitizeJobPayload(rawPayload);

            expect(clean.jobId).toBe('job-123');
            expect(clean.clientId).toBe('tenant-456');
            expect(clean.provider).toBe('aws');
            expect(clean.roleArn).toBe('arn:aws:iam::123:role/MyRole');
            expect(clean.normalMetadata).toBe('keep-this-safe-field');

            // Assert that every sensitive key is completely stripped
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
        const rawSecret = {
            accessKeyId: 'AKIAEXAMPLE123456',
            secretAccessKey: 'secretKeyStringValue987654321'
        };

        it('encrypts secret and returns metadata without leaking decrypted secret in save result', async () => {
            const result = await store.saveSecret(testOrg, testConn, rawSecret, 'usr_admin');
            expect(result).toBeDefined();
            expect(result.id).toBeDefined();
            expect(result.version).toBe(1);
            expect(result.accessKeyId).toBeUndefined();
            expect(result.secretAccessKey).toBeUndefined();
        });

        it('decrypts stored secret accurately on authorized retrieval', async () => {
            const retrieved = await store.getSecret(testOrg, testConn, 'compliance_scan', 'usr_admin');
            expect(retrieved).toBeDefined();
            expect(retrieved.accessKeyId).toBe(rawSecret.accessKeyId);
            expect(retrieved.secretAccessKey).toBe(rawSecret.secretAccessKey);
        });

        it('rotates secret and increments version', async () => {
            const newSecret = {
                accessKeyId: 'AKIAEXAMPLE_ROTATED',
                secretAccessKey: 'rotatedSecretKeyStringValue'
            };

            const rotated = await store.rotateSecret(testOrg, testConn, newSecret, 'usr_admin');
            expect(rotated).toBeDefined();
            expect(rotated.version).toBe(2);

            const fetched = await store.getSecret(testOrg, testConn, 'verify', 'usr_admin');
            expect(fetched.accessKeyId).toBe('AKIAEXAMPLE_ROTATED');
        });
    });

    describe('Production Fail-Closed Governance (Amendment 9)', () => {
        const origEnv = process.env.NODE_ENV;

        afterEach(() => {
            process.env.NODE_ENV = origEnv;
        });

        it('throws immediately in production if real PostgreSQL pool is unavailable (no silent memory fallback)', async () => {
            process.env.NODE_ENV = 'production';

            // resilientPool with no active real connection throws in production
            await expect(resilientPool.query('SELECT 1;'))
                .rejects
                .toThrow(/Production database/);
        });
    });
});
