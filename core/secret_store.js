import crypto from 'crypto';
import pool from './db.js';
import { recordAuditEvent } from './audit_events.js';
import { log } from './logger.js';

// Derive or load master encryption key
const getSecretStoreKey = () => {
    const rawKey = process.env.SECRET_STORE_KEY;
    if (!rawKey) {
        if (process.env.NODE_ENV === 'production') {
            throw new Error('FATAL: SECRET_STORE_KEY environment variable is required in production.');
        }
        // Dev fallback: deterministic 32-byte key for local test/dev only
        return crypto.createHash('sha256').update('COMPFLOW_DEV_SECRET_STORE_KEY_2026').digest();
    }
    // If provided as 32-byte hex string or arbitrary passphrase, hash to 32 bytes
    if (rawKey.length === 64 && /^[0-9a-fA-F]+$/.test(rawKey)) {
        return Buffer.from(rawKey, 'hex');
    }
    return crypto.createHash('sha256').update(rawKey).digest();
};

export class SecretStore {
    constructor(keyProvider = getSecretStoreKey) {
        this.keyProvider = keyProvider;
    }

    /**
     * Encrypts plain object/string secret data using AES-256-GCM.
     */
    _encrypt(data) {
        const key = this.keyProvider();
        const iv = crypto.randomBytes(12); // 96-bit IV for GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        
        const text = typeof data === 'string' ? data : JSON.stringify(data);
        const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();

        // Package encrypted payload with auth tag
        const combined = Buffer.concat([encrypted, tag]);
        return { encryptedData: combined, iv };
    }

    /**
     * Decrypts combined payload + tag using AES-256-GCM.
     */
    _decrypt(combined, iv) {
        const key = this.keyProvider();
        const tag = combined.subarray(combined.length - 16);
        const encrypted = combined.subarray(0, combined.length - 16);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
        try {
            return JSON.parse(decrypted);
        } catch {
            return decrypted;
        }
    }

    /**
     * Stores encrypted credentials for an organization's cloud connection.
     */
    async saveSecret(orgId, connectionId, secretData, createdBy = 'system') {
        if (!orgId || !connectionId || !secretData) {
            throw new Error('SecretStore.saveSecret: orgId, connectionId, and secretData are required.');
        }

        try {
            const { encryptedData, iv } = this._encrypt(secretData);
            const secretId = 'sec_' + crypto.randomUUID();

            const query = `
                INSERT INTO secrets (id, org_id, connection_id, encrypted_data, iv, version, created_by)
                VALUES ($1, $2, $3, $4, $5, 1, $6)
                RETURNING id, org_id, connection_id, version, created_at;
            `;

            const res = await pool.query(query, [secretId, orgId, connectionId, encryptedData, iv, createdBy]);

            log.info(`[SECRET_STORE] Secret saved for org ${orgId}, connection ${connectionId}`);
            return {
                id: res.rows?.[0]?.id || secretId,
                connectionId,
                orgId,
                version: 1
            };
        } catch (err) {
            log.error(`[SECRET_STORE] Failed to save secret: ${err.message}`);
            throw err;
        }
    }

    /**
     * Decrypts and retrieves credentials, recording an access audit event.
     * Never logs or exposes credentials in audit records.
     */
    async getSecret(orgId, connectionId, purpose = 'scan', actorUserId = 'system', req = null) {
        if (!orgId || !connectionId) {
            throw new Error('SecretStore.getSecret: orgId and connectionId are required.');
        }

        try {
            const query = `
                SELECT id, encrypted_data, iv, version 
                FROM secrets 
                WHERE org_id = $1 AND connection_id = $2;
            `;
            const res = await pool.query(query, [orgId, connectionId]);

            if (!res.rows || res.rows.length === 0) {
                return null;
            }

            const row = res.rows[0];
            const rawEncrypted = Buffer.isBuffer(row.encrypted_data) ? row.encrypted_data : Buffer.from(row.encrypted_data);
            const rawIv = Buffer.isBuffer(row.iv) ? row.iv : Buffer.from(row.iv);

            const secretData = this._decrypt(rawEncrypted, rawIv);

            // Touch last_accessed_at timestamp
            await pool.query('UPDATE secrets SET last_accessed_at = CURRENT_TIMESTAMP WHERE id = $1;', [row.id]).catch(() => {});

            // Record secret_accessed audit event (WITHOUT the secret!)
            await recordAuditEvent(
                orgId,
                actorUserId,
                'secret_accessed',
                'secret',
                connectionId,
                { purpose, result: 'success', version: row.version },
                req
            ).catch(e => log.warn(`[SECRET_STORE] Audit record warning: ${e.message}`));

            return secretData;
        } catch (err) {
            log.error(`[SECRET_STORE] Failed to retrieve secret: ${err.message}`);
            if (process.env.NODE_ENV === 'production') {
                throw err;
            }
            return null;
        }
    }

    /**
     * Deletes stored secret for a connection.
     */
    async deleteSecret(orgId, connectionId, actorUserId = 'system', req = null) {
        const res = await pool.query(
            'DELETE FROM secrets WHERE org_id = $1 AND connection_id = $2 RETURNING id;',
            [orgId, connectionId]
        );

        await recordAuditEvent(
            orgId,
            actorUserId,
            'secret_deleted',
            'secret',
            connectionId,
            { result: 'success' },
            req
        ).catch(() => {});

        return res.rowCount > 0;
    }

    /**
     * Rotates stored secret with a new version.
     */
    async rotateSecret(orgId, connectionId, newSecretData, rotatedBy = 'system', req = null) {
        const { encryptedData, iv } = this._encrypt(newSecretData);

        const query = `
            UPDATE secrets 
            SET encrypted_data = $1, iv = $2, version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE org_id = $3 AND connection_id = $4
            RETURNING id, version;
        `;
        const res = await pool.query(query, [encryptedData, iv, orgId, connectionId]);

        await recordAuditEvent(
            orgId,
            rotatedBy,
            'secret_rotated',
            'secret',
            connectionId,
            { result: 'success', newVersion: res.rows?.[0]?.version },
            req
        ).catch(() => {});

        return res.rows?.[0] || null;
    }
}

export const defaultSecretStore = new SecretStore();
export default defaultSecretStore;
