import crypto from 'crypto';
import pool from './db.js';
import { log } from './logger.js';

// Sensitive keys that must NEVER appear in audit event metadata.
const SENSITIVE_KEY_PATTERNS = [
    /secret/i,
    /password/i,
    /token/i,
    /credential/i,
    /private[_-]?key/i,
    /api[_-]?key/i,
    /verifier/i,
    /authorization/i,
    /signature/i
];

const MAX_STRING_LENGTH = 500;
const MAX_DEPTH = 5;

function isSensitiveKey(key) {
    return SENSITIVE_KEY_PATTERNS.some(pattern => pattern.test(key));
}

/**
 * Recursively sanitizes audit metadata before it is persisted.
 * Audit records must remain useful without becoming a secret-storage channel.
 */
function sanitizeValue(value, depth = 0) {
    if (depth > MAX_DEPTH) return '[max_depth]';

    if (typeof value === 'string') {
        return value.length > MAX_STRING_LENGTH
            ? `${value.substring(0, MAX_STRING_LENGTH)}...[truncated]`
            : value;
    }

    if (value === null || typeof value === 'number' || typeof value === 'boolean') {
        return value;
    }

    if (Array.isArray(value)) {
        return value.slice(0, 100).map(item => sanitizeValue(item, depth + 1));
    }

    if (typeof value === 'object') {
        const clean = {};
        for (const [key, nestedValue] of Object.entries(value)) {
            if (isSensitiveKey(key)) continue;
            clean[key] = sanitizeValue(nestedValue, depth + 1);
        }
        return clean;
    }

    return undefined;
}

function sanitizeMetadata(metadata = {}) {
    if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return {};
    return sanitizeValue(metadata);
}

/**
 * Records a lean, structured audit event in PostgreSQL.
 *
 * @param {string} orgId - Organization ID
 * @param {string} actorUserId - Actor user ID (or 'system')
 * @param {string} eventType - e.g., 'user_authenticated', 'cloud_connection_verified'
 * @param {string} resourceType - e.g., 'user', 'organization', 'cloud_connection'
 * @param {string} resourceId - Identifier of resource affected
 * @param {Object} metadata - Lean metadata (WHO/WHAT/WHEN/WHERE/TO WHAT/RESULT)
 * @param {Object} [req] - Express request object for IP and user-agent
 */
export async function recordAuditEvent(orgId, actorUserId, eventType, resourceType = null, resourceId = null, metadata = {}, req = null) {
    const id = 'evt_' + crypto.randomUUID();
    const cleanMetadata = sanitizeMetadata(metadata);

    let ipAddress = null;
    let userAgent = null;

    if (req) {
        ipAddress = req.ip || req.headers?.['x-forwarded-for'] || req.socket?.remoteAddress || null;
        userAgent = req.headers?.['user-agent'] || null;
    }

    const query = `
        INSERT INTO audit_events (
            id, organization_id, actor_user_id, event_type,
            resource_type, resource_id, metadata, ip_address, user_agent, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
        RETURNING *;
    `;

    try {
        const result = await pool.query(query, [
            id,
            orgId || null,
            actorUserId || 'system',
            eventType,
            resourceType || null,
            resourceId || null,
            JSON.stringify(cleanMetadata),
            ipAddress,
            userAgent
        ]);
        log.info(`[AUDIT] ${eventType} by ${actorUserId || 'system'} on ${resourceType || 'system'}:${resourceId || 'global'}`);
        return result.rows?.[0] || { id, event_type: eventType };
    } catch (err) {
        // Audit persistence is security-relevant. Never turn a failed durable write
        // into a successful-looking operation, regardless of environment.
        log.error(`[AUDIT] Failed to record audit event ${eventType}:`, err.message);
        throw err;
    }
}

/**
 * Retrieves recent audit events for an organization.
 */
export async function getAuditEvents(orgId, limit = 50) {
    const query = `
        SELECT * FROM audit_events
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT $2;
    `;
    const res = await pool.query(query, [orgId, limit]);
    return res.rows || [];
}
