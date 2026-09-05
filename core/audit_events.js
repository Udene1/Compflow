import crypto from 'crypto';
import pool from './db.js';
import { log } from './logger.js';

// Sensitive keys that must NEVER appear in audit event metadata
const SENSITIVE_KEY_PATTERNS = [
    /secret/i,
    /password/i,
    /token/i,
    /credential/i,
    /key/i,
    /verifier/i,
    /auth/i,
    /signature/i
];

/**
 * Strips any potential secret keys or huge payloads from audit metadata
 */
function sanitizeMetadata(metadata = {}) {
    if (!metadata || typeof metadata !== 'object') return {};
    const clean = {};
    for (const [k, v] of Object.entries(metadata)) {
        if (SENSITIVE_KEY_PATTERNS.some(pattern => pattern.test(k))) {
            continue; // Omit sensitive keys entirely
        }
        if (typeof v === 'string' && v.length > 500) {
            clean[k] = v.substring(0, 500) + '...[truncated]';
        } else if (typeof v === 'object' && v !== null) {
            // Shallow stringification or omit large nested objects
            const str = JSON.stringify(v);
            clean[k] = str.length > 500 ? '[complex_object]' : v;
        } else {
            clean[k] = v;
        }
    }
    return clean;
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
        log.error(`[AUDIT] Failed to record audit event ${eventType}:`, err.message);
        if (process.env.NODE_ENV === 'production') {
            throw err; // Fail-closed in production
        }
        return null;
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
