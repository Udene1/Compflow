import pool from './db.js';

export const ENTITLEMENT_STATUS = Object.freeze({
    ACTIVE: 'ACTIVE',
    TRIAL: 'TRIAL',
    PILOT: 'PILOT',
    PAST_DUE: 'PAST_DUE',
    CANCELED: 'CANCELED'
});

export const PLAN = Object.freeze({
    PILOT: 'pilot',
    TRIAL: 'trial',
    STANDARD: 'standard',
    ENTERPRISE: 'enterprise'
});

const ACTIVE_STATUSES = new Set([ENTITLEMENT_STATUS.ACTIVE, ENTITLEMENT_STATUS.TRIAL, ENTITLEMENT_STATUS.PILOT]);

export function evaluateEntitlement(entitlement, now = new Date()) {
    if (!entitlement) return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_REQUIRED', entitlement: null });
    const status = String(entitlement.status || '').toUpperCase();
    if (!ACTIVE_STATUSES.has(status)) return Object.freeze({ allowed: false, reason: `SERVICE_ENTITLEMENT_${status || 'INVALID'}`, entitlement });
    if (entitlement.expires_at && new Date(entitlement.expires_at).getTime() <= now.getTime()) {
        return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_EXPIRED', entitlement });
    }
    return Object.freeze({ allowed: true, reason: null, entitlement });
}

export async function getOrganizationEntitlement(organizationId) {
    if (!organizationId) return null;
    const result = await pool.query(
        `SELECT organization_id, plan, status, source, starts_at, expires_at, metadata, updated_at
         FROM organization_entitlements WHERE organization_id = $1 LIMIT 1`,
        [organizationId]
    );
    return result.rows[0] || null;
}

export async function grantOrganizationEntitlement({ organizationId, plan = PLAN.PILOT, status = ENTITLEMENT_STATUS.PILOT, source = 'pilot_code', expiresAt = null, metadata = {} }) {
    if (!organizationId) throw new Error('ORGANIZATION_CONTEXT_REQUIRED');
    const allowedPlans = new Set(Object.values(PLAN));
    const allowedStatuses = new Set(Object.values(ENTITLEMENT_STATUS));
    if (!allowedPlans.has(plan)) throw new Error('ENTITLEMENT_PLAN_INVALID');
    if (!allowedStatuses.has(status)) throw new Error('ENTITLEMENT_STATUS_INVALID');
    const result = await pool.query(
        `INSERT INTO organization_entitlements (organization_id, plan, status, source, starts_at, expires_at, metadata, updated_at)
         VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5, $6::jsonb, CURRENT_TIMESTAMP)
         ON CONFLICT (organization_id) DO UPDATE SET
           plan = EXCLUDED.plan, status = EXCLUDED.status, source = EXCLUDED.source,
           starts_at = CASE WHEN organization_entitlements.status IN ('CANCELED','PAST_DUE') THEN CURRENT_TIMESTAMP ELSE organization_entitlements.starts_at END,
           expires_at = EXCLUDED.expires_at, metadata = EXCLUDED.metadata, updated_at = CURRENT_TIMESTAMP
         RETURNING organization_id, plan, status, source, starts_at, expires_at, metadata, updated_at`,
        [organizationId, plan, status, source, expiresAt, JSON.stringify(metadata)]
    );
    return result.rows[0];
}

export function requireServiceEntitlement() {
    return async (req, res, next) => {
        const organizationId = req.user?.orgId || req.authContext?.orgId;
        if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
        try {
            const entitlement = await getOrganizationEntitlement(organizationId);
            const decision = evaluateEntitlement(entitlement);
            if (!decision.allowed) {
                return res.status(402).json({
                    error: decision.reason,
                    message: 'An active Compflow service entitlement is required to use cloud scanning, evidence, remediation, and execution services.',
                    access: { allowed: false, plan: entitlement?.plan || null, status: entitlement?.status || 'NONE', expiresAt: entitlement?.expires_at || null }
                });
            }
            req.serviceEntitlement = entitlement;
            return next();
        } catch (error) {
            // Entitlement authority is PostgreSQL. Never allow service use when it cannot be checked.
            return res.status(503).json({ error: 'SERVICE_ENTITLEMENT_AUTHORITY_UNAVAILABLE' });
        }
    };
}
