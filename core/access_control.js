import pool from './db.js';

export const ENTITLEMENT_STATUS = Object.freeze({ ACTIVE: 'ACTIVE', TRIAL: 'TRIAL', PILOT: 'PILOT', PAST_DUE: 'PAST_DUE', CANCELED: 'CANCELED' });
export const PLAN = Object.freeze({ PILOT: 'pilot', TRIAL: 'trial', STANDARD: 'standard', ENTERPRISE: 'enterprise' });
const ACTIVE_STATUSES = new Set([ENTITLEMENT_STATUS.ACTIVE, ENTITLEMENT_STATUS.TRIAL, ENTITLEMENT_STATUS.PILOT]);
const KNOWN_PLANS = new Set(Object.values(PLAN));

export function evaluateEntitlement(entitlement, now = new Date()) {
    if (!entitlement) return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_REQUIRED', entitlement: null });
    const status = String(entitlement.status || '').toUpperCase();
    const plan = String(entitlement.plan || '').toLowerCase();
    if (!KNOWN_PLANS.has(plan)) return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_INVALID_PLAN', entitlement });
    if (!ACTIVE_STATUSES.has(status)) return Object.freeze({ allowed: false, reason: `SERVICE_ENTITLEMENT_${status || 'INVALID'}`, entitlement });
    const currentTime = now instanceof Date ? now.getTime() : new Date(now).getTime();
    if (!Number.isFinite(currentTime)) return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_CLOCK_INVALID', entitlement });
    if (entitlement.starts_at) {
        const startsAt = new Date(entitlement.starts_at).getTime();
        if (!Number.isFinite(startsAt)) return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_INVALID_START', entitlement });
        if (startsAt > currentTime) return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_NOT_STARTED', entitlement });
    }
    if (entitlement.expires_at) {
        const expiresAt = new Date(entitlement.expires_at).getTime();
        if (!Number.isFinite(expiresAt)) return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_INVALID_EXPIRY', entitlement });
        if (expiresAt <= currentTime) return Object.freeze({ allowed: false, reason: 'SERVICE_ENTITLEMENT_EXPIRED', entitlement });
    }
    return Object.freeze({ allowed: true, reason: null, entitlement });
}

export async function getOrganizationEntitlement(organizationId) {
    if (!organizationId) return null;
    const result = await pool.query(`SELECT organization_id, plan, status, source, starts_at, expires_at, metadata, updated_at FROM organization_entitlements WHERE organization_id = $1 LIMIT 1`, [organizationId]);
    return result.rows[0] || null;
}

export async function grantOrganizationEntitlement({ organizationId, plan = PLAN.PILOT, status = ENTITLEMENT_STATUS.PILOT, source = 'pilot_invitation', expiresAt = null, metadata = {} }) {
    if (!organizationId) throw new Error('ORGANIZATION_CONTEXT_REQUIRED');
    if (!Object.values(PLAN).includes(plan)) throw new Error('ENTITLEMENT_PLAN_INVALID');
    if (!Object.values(ENTITLEMENT_STATUS).includes(status)) throw new Error('ENTITLEMENT_STATUS_INVALID');
    const result = await pool.query(
        `INSERT INTO organization_entitlements (organization_id, plan, status, source, starts_at, expires_at, metadata, updated_at)
         VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP,$5,$6::jsonb,CURRENT_TIMESTAMP)
         ON CONFLICT (organization_id) DO UPDATE SET plan=EXCLUDED.plan,status=EXCLUDED.status,source=EXCLUDED.source,starts_at=CASE WHEN organization_entitlements.status IN ('CANCELED','PAST_DUE') THEN CURRENT_TIMESTAMP ELSE organization_entitlements.starts_at END,expires_at=EXCLUDED.expires_at,metadata=EXCLUDED.metadata,updated_at=CURRENT_TIMESTAMP
         RETURNING organization_id,plan,status,source,starts_at,expires_at,metadata,updated_at`,
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
            if (!decision.allowed) return res.status(402).json({ error: decision.reason, message: 'An active Compflow service entitlement is required to use cloud scanning, evidence, remediation, and execution services.', access: { allowed: false, plan: entitlement?.plan || null, status: entitlement?.status || 'NONE', expiresAt: entitlement?.expires_at || null } });
            req.serviceEntitlement = entitlement;
            return next();
        } catch { return res.status(503).json({ error: 'SERVICE_ENTITLEMENT_AUTHORITY_UNAVAILABLE' }); }
    };
}
