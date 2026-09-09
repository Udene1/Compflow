import { validateSessionToken, hasRole } from './auth.js';
import { getOrganizationEntitlement, evaluateEntitlement } from './access_control.js';

function parseCookies(cookieHeader) {
    const list = {};
    if (!cookieHeader) return list;
    for (const cookie of String(cookieHeader).split(';')) {
        const separator = cookie.indexOf('=');
        if (separator <= 0) continue;
        const name = cookie.slice(0, separator).trim();
        if (!name || name.length > 128) continue;
        const rawValue = cookie.slice(separator + 1).trim();
        try { list[name] = decodeURIComponent(rawValue); } catch { /* ignore malformed cookie */ }
    }
    return list;
}

function apiError(res, status, code, message, details = undefined) {
    const body = { error: code, code, message };
    if (details !== undefined) body.details = details;
    return res.status(status).json(body);
}

export function requireAuth(allowedRoles = []) {
    return async (req, res, next) => {
        const cookies = req.cookies || parseCookies(req.headers.cookie);
        const bearer = req.headers.authorization;
        const token = cookies.cf_session || (typeof bearer === 'string' && /^Bearer\s+[^\s]+$/i.test(bearer) ? bearer.replace(/^Bearer\s+/i, '') : null);

        if (!token) {
            return apiError(res, 401, 'AUTHENTICATION_REQUIRED', 'Authentication required. Please sign in or provide a session token.');
        }

        const { valid, user, error } = await validateSessionToken(token);
        if (!valid || !user) {
            return apiError(res, 401, 'INVALID_SESSION', error || 'Invalid session credentials.');
        }

        if (allowedRoles.length > 0 && !hasRole(user.role, allowedRoles)) {
            return apiError(res, 403, 'INSUFFICIENT_PERMISSIONS', 'Insufficient permissions.');
        }
        req.user = user;

        // Direct unit invocation has no Express application object. Real HTTP requests do.
        // Authentication/session endpoints remain usable when service access is locked.
        if (!req.app || req.baseUrl === '/api/auth') return next();

        const organizationId = user.orgId;
        if (!organizationId) return apiError(res, 403, 'ORGANIZATION_CONTEXT_REQUIRED', 'Organization context is required for this service request.');
        try {
            const entitlement = await getOrganizationEntitlement(organizationId);
            const decision = evaluateEntitlement(entitlement);
            if (!decision.allowed) {
                return apiError(res, 402, decision.reason, 'An active Compflow service entitlement is required to use the service.', {
                    allowed: false,
                    plan: entitlement?.plan || null,
                    status: entitlement?.status || 'NONE',
                    expiresAt: entitlement?.expires_at || null
                });
            }
            req.serviceEntitlement = entitlement;
            return next();
        } catch {
            // PostgreSQL is authoritative for entitlements. Never fail open when access
            // state cannot be determined.
            return apiError(res, 503, 'SERVICE_ENTITLEMENT_AUTHORITY_UNAVAILABLE', 'Service access could not be verified. Please try again.');
        }
    };
}

export function optionalAuth(req, res, next) {
    return (async () => {
        const cookies = req.cookies || parseCookies(req.headers.cookie);
        const bearer = req.headers.authorization;
        const token = cookies.cf_session || (typeof bearer === 'string' && /^Bearer\s+[^\s]+$/i.test(bearer) ? bearer.replace(/^Bearer\s+/i, '') : null);
        if (token) {
            const { valid, user } = await validateSessionToken(token);
            if (valid && user) req.user = user;
        }
        next();
    })().catch(next);
}
