import { validateSessionToken, hasRole } from './auth.js';

/**
 * Helper to parse cookie string from HTTP headers if cookie-parser is absent.
 */
function parseCookies(cookieHeader) {
    const list = {};
    if (!cookieHeader) return list;

    cookieHeader.split(';').forEach(cookie => {
        let [name, ...rest] = cookie.split('=');
        name = name?.trim();
        if (!name) return;
        const value = rest.join('=').trim();
        list[name] = decodeURIComponent(value);
    });

    return list;
}

/**
 * Express Middleware to require an authenticated session and enforce RBAC roles.
 * 
 * @param {Array<string>} allowedRoles - Optional list of required roles (e.g., ['ADMIN', 'ENGINEER'])
 */
export function requireAuth(allowedRoles = []) {
    return (req, res, next) => {
        const cookies = req.cookies || parseCookies(req.headers.cookie);
        const token = cookies.cf_session || 
                      req.headers.authorization?.replace(/^Bearer\s+/i, '') ||
                      req.query?.auth_token;

        if (!token) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Authentication required. Please sign in via Google, GitHub, or provide a session token.'
            });
        }

        const { valid, user, error } = validateSessionToken(token);

        if (!valid || !user) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: error || 'Invalid session credentials.'
            });
        }

        // Enforce Role Hierarchy
        if (allowedRoles.length > 0 && !hasRole(user.role, allowedRoles)) {
            return res.status(403).json({
                error: 'Forbidden',
                message: `Your role (${user.role}) lacks required permissions. Required: [${allowedRoles.join(', ')}]`
            });
        }

        // Attach user context to request
        req.user = user;
        next();
    };
}

/**
 * Optional authentication middleware: populates req.user if valid token present, but does not block.
 */
export function optionalAuth(req, res, next) {
    const cookies = req.cookies || parseCookies(req.headers.cookie);
    const token = cookies.cf_session || 
                  req.headers.authorization?.replace(/^Bearer\s+/i, '') ||
                  req.query?.auth_token;

    if (token) {
        const { valid, user } = validateSessionToken(token);
        if (valid && user) {
            req.user = user;
        }
    }
    next();
}
