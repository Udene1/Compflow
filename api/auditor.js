import { generateAuditorToken, validateAuditorToken, generateAuditorEvidencePackage, verifyAuditorPackage } from '../core/auditor_portal.js';
import { getClient } from '../core/registry.js';
import { getAuditLogs } from '../core/audit.js';

/**
 * Auditor Portal API Route Handler
 * Endpoints:
 * - POST /api/auditor/token  -> Issues temporary read-only auditor access token
 * - GET  /api/auditor/export -> Exports cryptographically signed evidence bundle
 * - POST /api/auditor/verify -> Verifies cryptographic integrity of an auditor package
 */
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const path = req.path || req.url || '';

    // Route 1: Token Generation (Requires tenant ownership or admin request)
    if (req.method === 'POST' && (path.endsWith('/token') || req.query.action === 'token')) {
        try {
            const { tenantId, auditorEmail, expiryHours } = req.body || {};
            if (!tenantId || !auditorEmail) {
                return res.status(400).json({ error: 'Missing tenantId or auditorEmail' });
            }

            const tokenInfo = generateAuditorToken(tenantId, auditorEmail, expiryHours || 72);
            return res.status(200).json({
                success: true,
                ...tokenInfo,
                portalUrl: `/auditor-portal.html?token=${tokenInfo.token}`
            });
        } catch (err) {
            return res.status(500).json({ error: 'Failed to issue auditor token: ' + err.message });
        }
    }

    // Route 2: Cryptographic Evidence Bundle Export
    if ((req.method === 'GET' || req.method === 'POST') && (path.endsWith('/export') || req.query.action === 'export')) {
        try {
            const authHeader = req.headers.authorization || '';
            const tokenParam = req.query.token || (req.body && req.body.token);
            const token = authHeader.replace(/^Bearer\s+/i, '') || tokenParam;

            let tenantName = req.query.tenantName || 'Enterprise Cloud Environment';
            let resources = [];
            let auditLogs = [];

            if (token) {
                const tokenVal = validateAuditorToken(token);
                if (!tokenVal.valid) {
                    return res.status(401).json({ error: 'Unauthorized auditor token: ' + tokenVal.error });
                }
                const tenant = await getClient(tokenVal.payload.tenantId);
                if (tenant) {
                    tenantName = tenant.name;
                }
            }

            // If resources passed directly in POST body (e.g. from live scan state)
            if (req.body && Array.isArray(req.body.resources)) {
                resources = req.body.resources;
                tenantName = req.body.tenantName || tenantName;
            }

            const packageBundle = await generateAuditorEvidencePackage(tenantName, resources, auditLogs, {
                auditorName: req.query.auditorName || 'Independent SOC2 Auditor',
                auditorFirm: req.query.auditorFirm || 'CPA Practice'
            });

            return res.status(200).json({
                success: true,
                package: packageBundle
            });
        } catch (err) {
            return res.status(500).json({ error: 'Failed to generate auditor bundle: ' + err.message });
        }
    }

    // Route 3: Cryptographic Verification of an Evidence Package
    if (req.method === 'POST' && (path.endsWith('/verify') || req.query.action === 'verify')) {
        try {
            const packageData = req.body.package || req.body;
            const verification = verifyAuditorPackage(packageData);
            return res.status(verification.verified ? 200 : 400).json(verification);
        } catch (err) {
            return res.status(500).json({ error: 'Package verification failed: ' + err.message });
        }
    }

    return res.status(404).json({ error: 'Auditor portal endpoint not found' });
}
