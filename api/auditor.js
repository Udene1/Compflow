import { generateAuditorToken, verifyAuditorPackage } from '../core/auditor_portal.js';
import { buildAuditExport } from '../core/audit_export.js';
import pool from '../core/db.js';

/**
 * Auditor Portal API.
 * Durable exports are always derived from the authenticated organization and
 * execution state; callers cannot inject findings/resources into an audit package.
 */
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', 'https://compflow.icu');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const path = req.path || req.url || '';
    const organizationId = req.user?.orgId || req.authContext?.orgId || null;

    if (req.method === 'POST' && (path.endsWith('/token') || req.query.action === 'token')) {
        try {
            if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
            const { tenantId, auditorEmail, expiryHours } = req.body || {};
            if (!tenantId || !auditorEmail) return res.status(400).json({ error: 'Missing tenantId or auditorEmail' });
            const tenant = await pool.query('SELECT id FROM tenants WHERE id=$1 AND org_id=$2 LIMIT 1', [String(tenantId), organizationId]);
            if (!tenant.rows[0]) return res.status(404).json({ error: 'TENANT_NOT_FOUND' });
            const tokenInfo = generateAuditorToken(tenantId, auditorEmail, expiryHours || 72);
            return res.status(200).json({ success: true, ...tokenInfo, portalUrl: `/auditor-portal.html?token=${tokenInfo.token}` });
        } catch (err) {
            return res.status(500).json({ error: 'Failed to issue auditor token' });
        }
    }

    if ((req.method === 'GET' || req.method === 'POST') && (path.endsWith('/export') || req.query.action === 'export')) {
        try {
            if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
            const executionId = String(req.query.executionId || req.body?.executionId || '').trim();
            if (!/^[A-Za-z0-9._:-]{1,128}$/.test(executionId)) return res.status(400).json({ error: 'EXECUTION_ID_INVALID' });
            const auditExport = await buildAuditExport({ organizationId, executionId });
            res.setHeader('Cache-Control', 'no-store');
            return res.status(200).json({ success: true, ...auditExport });
        } catch (err) {
            return res.status(err?.message === 'EXECUTION_NOT_FOUND' ? 404 : 500).json({ error: err?.message === 'EXECUTION_NOT_FOUND' ? err.message : 'AUDIT_EXPORT_FAILED' });
        }
    }

    if (req.method === 'POST' && (path.endsWith('/verify') || req.query.action === 'verify')) {
        try {
            const packageData = req.body?.package || req.body;
            const verification = verifyAuditorPackage(packageData);
            return res.status(verification.verified ? 200 : 400).json(verification);
        } catch (err) {
            return res.status(500).json({ error: 'Package verification failed' });
        }
    }

    return res.status(404).json({ error: 'Auditor portal endpoint not found' });
}
