import express from 'express';
import { buildAuditExport } from '../core/audit_export.js';

const router = express.Router();
const ID = /^[A-Za-z0-9._:-]{1,128}$/;

router.get('/executions/:executionId/export', async (req, res, next) => {
  try {
    const organizationId = req.user?.orgId || req.authContext?.orgId || null;
    if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
    const executionId = String(req.params.executionId || '');
    if (!ID.test(executionId)) return res.status(400).json({ error: 'EXECUTION_ID_INVALID' });
    const auditExport = await buildAuditExport({ organizationId, executionId });
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ success: true, ...auditExport });
  } catch (error) {
    return next(error);
  }
});

export default router;
