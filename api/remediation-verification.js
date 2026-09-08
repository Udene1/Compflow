import express from 'express';
import { hasRole, ROLES } from '../core/auth.js';
import { deriveExecutionRemediationBreakpoints } from '../core/remediation_breakpoints.js';
import { getExecutionExposurePaths } from '../core/exposure_paths.js';
import { proposeRemediation, approveRemediation, reportRemediationApplied, requestRemediationVerification, verifyRemediation, listRemediations } from '../core/remediation_verification.js';
import pool from '../core/db.js';

const router = express.Router();
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const ACTION_ROLES = [ROLES.ENGINEER, ROLES.ADMIN, ROLES.OWNER];
function org(req) { return req.user?.orgId || req.authContext?.orgId || null; }
function actor(req) { return req.user?.userId || req.user?.id || req.authContext?.userId || null; }
function validId(value, error = 'ID_INVALID') { if (!ID.test(String(value || ''))) throw new Error(error); return String(value); }
function authorize(req) { if (!hasRole(req.user?.role, ACTION_ROLES)) { const error = new Error('FORBIDDEN_ACTION'); error.status = 403; throw error; } }

router.get('/executions/:executionId/remediations', async (req, res, next) => {
  try {
    const organizationId = org(req); if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
    const executionId = validId(req.params.executionId, 'EXECUTION_ID_INVALID');
    const remediations = await listRemediations({ organizationId, executionId });
    return res.json({ executionId, remediations });
  } catch (error) { next(error); }
});

router.get('/executions/:executionId/remediation-candidates', async (req, res, next) => {
  try {
    const organizationId = org(req); if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' });
    const executionId = validId(req.params.executionId, 'EXECUTION_ID_INVALID');
    const paths = await getExecutionExposurePaths({ organizationId, executionId, limit: 100 });
    const execution = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
    if (!execution.rows[0]) return res.status(404).json({ error: 'EXECUTION_NOT_FOUND' });
    const scanId = execution.rows[0].metadata?.scanId || execution.rows[0].metadata?.scan_id || null;
    const findings = scanId ? await pool.query('SELECT id,resource_id,code,severity FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT 100', [organizationId, scanId]) : { rows: [] };
    return res.json({ executionId, candidates: deriveExecutionRemediationBreakpoints({ paths, findings: findings.rows }) });
  } catch (error) { next(error); }
});

router.post('/executions/:executionId/remediations', async (req, res, next) => {
  try {
    const organizationId = org(req); if (!organizationId) return res.status(403).json({ error: 'ORGANIZATION_CONTEXT_REQUIRED' }); authorize(req);
    const executionId = validId(req.params.executionId, 'EXECUTION_ID_INVALID');
    for (const field of ['pathId','findingId','code','resourceId','action']) validId(req.body?.[field], `${field.toUpperCase()}_INVALID`);
    const result = await proposeRemediation({ organizationId, executionId, ...req.body, actorId: actor(req), idempotencyKey: req.get('Idempotency-Key') || null });
    return res.status(201).json(result);
  } catch (error) { next(error); }
});

router.post('/executions/:executionId/remediations/:remediationId/approve', async (req, res, next) => {
  try { const organizationId=org(req); if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'}); authorize(req); const result=await approveRemediation({organizationId,executionId:validId(req.params.executionId,'EXECUTION_ID_INVALID'),remediationId:validId(req.params.remediationId,'REMEDIATION_ID_INVALID'),actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null}); return res.json(result); } catch(error){next(error);}
});
router.post('/executions/:executionId/remediations/:remediationId/applied', async (req, res, next) => {
  try { const organizationId=org(req); if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'}); authorize(req); const result=await reportRemediationApplied({organizationId,executionId:validId(req.params.executionId,'EXECUTION_ID_INVALID'),remediationId:validId(req.params.remediationId,'REMEDIATION_ID_INVALID'),actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null}); return res.status(202).json({...result,verified:false}); } catch(error){next(error);}
});
router.post('/executions/:executionId/remediations/:remediationId/verify', async (req, res, next) => {
  try { const organizationId=org(req); if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'}); authorize(req); const remediationId=validId(req.params.remediationId,'REMEDIATION_ID_INVALID'); const result=await requestRemediationVerification({organizationId,executionId:validId(req.params.executionId,'EXECUTION_ID_INVALID'),remediationId,actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null}); const verification=await verifyRemediation({organizationId,executionId:result.executionId,remediationId,actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null}); return res.status(200).json({remediation:verification,verified:verification.state==='VERIFIED'}); } catch(error){next(error);}
});

export default router;
