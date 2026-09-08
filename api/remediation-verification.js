import express from 'express';
import { hasRole, ROLES } from '../core/auth.js';
import { deriveExecutionRemediationBreakpoints } from '../core/remediation_breakpoints.js';
import { getExecutionExposurePaths } from '../core/exposure_paths.js';
import { proposeRemediation, approveRemediation, executeApprovedRemediation, reportRemediationApplied, requestRemediationVerification, verifyRemediation, listRemediations } from '../core/remediation_verification.js';
import { runRemediationPostcheck } from '../core/remediation_postcheck.js';
import { getRemediationSecurityImpact } from '../core/remediation_impact.js';
import pool from '../core/db.js';

const router = express.Router();
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const ACTION_ROLES = [ROLES.ENGINEER, ROLES.ADMIN, ROLES.OWNER];
function org(req) { return req.user?.orgId || req.authContext?.orgId || null; }
function actor(req) { return req.user?.userId || req.user?.id || req.authContext?.userId || null; }
function validId(value, error = 'ID_INVALID') { if (!ID.test(String(value || ''))) throw new Error(error); return String(value); }
function text(value, error, max = 1000) { const result = String(value || '').trim(); if (!result || result.length > max) throw new Error(error); return result; }
function authorize(req) { if (!hasRole(req.user?.role, ACTION_ROLES)) { const error = new Error('FORBIDDEN_ACTION'); error.status = 403; throw error; } }
async function candidatesFor({ organizationId, executionId }) {
  const paths = await getExecutionExposurePaths({ organizationId, executionId, limit: 100 });
  const execution = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
  if (!execution.rows[0]) throw new Error('EXECUTION_NOT_FOUND');
  const scanId = execution.rows[0].metadata?.scanId || execution.rows[0].metadata?.scan_id || null;
  const findings = scanId ? await pool.query('SELECT id,resource_id,code,severity FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT 100', [organizationId, scanId]) : { rows: [] };
  return deriveExecutionRemediationBreakpoints({ paths, findings: findings.rows });
}

router.get('/executions/:executionId/remediations', async (req, res, next) => {
  try { const organizationId=org(req); if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'}); const executionId=validId(req.params.executionId,'EXECUTION_ID_INVALID'); return res.json({executionId,remediations:await listRemediations({organizationId,executionId})}); } catch(error){next(error);}
});
router.get('/executions/:executionId/remediation-candidates', async (req, res, next) => {
  try { const organizationId=org(req); if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'}); const executionId=validId(req.params.executionId,'EXECUTION_ID_INVALID'); return res.json({executionId,candidates:await candidatesFor({organizationId,executionId})}); } catch(error){next(error);}
});
router.get('/executions/:executionId/remediations/:remediationId/impact', async (req,res,next)=>{try{const organizationId=org(req);if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'});const executionId=validId(req.params.executionId,'EXECUTION_ID_INVALID');const remediationId=validId(req.params.remediationId,'REMEDIATION_ID_INVALID');return res.json(await getRemediationSecurityImpact({organizationId,executionId,remediationId}));}catch(error){next(error);}});
router.post('/executions/:executionId/remediations', async (req, res, next) => {
  try {
    const organizationId=org(req); if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'}); authorize(req);
    const executionId=validId(req.params.executionId,'EXECUTION_ID_INVALID');
    const pathId=validId(req.body?.pathId,'PATH_ID_INVALID'); const findingId=validId(req.body?.findingId,'FINDING_ID_INVALID'); const code=validId(req.body?.code,'CODE_INVALID'); const resourceId=validId(req.body?.resourceId,'RESOURCE_ID_INVALID');
    const candidates=await candidatesFor({organizationId,executionId});
    const candidate=candidates.find(item => item.pathId===pathId && item.findingId===findingId && item.code===code.toUpperCase() && item.resourceId===resourceId);
    if(!candidate) return res.status(409).json({error:'REMEDIATION_CANDIDATE_INVALID'});
    const requestedAction=text(req.body?.action,'ACTION_TEXT_INVALID');
    if(requestedAction!==candidate.action) return res.status(409).json({error:'REMEDIATION_ACTION_MISMATCH'});
    const requestedRationale=text(req.body?.rationale || candidate.rationale,'RATIONALE_TEXT_INVALID');
    if(requestedRationale!==candidate.rationale) return res.status(409).json({error:'REMEDIATION_RATIONALE_MISMATCH'});
    const result=await proposeRemediation({organizationId,executionId,pathId,findingId,code:candidate.code,resourceId,action:candidate.action,rationale:candidate.rationale,actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null});
    return res.status(201).json(result);
  } catch(error){next(error);}
});
router.post('/executions/:executionId/remediations/:remediationId/approve', async (req,res,next)=>{try{const organizationId=org(req);if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'});authorize(req);return res.json(await approveRemediation({organizationId,executionId:validId(req.params.executionId,'EXECUTION_ID_INVALID'),remediationId:validId(req.params.remediationId,'REMEDIATION_ID_INVALID'),actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null}));}catch(error){next(error);}});
router.post('/executions/:executionId/remediations/:remediationId/execute', async (req,res,next)=>{try{const organizationId=org(req);if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'});authorize(req);const executionId=validId(req.params.executionId,'EXECUTION_ID_INVALID');const remediationId=validId(req.params.remediationId,'REMEDIATION_ID_INVALID');const result=await executeApprovedRemediation({organizationId,executionId,remediationId,actorId:actor(req),req,idempotencyKey:req.get('Idempotency-Key')||null});let postcheck=null;try{postcheck=await runRemediationPostcheck({organizationId,executionId,remediationId,actorId:actor(req),req});}catch(error){postcheck={status:'FAILED',errorCode:String(error.code||'POSTCHECK_FAILED')};}const pending=await requestRemediationVerification({organizationId,executionId,remediationId,actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null});return res.status(202).json({executionId,remediation:pending,execution:result,postcheck,verified:false,verificationRequired:true});}catch(error){next(error);}});
router.post('/executions/:executionId/remediations/:remediationId/applied', async (req,res,next)=>{try{const organizationId=org(req);if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'});authorize(req);const result=await reportRemediationApplied({organizationId,executionId:validId(req.params.executionId,'EXECUTION_ID_INVALID'),remediationId:validId(req.params.remediationId,'REMEDIATION_ID_INVALID'),actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null});return res.status(202).json({...result,verified:false,verificationRequired:true});}catch(error){next(error);}});
router.post('/executions/:executionId/remediations/:remediationId/verify', async (req,res,next)=>{try{const organizationId=org(req);if(!organizationId)return res.status(403).json({error:'ORGANIZATION_CONTEXT_REQUIRED'});authorize(req);const executionId=validId(req.params.executionId,'EXECUTION_ID_INVALID');const remediationId=validId(req.params.remediationId,'REMEDIATION_ID_INVALID');await requestRemediationVerification({organizationId,executionId,remediationId,actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null});const verification=await verifyRemediation({organizationId,executionId,remediationId,actorId:actor(req),idempotencyKey:req.get('Idempotency-Key')||null});return res.json({executionId,remediation:verification,verified:verification.state==='VERIFIED'});}catch(error){next(error);}});
export default router;
