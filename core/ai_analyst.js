import crypto from 'crypto';
import { GoogleGenerativeAI } from '@google/generative-ai';
import pool from './db.js';
import { appendExecutionEvent } from './execution_events.js';
import { aggregateSecurityRisk } from './security_risk.js';
import { deriveExecutionRemediationBreakpoints } from './remediation_breakpoints.js';

const MODEL = process.env.GEMINI_ANALYST_MODEL || process.env.GEMINI_MODEL || 'gemini-1.5-flash';
const MAX_RETRIES = 3;
const MAX_FINDINGS = 100;
const MAX_PATHS = 50;
const PROMPT_VERSION = 'security-analyst-v7';
function clean(value, max = 500) { return String(value ?? '').trim().slice(0, max); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function normalizeFinding(row) { return { id: clean(row.id, 128), code: clean(row.code, 128), resourceId: clean(row.resource_id, 255), controlId: clean(row.control_id, 128), severity: clean(row.severity, 32).toUpperCase(), status: clean(row.status, 32), issue: clean(row.issue || row.title || row.description, 500) }; }
function normalizePath(path) { return { id: clean(path.id, 128), status: clean(path.status, 32), severity: clean(path.severity, 32), confidence: Number(path.confidence), evidenceComplete: Boolean(path.evidence_complete), title: clean(path.title, 500), summary: clean(path.summary, 1000), nodes: Array.isArray(path.nodes) ? path.nodes.slice(0, 20).map(node => ({ resourceId: clean(node.resource_id, 255), nodeType: clean(node.node_type, 64), label: clean(node.label, 255), findingIds: Array.isArray(node.finding_ids) ? node.finding_ids.slice(0, 50) : [], evidenceIds: Array.isArray(node.evidence_ids) ? node.evidence_ids.slice(0, 50) : [], metadata: node.metadata && typeof node.metadata === 'object' ? node.metadata : {} })) : [], edges: Array.isArray(path.edges) ? path.edges.slice(0, 20).map(edge => ({ relationship: clean(edge.relationship, 128), evidenceIds: Array.isArray(edge.evidence_ids) ? edge.evidence_ids.slice(0, 50) : [], metadata: edge.metadata && typeof edge.metadata === 'object' ? edge.metadata : {} })) : [] }; }

export function buildAnalystContext({ findings = [], paths = [], evidence = [], risk = null, breakpoints = null, remediationProofs = [] } = {}) {
  const safeFindings = findings.slice(0, MAX_FINDINGS).map(normalizeFinding);
  const safePaths = paths.slice(0, MAX_PATHS).map(normalizePath);
  const safeEvidence = evidence.slice(0, 200).map(row => ({ id: clean(row.id, 128), controlId: clean(row.control_id, 128), provider: clean(row.provider, 64), resourceId: clean(row.resource_id, 255), sourceType: clean(row.source_type, 64), evidenceHash: clean(row.evidence_hash, 128), observedAt: row.observed_at || row.collected_at || null }));
  const deterministicRisk = risk || aggregateSecurityRisk({ findings, paths });
  const deterministicBreakpoints = breakpoints || deriveExecutionRemediationBreakpoints({ paths, findings });
  return {
    findings: safeFindings,
    paths: safePaths,
    evidence: safeEvidence,
    risk: { riskLevel: clean(deterministicRisk.riskLevel, 32), score: Number(deterministicRisk.score) || 0, findingCount: Number(deterministicRisk.findingCount) || 0, weaknessCount: Number(deterministicRisk.weaknessCount) || 0, pathCount: Number(deterministicRisk.pathCount) || 0, verifiedPathCount: Number(deterministicRisk.verifiedPathCount) || 0, potentialPathCount: Number(deterministicRisk.potentialPathCount) || 0, correlatedFindingCount: Number(deterministicRisk.correlatedFindingCount) || 0, compromiseConfirmed: false, weaknesses: Array.isArray(deterministicRisk.weaknesses) ? deterministicRisk.weaknesses.slice(0, 200).map(item => ({ id: clean(item.id, 128), code: clean(item.code, 128), controlId: clean(item.controlId, 128), resourceId: clean(item.resourceId, 255), severity: clean(item.severity, 32), findingIds: Array.isArray(item.findingIds) ? item.findingIds.slice(0, 50) : [] })) : [] },
    remediationBreakpoints: deterministicBreakpoints.slice(0, 200).map(item => ({ id: clean(item.id, 128), pathId: clean(item.pathId, 128), findingId: clean(item.findingId, 128), code: clean(item.code, 128), resourceId: clean(item.resourceId, 255), action: clean(item.action, 1000), rationale: clean(item.rationale, 2000), breaks: Array.isArray(item.breaks) ? item.breaks.slice(0, 10) : [], executed: false, verified: false })),
    remediationProofs: remediationProofs.slice(0, 50).map(item => {
      const afterComplete = item.afterComplete === true;
      const hasIndependentControlEvidence = Boolean(item.controlEvidenceId && item.controlEvidenceHash);
      const hasIndependentReanalysisEvidence = Boolean(item.reanalysisEvidenceId && item.reanalysisEvidenceHash);
      const independent = hasIndependentControlEvidence && hasIndependentReanalysisEvidence && item.controlEvidenceId !== item.reanalysisEvidenceId && item.controlEvidenceHash !== item.reanalysisEvidenceHash;
      const distinctScans = Boolean(item.baselineScanId && item.freshScanId && item.baselineScanId !== item.freshScanId);
      const claimSafe = item.claimSafe === true && afterComplete && independent && distinctScans;
      return { remediationId: clean(item.remediationId, 128), findingId: clean(item.findingId, 128), baselineScanId: clean(item.baselineScanId, 128), freshScanId: clean(item.freshScanId, 128), controlEvidenceId: clean(item.controlEvidenceId, 128), controlEvidenceHash: clean(item.controlEvidenceHash, 128), reanalysisEvidenceId: clean(item.reanalysisEvidenceId, 128), reanalysisEvidenceHash: clean(item.reanalysisEvidenceHash, 128), afterComplete, riskBefore: Number(item.riskBefore?.score), riskAfter: Number(item.riskAfter?.score), pathRemoved: Number(item.pathRemoved || 0), pathAdded: Number(item.pathAdded || 0), claimSafe };
    })
  };
}

function validateAnalysis(value, context) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('AI_ANALYST_INVALID_RESPONSE');
  const allowedFindingIds = new Set(context.findings.map(item => item.id));
  const allowedEvidenceIds = new Set(context.evidence.map(item => item.id));
  const allowedPathIds = new Set(context.paths.map(item => item.id));
  const allowedBreakpointFindingIds = new Set((context.remediationBreakpoints || []).map(item => item.findingId));
  const evidenceRefs = Array.isArray(value.evidence_refs) ? value.evidence_refs : [];
  const findingRefs = Array.isArray(value.finding_refs) ? value.finding_refs : [];
  const pathRefs = Array.isArray(value.path_refs) ? value.path_refs : [];
  if (findingRefs.some(id => !allowedFindingIds.has(id))) throw new Error('AI_ANALYST_UNGROUNDED_FINDING_REF');
  if (evidenceRefs.some(id => !allowedEvidenceIds.has(id))) throw new Error('AI_ANALYST_UNGROUNDED_EVIDENCE_REF');
  if (pathRefs.some(id => !allowedPathIds.has(id))) throw new Error('AI_ANALYST_UNGROUNDED_PATH_REF');
  if (value.compromise_confirmed !== false) throw new Error('AI_ANALYST_COMPROMISE_CLAIM_FORBIDDEN');
  return { summary: clean(value.summary, 2000), why_it_matters: clean(value.why_it_matters, 4000), finding_refs: findingRefs.slice(0, 100), path_refs: pathRefs.slice(0, 50), evidence_refs: evidenceRefs.slice(0, 200), affected_resources: Array.isArray(value.affected_resources) ? value.affected_resources.slice(0, 100).map(item => clean(item, 255)) : [], uncertainty: clean(value.uncertainty, 3000), recommended_breakpoints: Array.isArray(value.recommended_breakpoints) ? value.recommended_breakpoints.slice(0, 20).map(item => ({ finding_id: clean(item.finding_id, 128), action: clean(item.action, 1000), rationale: clean(item.rationale, 2000), expected_effect: clean(item.expected_effect, 1000) })).filter(item => !item.finding_id || (allowedFindingIds.has(item.finding_id) && allowedBreakpointFindingIds.has(item.finding_id))) : [], compromise_confirmed: false };
}
function parseModelJson(text) { const cleaned = String(text || '').replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim(); return JSON.parse(cleaned); }

export async function analyzeSecurityContext(context) {
  if (!process.env.GEMINI_API_KEY) throw new Error('AI_ANALYST_UNAVAILABLE');
  const safeContext = buildAnalystContext(context);
  const sourceHash = sha256(JSON.stringify(safeContext));
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  const model = genAI.getGenerativeModel({ model: MODEL });
  const prompt = `You are Compflow's security analyst. Explain security/compliance state using ONLY supplied deterministic facts. Risk, exposure paths, remediation breakpoints, and remediation proofs are authoritative. Do not recalculate, override, or invent them. Do not invent relationships, findings, resources, evidence, controls, exploits, or compromise. Do not infer compromise from any path. Every reference must use an ID present in the input. If evidence is incomplete, say so. A remediation proof is authoritative only when claimSafe is true, the baseline and fresh scan IDs are distinct, exposure reanalysis is complete, and control-verification evidence and reanalysis evidence are independently linked. Never treat the same evidence row as both stages. Never claim path or aggregate-risk reduction from an incomplete proof.\n\nReturn JSON only with exactly these concepts: summary, why_it_matters, finding_refs, path_refs, evidence_refs, affected_resources, uncertainty, recommended_breakpoints, compromise_confirmed. compromise_confirmed MUST be false.\n\nDETERMINISTIC CONTEXT:\n${JSON.stringify(safeContext)}`;
  let lastError;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt += 1) {
    try { const result = await model.generateContent(prompt); const parsed = parseModelJson(result.response.text()); return { analysis: validateAnalysis(parsed, safeContext), model: MODEL, promptVersion: PROMPT_VERSION, sourceHash }; }
    catch (error) { lastError = error; const retryable = error?.status === 429 || error?.status >= 500 || /rate|timeout|temporar/i.test(error?.message || ''); if (!retryable || attempt === MAX_RETRIES) break; await new Promise(resolve => setTimeout(resolve, 500 * 2 ** (attempt - 1))); }
  }
  throw lastError || new Error('AI_ANALYST_FAILED');
}

export async function analyzeExecutionSecurity({ organizationId, executionId, actorId = null, idempotencyKey = null } = {}) {
  if (!organizationId || !executionId) throw new Error('AI_ANALYST_INPUT_INVALID');
  const evidence = await pool.query('SELECT id,control_id,provider,resource_id,source_type,evidence_hash,observed_at,collected_at FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 ORDER BY collected_at ASC LIMIT 200', [organizationId, executionId]);
  const paths = await pool.query(`SELECT p.*, COALESCE(jsonb_agg(DISTINCT n) FILTER (WHERE n.id IS NOT NULL),'[]'::jsonb) AS nodes, COALESCE(jsonb_agg(DISTINCT e) FILTER (WHERE e.id IS NOT NULL),'[]'::jsonb) AS edges FROM exposure_paths p LEFT JOIN exposure_path_nodes n ON n.path_id=p.id LEFT JOIN exposure_path_edges e ON e.path_id=p.id WHERE p.organization_id=$1 AND p.execution_id=$2 GROUP BY p.id ORDER BY p.updated_at DESC LIMIT $3`, [organizationId, executionId, MAX_PATHS]);
  const execution = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
  const scanId = execution.rows[0]?.metadata?.scanId || execution.rows[0]?.metadata?.scan_id || null;
  const findings = scanId ? await pool.query('SELECT id,resource_id,control_id,severity,status,code FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC LIMIT $3', [organizationId, scanId, MAX_FINDINGS]) : { rows: [] };
  const proofEvents = await pool.query(`SELECT id,payload FROM execution_events WHERE organization_id=$1 AND execution_id=$2 AND event_type='REMEDIATION_REANALYSIS_COMPLETED' AND result='completed' ORDER BY sequence DESC LIMIT 50`, [organizationId, executionId]);
  const remediationProofs = proofEvents.rows.map(row => { const p = row.payload || {}; return { ...p, claimSafe: p.claimSafe === true && p.afterComplete === true && Boolean(p.controlEvidenceId && p.controlEvidenceHash) && Boolean(p.reanalysisEvidenceId && p.reanalysisEvidenceHash) && p.controlEvidenceId !== p.reanalysisEvidenceId && p.baselineScanId && p.freshScanId && p.baselineScanId !== p.freshScanId, pathRemoved: Number(p.pathRemoved || 0), pathAdded: Number(p.pathAdded || 0) }; });
  const context = buildAnalystContext({ findings: findings.rows, paths: paths.rows, evidence: evidence.rows, remediationProofs });
  if (!context.findings.length && !context.paths.length) throw new Error('AI_ANALYST_NO_DETERMINISTIC_CONTEXT');
  const result = await analyzeSecurityContext(context);
  const event = await appendExecutionEvent({ organizationId, executionId, actorType: 'SYSTEM', actorId, eventType: 'SECURITY_ANALYSIS_COMPLETED', result: 'success', payload: { ...result, analysis: result.analysis }, idempotencyKey: idempotencyKey ? `security-analysis:${idempotencyKey}` : null });
  return { executionId, eventId: event.id, ...result };
}

export async function getLatestSecurityAnalysis({ organizationId, executionId } = {}) { if (!organizationId || !executionId) throw new Error('AI_ANALYST_INPUT_INVALID'); const result = await pool.query(`SELECT * FROM execution_events WHERE organization_id=$1 AND execution_id=$2 AND event_type='SECURITY_ANALYSIS_COMPLETED' ORDER BY sequence DESC LIMIT 1`, [organizationId, executionId]); return result.rows[0] || null; }
