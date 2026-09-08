import crypto from 'crypto';
import pool from './db.js';
import { appendExecutionEvent, listExecutionEvents } from './execution_events.js';

export const REMEDIATION_STATES = Object.freeze({
  PROPOSED: 'PROPOSED',
  APPROVED: 'APPROVED',
  REPORTED_APPLIED: 'REPORTED_APPLIED',
  VERIFICATION_PENDING: 'VERIFICATION_PENDING',
  VERIFIED: 'VERIFIED',
  VERIFICATION_FAILED: 'VERIFICATION_FAILED'
});

const EVENT_TYPES = Object.freeze({
  PROPOSED: 'REMEDIATION_PROPOSED',
  APPROVED: 'REMEDIATION_APPROVED',
  APPLIED: 'REMEDIATION_REPORTED_APPLIED',
  VERIFICATION_PENDING: 'REMEDIATION_VERIFICATION_PENDING',
  VERIFIED: 'REMEDIATION_VERIFIED',
  FAILED: 'REMEDIATION_VERIFICATION_FAILED'
});

function clean(value, max = 255) { return String(value ?? '').trim().slice(0, max); }
function idFor({ executionId, findingId, pathId }) {
  return `remediation_${crypto.createHash('sha256').update(`${executionId}:${pathId}:${findingId}`).digest('hex').slice(0, 32)}`;
}
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
function flatten(value, prefix = '', out = {}) {
  if (value == null || Object.keys(out).length >= 500) return out;
  if (Array.isArray(value)) return value.slice(0, 100).reduce((a, v, i) => flatten(v, `${prefix}[${i}]`, a), out);
  if (typeof value !== 'object') { if (prefix) out[prefix.toLowerCase()] = value; return out; }
  for (const [key, val] of Object.entries(value).slice(0, 200)) flatten(val, prefix ? `${prefix}.${key}` : key, out);
  return out;
}
function bool(value) { return value === true || String(value).toLowerCase() === 'true'; }
function isWorld(value) { return value === '0.0.0.0/0' || value === '::/0' || String(value).toLowerCase() === 'internet'; }

/**
 * Evaluate only fresh provider evidence. Unknown evidence is deliberately
 * inconclusive; this function never treats an operator assertion as proof.
 */
export function evaluateFreshEvidence({ code, evidence } = {}) {
  const flat = flatten(object(evidence));
  const entries = Object.entries(flat);
  const normalized = clean(code).toUpperCase();

  if (normalized === 'S3_PUBLIC_ACCESS' || normalized === 'AZURE_STORAGE_PUBLIC_BLOB') {
    const blocking = entries.filter(([key]) => /public|anonymous|access.?control/i.test(key));
    const explicitFalse = blocking.some(([, value]) => value === false || String(value).toLowerCase() === 'false');
    const s3Block = entries.some(([key, value]) => /publicaccessblockconfiguration\.(blockpublic|restrictpublic|ignorepublic|blockpublicacls|restrictpublicbuckets)/i.test(key) && bool(value));
    return explicitFalse || s3Block ? { outcome: 'VERIFIED', reason: 'Fresh evidence reports public access as disabled.' } : { outcome: 'INCONCLUSIVE', reason: 'Fresh evidence does not contain a deterministic public-access block.' };
  }

  if (normalized === 'RDS_PUBLICLY_ACCESSIBLE' || normalized === 'AZURE_SQL_PUBLIC_ACCESS') {
    const explicitFalse = entries.some(([key, value]) => /publiclyaccessible|public.?access/i.test(key) && (value === false || String(value).toLowerCase() === 'false'));
    return explicitFalse ? { outcome: 'VERIFIED', reason: 'Fresh evidence reports public database access as disabled.' } : { outcome: 'INCONCLUSIVE', reason: 'Fresh evidence does not deterministically show public database access is disabled.' };
  }

  if (normalized === 'SG_OPEN_SSH_WORLD' || normalized === 'SG_OPEN_RDP_WORLD' || normalized === 'SG_OPEN_HTTP_WORLD' || normalized === 'AZURE_NSG_OPEN_INBOUND') {
    const worldIngress = entries.some(([key, value]) => /cidr|source|sourceaddress|addressprefix|sourceprefix/i.test(key) && isWorld(value));
    return worldIngress ? { outcome: 'VERIFICATION_FAILED', reason: 'Fresh evidence still contains a world-open ingress source.' } : { outcome: 'INCONCLUSIVE', reason: 'Fresh evidence does not expose a deterministic world-open ingress check.' };
  }

  if (normalized === 'IAM_WILDCARD_PERMISSION' || normalized === 'IAM_ROOT_KEYS') {
    const wildcard = entries.some(([key, value]) => /action|actions|resource|resources|principal|permission/i.test(key) && value === '*');
    return wildcard ? { outcome: 'VERIFICATION_FAILED', reason: 'Fresh evidence still contains a wildcard permission or principal.' } : { outcome: 'INCONCLUSIVE', reason: 'Fresh evidence does not deterministically prove least privilege.' };
  }

  return { outcome: 'INCONCLUSIVE', reason: 'No deterministic verifier exists for this remediation code.' };
}

async function events({ organizationId, executionId }) {
  return listExecutionEvents({ organizationId, executionId, limit: 1000 });
}

function recordsFromEvents(rows) {
  const map = new Map();
  for (const event of rows) {
    const record = event.payload?.remediation;
    if (!record?.id) continue;
    const current = map.get(record.id) || { ...record, state: REMEDIATION_STATES.PROPOSED, history: [] };
    current.history.push({ eventId: event.id, eventType: event.event_type, occurredAt: event.occurred_at, result: event.result });
    if (event.event_type === EVENT_TYPES.APPROVED) current.state = REMEDIATION_STATES.APPROVED;
    if (event.event_type === EVENT_TYPES.APPLIED) current.state = REMEDIATION_STATES.REPORTED_APPLIED;
    if (event.event_type === EVENT_TYPES.VERIFICATION_PENDING) current.state = REMEDIATION_STATES.VERIFICATION_PENDING;
    if (event.event_type === EVENT_TYPES.VERIFIED) { current.state = REMEDIATION_STATES.VERIFIED; current.verification = event.payload.verification; }
    if (event.event_type === EVENT_TYPES.FAILED) { current.state = REMEDIATION_STATES.VERIFICATION_FAILED; current.verification = event.payload.verification; }
    map.set(record.id, current);
  }
  return [...map.values()];
}

export async function listRemediations({ organizationId, executionId }) {
  if (!organizationId || !executionId) throw new Error('REMEDIATION_INPUT_INVALID');
  return recordsFromEvents(await events({ organizationId, executionId }));
}

export async function proposeRemediation({ organizationId, executionId, pathId, findingId, code, resourceId, action, rationale, actorId, idempotencyKey = null }) {
  const id = idFor({ executionId, findingId, pathId });
  const remediation = { id, executionId, pathId: clean(pathId), findingId: clean(findingId), code: clean(code, 64).toUpperCase(), resourceId: clean(resourceId), action: clean(action, 1000), rationale: clean(rationale, 1000), state: REMEDIATION_STATES.PROPOSED };
  const event = await appendExecutionEvent({ organizationId, executionId, eventType: EVENT_TYPES.PROPOSED, actorType: 'USER', actorId, result: 'proposed', payload: { remediation }, idempotencyKey: idempotencyKey ? `remediation:propose:${idempotencyKey}` : null });
  return { remediation, eventId: event.id };
}

async function transition({ organizationId, executionId, remediationId, eventType, state, actorId, result, verification = null, idempotencyKey = null }) {
  const current = (await listRemediations({ organizationId, executionId })).find(item => item.id === remediationId);
  if (!current) throw new Error('REMEDIATION_NOT_FOUND');
  const allowed = {
    [EVENT_TYPES.APPROVED]: [REMEDIATION_STATES.PROPOSED],
    [EVENT_TYPES.APPLIED]: [REMEDIATION_STATES.APPROVED],
    [EVENT_TYPES.VERIFICATION_PENDING]: [REMEDIATION_STATES.REPORTED_APPLIED, REMEDIATION_STATES.APPROVED],
    [EVENT_TYPES.VERIFIED]: [REMEDIATION_STATES.VERIFICATION_PENDING],
    [EVENT_TYPES.FAILED]: [REMEDIATION_STATES.VERIFICATION_PENDING]
  }[eventType] || [];
  if (!allowed.includes(current.state)) throw new Error('REMEDIATION_TRANSITION_INVALID');
  const payload = { remediation: { ...current, state }, ...(verification ? { verification } : {}) };
  const event = await appendExecutionEvent({ organizationId, executionId, eventType, actorType: 'USER', actorId, result, payload, idempotencyKey: idempotencyKey ? `remediation:${eventType}:${remediationId}:${idempotencyKey}` : null });
  return { ...payload.remediation, eventId: event.id, verification };
}

export async function approveRemediation(args) { return transition({ ...args, eventType: EVENT_TYPES.APPROVED, state: REMEDIATION_STATES.APPROVED, result: 'approved' }); }
export async function reportRemediationApplied(args) { return transition({ ...args, eventType: EVENT_TYPES.APPLIED, state: REMEDIATION_STATES.REPORTED_APPLIED, result: 'reported_applied' }); }
export async function requestRemediationVerification(args) { return transition({ ...args, eventType: EVENT_TYPES.VERIFICATION_PENDING, state: REMEDIATION_STATES.VERIFICATION_PENDING, result: 'verification_pending' }); }

export async function verifyRemediation({ organizationId, executionId, remediationId, actorId, idempotencyKey = null }) {
  const current = (await listRemediations({ organizationId, executionId })).find(item => item.id === remediationId);
  if (!current) throw new Error('REMEDIATION_NOT_FOUND');
  if (current.state !== REMEDIATION_STATES.VERIFICATION_PENDING) throw new Error('REMEDIATION_TRANSITION_INVALID');
  const source = await pool.query(`SELECT id,collected_at,evidence_hash,evidence FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 AND resource_id=$3 ORDER BY collected_at DESC LIMIT 1`, [organizationId, executionId, current.resourceId]);
  if (!source.rows[0]) {
    const verification = { outcome: 'INCONCLUSIVE', reason: 'No fresh evidence exists for the affected resource.', evidenceId: null };
    return transition({ organizationId, executionId, remediationId, actorId, eventType: EVENT_TYPES.FAILED, state: REMEDIATION_STATES.VERIFICATION_FAILED, result: 'inconclusive', verification, idempotencyKey });
  }
  const evidence = source.rows[0];
  const verification = { ...evaluateFreshEvidence({ code: current.code, evidence: evidence.evidence }), evidenceId: evidence.id, evidenceHash: evidence.evidence_hash, collectedAt: evidence.collected_at };
  if (verification.outcome === 'VERIFIED') return transition({ organizationId, executionId, remediationId, actorId, eventType: EVENT_TYPES.VERIFIED, state: REMEDIATION_STATES.VERIFIED, result: 'verified', verification, idempotencyKey });
  return transition({ organizationId, executionId, remediationId, actorId, eventType: EVENT_TYPES.FAILED, state: REMEDIATION_STATES.VERIFICATION_FAILED, result: verification.outcome.toLowerCase(), verification, idempotencyKey });
}
