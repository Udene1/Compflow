import crypto from 'crypto';
import pool from './db.js';

const MAX_PAYLOAD = 100;
const MAX_LINEAGE = 20;
function canonical(value) { return JSON.stringify(value); }
function hashEvidence(value) { return crypto.createHash('sha256').update(canonical(value)).digest('hex'); }
function assertTimestamp(value, code) { const date = new Date(value); if (Number.isNaN(date.getTime())) throw new Error(code); return date.toISOString(); }
function normalizeLineage(lineage) { if (lineage == null) return []; if (!Array.isArray(lineage) || lineage.length > MAX_LINEAGE) throw new Error('EVIDENCE_LINEAGE_INVALID'); return lineage.map((item, index) => { if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error(`EVIDENCE_LINEAGE_INVALID:${index}`); const clean = {}; for (const [key, value] of Object.entries(item)) { if (typeof key !== 'string' || key.length > 64) continue; if (typeof value === 'string') clean[key] = value.slice(0, 256); else if (typeof value === 'number' || typeof value === 'boolean' || value === null) clean[key] = value; } return clean; }); }

// Schema is owned by core/db.js and initialized before workers/API traffic start.
// Evidence operations only verify that the authoritative table is present.
export async function ensureEvidenceSchema() {
  await pool.query('SELECT 1 FROM execution_evidence_records LIMIT 0');
}

export async function recordEvidence({ organizationId, executionId, nodeId, attemptId, controlId, provider, connectionId, resourceId = null, sourceType = 'cloud_scan', sourceRef = null, evidenceKind = 'observation', observedAt = null, freshnessExpiresAt = null, lineage = [], evidence } = {}) {
  await ensureEvidenceSchema();
  if (!organizationId || !executionId || !nodeId || !attemptId || !controlId || !provider || !connectionId) throw new Error('EVIDENCE_INPUT_INVALID');
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) throw new Error('EVIDENCE_PAYLOAD_INVALID');
  if (typeof evidenceKind !== 'string' || evidenceKind.length < 1 || evidenceKind.length > 64) throw new Error('EVIDENCE_KIND_INVALID');
  const normalizedObservedAt = observedAt == null ? new Date().toISOString() : assertTimestamp(observedAt, 'EVIDENCE_OBSERVED_AT_INVALID');
  const normalizedExpiry = freshnessExpiresAt == null ? null : assertTimestamp(freshnessExpiresAt, 'EVIDENCE_FRESHNESS_INVALID');
  const normalizedLineage = normalizeLineage(lineage);
  const bounded = { ...evidence, resources: Array.isArray(evidence.resources) ? evidence.resources.slice(0, MAX_PAYLOAD) : [] };
  const collectedAt = new Date().toISOString();
  const evidenceHash = hashEvidence(bounded);
  const id = `evidence_${crypto.randomUUID()}`;
  const result = await pool.query(`INSERT INTO execution_evidence_records (id,organization_id,execution_id,node_id,attempt_id,control_id,provider,connection_id,resource_id,source_type,source_ref,collected_at,evidence,evidence_hash,evidence_kind,observed_at,freshness_expires_at,lineage) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18::jsonb) RETURNING *`, [id, organizationId, executionId, nodeId, attemptId, controlId, provider, connectionId, resourceId, sourceType, sourceRef, collectedAt, canonical(bounded), evidenceHash, evidenceKind, normalizedObservedAt, normalizedExpiry, JSON.stringify(normalizedLineage)]);
  return result.rows[0];
}

export async function promoteLegacyExecutionEvidence({ organizationId, executionId } = {}) {
  await ensureEvidenceSchema();
  const table = await pool.query(`SELECT to_regclass('public.execution_evidence') AS name`);
  if (!table.rows[0]?.name) return [];
  const legacy = await pool.query('SELECT * FROM execution_evidence WHERE organization_id=$1 AND execution_id=$2 ORDER BY created_at ASC', [organizationId, executionId]);
  const promoted = [];
  for (const row of legacy.rows) {
    const evidence = row.evidence || {};
    const bounded = { ...evidence, resources: Array.isArray(evidence.resources) ? evidence.resources.slice(0, MAX_PAYLOAD) : [] };
    const normalizedHash = hashEvidence(bounded);
    const result = await pool.query(`INSERT INTO execution_evidence_records (id,organization_id,execution_id,node_id,attempt_id,control_id,provider,connection_id,resource_id,source_type,source_ref,collected_at,evidence,evidence_hash,evidence_kind,observed_at,lineage) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,'[]'::jsonb) ON CONFLICT (organization_id,execution_id,node_id,attempt_id) DO NOTHING RETURNING *`, [`legacy_evidence_${row.id}`, row.organization_id, row.execution_id, row.node_id, row.attempt_id, row.control_id, row.provider, row.connection_id, row.resource_id, row.source_type, row.node_id, row.created_at, canonical(bounded), normalizedHash, 'observation', row.created_at]);
    if (result.rows[0]) promoted.push(result.rows[0]);
  }
  return promoted;
}

export async function getEvidenceForNode({ organizationId, executionId, nodeId, attemptId = null } = {}) {
  await ensureEvidenceSchema();
  const result = await pool.query(`SELECT * FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 AND node_id=$3 ${attemptId ? 'AND attempt_id=$4' : ''} ORDER BY collected_at DESC LIMIT 1`, attemptId ? [organizationId, executionId, nodeId, attemptId] : [organizationId, executionId, nodeId]);
  return result.rows[0] || null;
}

export function verifyEvidenceIntegrity(row) { return Boolean(row) && hashEvidence(row.evidence || {}) === row.evidence_hash; }
export function getEvidenceFreshness(row, now = new Date()) { if (!row) return { state: 'MISSING' }; if (!row.freshness_expires_at) return { state: 'UNBOUNDED', observedAt: row.observed_at || row.collected_at }; const expiry = new Date(row.freshness_expires_at); if (Number.isNaN(expiry.getTime())) return { state: 'INVALID' }; return { state: expiry.getTime() >= new Date(now).getTime() ? 'FRESH' : 'STALE', observedAt: row.observed_at || row.collected_at, expiresAt: expiry.toISOString() }; }
