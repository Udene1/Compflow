import crypto from 'crypto';
import pool from './db.js';

const MAX_PAYLOAD = 100;
function canonical(value) { return JSON.stringify(value); }
function hashEvidence(value) { return crypto.createHash('sha256').update(canonical(value)).digest('hex'); }

export async function ensureEvidenceSchema() {
  await pool.query(`CREATE TABLE IF NOT EXISTS execution_evidence_records (
    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, node_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
    control_id TEXT NOT NULL, provider TEXT NOT NULL, connection_id TEXT NOT NULL, resource_id TEXT, source_type TEXT NOT NULL, source_ref TEXT,
    collected_at TIMESTAMPTZ NOT NULL, evidence JSONB NOT NULL, evidence_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, execution_id, node_id, attempt_id)
  );
  CREATE INDEX IF NOT EXISTS execution_evidence_records_control_idx ON execution_evidence_records (organization_id, execution_id, control_id, collected_at DESC);
  CREATE INDEX IF NOT EXISTS execution_evidence_records_resource_idx ON execution_evidence_records (organization_id, resource_id, collected_at DESC);`);
}

export async function recordEvidence({ organizationId, executionId, nodeId, attemptId, controlId, provider, connectionId, resourceId = null, sourceType = 'cloud_scan', sourceRef = null, evidence } = {}) {
  await ensureEvidenceSchema();
  if (!organizationId || !executionId || !nodeId || !attemptId || !controlId || !provider || !connectionId) throw new Error('EVIDENCE_INPUT_INVALID');
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) throw new Error('EVIDENCE_PAYLOAD_INVALID');
  const bounded = { ...evidence, resources: Array.isArray(evidence.resources) ? evidence.resources.slice(0, MAX_PAYLOAD) : [] };
  const collectedAt = new Date().toISOString();
  const evidenceHash = hashEvidence(bounded);
  const id = `evidence_${crypto.randomUUID()}`;
  const result = await pool.query(`INSERT INTO execution_evidence_records (id,organization_id,execution_id,node_id,attempt_id,control_id,provider,connection_id,resource_id,source_type,source_ref,collected_at,evidence,evidence_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14) RETURNING *`, [id, organizationId, executionId, nodeId, attemptId, controlId, provider, connectionId, resourceId, sourceType, sourceRef, collectedAt, canonical(bounded), evidenceHash]);
  return result.rows[0];
}

export async function promoteLegacyExecutionEvidence({ organizationId, executionId } = {}) {
  await ensureEvidenceSchema();
  const legacy = await pool.query('SELECT * FROM execution_evidence WHERE organization_id=$1 AND execution_id=$2 ORDER BY created_at ASC', [organizationId, executionId]);
  const promoted = [];
  for (const row of legacy.rows) {
    const evidence = row.evidence || {};
    const bounded = { ...evidence, resources: Array.isArray(evidence.resources) ? evidence.resources.slice(0, MAX_PAYLOAD) : [] };
    const result = await pool.query(`INSERT INTO execution_evidence_records (id,organization_id,execution_id,node_id,attempt_id,control_id,provider,connection_id,resource_id,source_type,source_ref,collected_at,evidence,evidence_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14) ON CONFLICT (organization_id,execution_id,node_id,attempt_id) DO NOTHING RETURNING *`, [`legacy_evidence_${row.id}`, row.organization_id, row.execution_id, row.node_id, row.attempt_id, row.control_id, row.provider, row.connection_id, row.resource_id, row.source_type, row.node_id, row.created_at, canonical(bounded), row.evidence_hash || hashEvidence(bounded)]);
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
