import crypto from 'crypto';
import pool from './db.js';
import { verifyEvidenceIntegrity } from './evidence.js';

export async function ensureVerificationSchema() {
  await pool.query(`CREATE TABLE IF NOT EXISTS execution_verifications (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    evidence_id TEXT,
    evidence_hash TEXT,
    verification_hash TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, execution_id, node_id, attempt_id)
  );
  CREATE INDEX IF NOT EXISTS execution_verifications_control_idx ON execution_verifications (organization_id, execution_id, control_id, created_at DESC);`);
}

export async function recordVerification({ organizationId, executionId, nodeId, attemptId, controlId, outcome, evidence = null, details = {} } = {}) {
  await ensureVerificationSchema();
  if (!['PASS', 'FAIL', 'INSUFFICIENT_EVIDENCE'].includes(outcome)) throw new Error('VERIFICATION_OUTCOME_INVALID');
  if (!organizationId || !executionId || !nodeId || !attemptId || !controlId) throw new Error('VERIFICATION_INPUT_INVALID');
  if (evidence && !verifyEvidenceIntegrity(evidence)) throw new Error('VERIFICATION_EVIDENCE_INTEGRITY_FAILED');
  const verificationHash = crypto.createHash('sha256').update(JSON.stringify({ controlId, outcome, evidenceHash: evidence?.evidence_hash || null, details })).digest('hex');
  const id = `verification_${crypto.randomUUID()}`;
  const result = await pool.query(`INSERT INTO execution_verifications (id,organization_id,execution_id,node_id,attempt_id,control_id,outcome,evidence_id,evidence_hash,verification_hash,details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb) RETURNING *`, [id, organizationId, executionId, nodeId, attemptId, controlId, outcome, evidence?.id || null, evidence?.evidence_hash || null, verificationHash, JSON.stringify(details)]);
  return result.rows[0];
}
