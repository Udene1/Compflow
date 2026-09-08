import crypto from 'crypto';
import pool from './db.js';
import { getEvidenceForNode, verifyEvidenceIntegrity } from './evidence.js';

export async function ensureVerificationSchema() {
  await pool.query(`CREATE TABLE IF NOT EXISTS execution_verifications (
    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, node_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
    control_id TEXT NOT NULL, outcome TEXT NOT NULL, evidence_id TEXT, evidence_hash TEXT, verification_hash TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (organization_id, execution_id, node_id, attempt_id)
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
  const result = await pool.query(`INSERT INTO execution_verifications (id,organization_id,execution_id,node_id,attempt_id,control_id,outcome,evidence_id,evidence_hash,verification_hash,details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb) ON CONFLICT (organization_id,execution_id,node_id,attempt_id) DO NOTHING RETURNING *`, [id, organizationId, executionId, nodeId, attemptId, controlId, outcome, evidence?.id || null, evidence?.evidence_hash || null, verificationHash, JSON.stringify(details)]);
  return result.rows[0] || null;
}

export async function promoteExecutionVerifications({ organizationId, executionId } = {}) {
  await ensureVerificationSchema();
  const result = await pool.query(`SELECT n.id,n.metadata,a.id AS attempt_id,a.metadata AS attempt_metadata FROM execution_graph_nodes n JOIN execution_attempts a ON a.node_id=n.id AND a.organization_id=n.organization_id AND a.execution_id=n.execution_id WHERE n.organization_id=$1 AND n.execution_id=$2 AND n.node_type='VERIFICATION' AND a.status='SUCCEEDED'`, [organizationId, executionId]);
  const promoted = [];
  for (const row of result.rows) {
    const nodeResult = row.attempt_metadata?.result || {};
    const outcome = nodeResult.verified ? 'PASS' : 'FAIL';
    const evidence = await getEvidenceForNode({ organizationId, executionId, nodeId: row.id });
    const stored = await recordVerification({ organizationId, executionId, nodeId: row.id, attemptId: row.attempt_id, controlId: row.metadata?.controlId, outcome, evidence, details: nodeResult });
    if (stored) promoted.push(stored);
  }
  return promoted;
}
