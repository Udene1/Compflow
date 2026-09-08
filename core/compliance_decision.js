import crypto from 'crypto';
import pool from './db.js';
import { promoteLegacyExecutionEvidence } from './evidence.js';
import { promoteExecutionVerifications } from './compliance_verification.js';

const OUTCOMES = new Set(['PASS', 'FAIL', 'NOT_APPLICABLE', 'INSUFFICIENT_EVIDENCE']);

export async function ensureDecisionSchema() {
  await pool.query(`CREATE TABLE IF NOT EXISTS compliance_decisions (
    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, control_id TEXT, scope_key TEXT NOT NULL,
    outcome TEXT NOT NULL, evidence_hash TEXT, verification_hash TEXT, rationale JSONB NOT NULL DEFAULT '{}'::jsonb,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (organization_id, execution_id, scope_key)
  );
  CREATE INDEX IF NOT EXISTS compliance_decisions_execution_idx ON compliance_decisions (organization_id, execution_id, decided_at);
  CREATE TABLE IF NOT EXISTS compliance_decision_history (
    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, decision_id TEXT NOT NULL,
    control_id TEXT NOT NULL, scope_key TEXT NOT NULL, outcome TEXT NOT NULL, evidence_hash TEXT, verification_hash TEXT,
    rationale JSONB NOT NULL DEFAULT '{}'::jsonb, decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS compliance_decision_history_execution_idx ON compliance_decision_history (organization_id, execution_id, decided_at);
  CREATE UNIQUE INDEX IF NOT EXISTS compliance_decision_history_state_idx ON compliance_decision_history (decision_id, outcome, COALESCE(evidence_hash, ''), COALESCE(verification_hash, ''));
  CREATE TABLE IF NOT EXISTS execution_final_decisions (
    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, outcome TEXT NOT NULL, decision_hash TEXT NOT NULL,
    summary JSONB NOT NULL, decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (organization_id, execution_id)
  );`);
}

function assertOutcome(outcome) { if (!OUTCOMES.has(outcome)) throw new Error('DECISION_OUTCOME_INVALID'); }
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  return value;
}
function finalDecisionHash(organizationId, executionId, outcome, summary) { return crypto.createHash('sha256').update(JSON.stringify(canonicalize({ organizationId, executionId, outcome, summary }))).digest('hex'); }

export async function recordControlDecision({ organizationId, executionId, controlId, scopeKey, outcome, evidenceHash = null, verificationHash = null, rationale = {} } = {}) {
  await ensureDecisionSchema(); assertOutcome(outcome);
  if (!organizationId || !executionId || !controlId || !scopeKey) throw new Error('DECISION_INPUT_INVALID');
  const id = `decision_${crypto.createHash('sha256').update(`${organizationId}:${executionId}:${scopeKey}`).digest('hex').slice(0, 32)}`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query('SELECT * FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2 AND scope_key=$3 FOR UPDATE', [organizationId, executionId, scopeKey]);
    let current;
    if (existing.rows[0]) {
      const row = existing.rows[0];
      if (row.outcome === outcome && row.evidence_hash === evidenceHash && row.verification_hash === verificationHash) { await client.query('COMMIT'); return row; }
      current = (await client.query(`UPDATE compliance_decisions SET outcome=$1,evidence_hash=$2,verification_hash=$3,rationale=$4::jsonb,decided_at=clock_timestamp() WHERE id=$5 RETURNING *`, [outcome,evidenceHash,verificationHash,JSON.stringify(rationale),row.id])).rows[0];
    } else {
      current = (await client.query(`INSERT INTO compliance_decisions (id,organization_id,execution_id,control_id,scope_key,outcome,evidence_hash,verification_hash,rationale) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) RETURNING *`, [id,organizationId,executionId,controlId,scopeKey,outcome,evidenceHash,verificationHash,JSON.stringify(rationale)])).rows[0];
    }
    await client.query(`INSERT INTO compliance_decision_history (id,organization_id,execution_id,decision_id,control_id,scope_key,outcome,evidence_hash,verification_hash,rationale) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb) ON CONFLICT (decision_id, outcome, COALESCE(evidence_hash, ''), COALESCE(verification_hash, '')) DO NOTHING`, [`decision_history_${crypto.randomUUID()}`,organizationId,executionId,current.id,controlId,scopeKey,outcome,evidenceHash,verificationHash,JSON.stringify(rationale)]);
    await client.query('COMMIT'); return current;
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
}

export async function deriveExecutionDecisions({ organizationId, executionId } = {}) {
  await ensureDecisionSchema(); await promoteLegacyExecutionEvidence({ organizationId, executionId }); await promoteExecutionVerifications({ organizationId, executionId });
  const nodes = await pool.query(`SELECT id,node_type,logical_key,status,metadata FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2 AND node_type IN ('CONTROL_EVALUATION','VERIFICATION') ORDER BY created_at ASC`, [organizationId, executionId]);
  const attempts = await pool.query(`SELECT DISTINCT ON (node_id) node_id,status,metadata FROM execution_attempts WHERE organization_id=$1 AND execution_id=$2 ORDER BY node_id,attempt_number DESC`, [organizationId, executionId]);
  const latest = new Map(attempts.rows.map(row => [row.node_id, row])); const verificationByKey = new Map();
  const verificationRows = await pool.query('SELECT * FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2 ORDER BY created_at DESC', [organizationId, executionId]);
  for (const row of verificationRows.rows) if (!verificationByKey.has(row.node_id)) verificationByKey.set(row.node_id, row);
  const decisions = [];
  for (const node of nodes.rows.filter(row => row.node_type === 'CONTROL_EVALUATION')) {
    const attempt = latest.get(node.id); const result = attempt?.metadata?.result || {};
    const verificationNode = nodes.rows.find(candidate => candidate.node_type === 'VERIFICATION' && candidate.logical_key.startsWith(node.logical_key.replace(/:evaluate:[^:]+$/, '') + ':verify:'));
    const verification = verificationNode ? verificationByKey.get(verificationNode.id) : null;
    const evidenceHash = result.evidenceHash || null; const verificationHash = verification?.verification_hash || null;
    let outcome;
    if (verification?.outcome) outcome = verification.evidence_hash ? verification.outcome : 'INSUFFICIENT_EVIDENCE';
    else if (attempt?.status === 'SUCCEEDED') outcome = result.assessment === 'PASS' && evidenceHash ? 'PASS' : result.assessment === 'FAIL' && evidenceHash ? 'FAIL' : 'INSUFFICIENT_EVIDENCE';
    else outcome = 'INSUFFICIENT_EVIDENCE';
    const existing = await pool.query('SELECT * FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2 AND scope_key=$3', [organizationId, executionId, node.logical_key]);
    if (existing.rows[0] && existing.rows[0].outcome === outcome && existing.rows[0].evidence_hash === evidenceHash && existing.rows[0].verification_hash === verificationHash) { decisions.push(existing.rows[0]); continue; }
    decisions.push(await recordControlDecision({ organizationId, executionId, controlId: node.metadata?.controlId, scopeKey: node.logical_key, outcome, evidenceHash, verificationHash, rationale: { evaluation: result, evaluationAttemptStatus: attempt?.status || 'MISSING', evidenceRequired: true, verification: verification ? { outcome: verification.outcome, id: verification.id, evidenceHash: verification.evidence_hash } : null, nodeId: node.id } }));
  }
  return decisions;
}

export async function finalizeExecutionDecision({ organizationId, executionId } = {}) {
  await ensureDecisionSchema();
  const existingFinal = await pool.query('SELECT * FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  if (existingFinal.rows[0]) {
    const row = existingFinal.rows[0];
    if (row.decision_hash !== finalDecisionHash(organizationId, executionId, row.outcome, row.summary)) throw new Error('FINAL_DECISION_IMMUTABLE');
    return row;
  }
  const graph = await pool.query(`SELECT node_type,status FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2`, [organizationId, executionId]);
  const active = graph.rows.some(node => ['PENDING', 'RUNNING'].includes(node.status) && ['EVIDENCE_COLLECTION','CONTROL_EVALUATION','APPROVAL','REMEDIATION','VERIFICATION'].includes(node.node_type));
  if (active) throw new Error('DECISION_EXECUTION_NOT_TERMINAL');
  await deriveExecutionDecisions({ organizationId, executionId });
  const result = await pool.query('SELECT * FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2 ORDER BY control_id,scope_key', [organizationId, executionId]);
  if (!result.rows.length) throw new Error('DECISION_INPUTS_MISSING');
  const outcomes = result.rows.map(row => row.outcome); let outcome = 'PASS'; if (outcomes.includes('FAIL')) outcome = 'FAIL'; else if (outcomes.includes('INSUFFICIENT_EVIDENCE')) outcome = 'INSUFFICIENT_EVIDENCE'; else if (outcomes.every(value => value === 'NOT_APPLICABLE')) outcome = 'NOT_APPLICABLE';
  const summary = { controls: result.rows.map(row => ({ controlId: row.control_id, scopeKey: row.scope_key, outcome: row.outcome, evidenceHash: row.evidence_hash, verificationHash: row.verification_hash })), counts: outcomes.reduce((acc, value) => { acc[value] = (acc[value] || 0) + 1; return acc; }, {}) };
  const decisionHash = finalDecisionHash(organizationId, executionId, outcome, summary); const id = `final_decision_${crypto.createHash('sha256').update(`${organizationId}:${executionId}`).digest('hex').slice(0, 32)}`;
  const stored = await pool.query(`INSERT INTO execution_final_decisions (id,organization_id,execution_id,outcome,decision_hash,summary) VALUES ($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT (organization_id,execution_id) DO NOTHING RETURNING *`, [id, organizationId, executionId, outcome, decisionHash, JSON.stringify(summary)]);
  if (stored.rows[0]) return stored.rows[0];
  const raced = await pool.query('SELECT * FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  if (!raced.rows[0]) throw new Error('FINAL_DECISION_PERSISTENCE_FAILED');
  if (raced.rows[0].decision_hash !== finalDecisionHash(organizationId, executionId, raced.rows[0].outcome, raced.rows[0].summary)) throw new Error('FINAL_DECISION_IMMUTABLE');
  return raced.rows[0];
}
