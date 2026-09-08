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
  CREATE TABLE IF NOT EXISTS execution_final_decisions (
    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, execution_id TEXT NOT NULL, outcome TEXT NOT NULL, decision_hash TEXT NOT NULL,
    summary JSONB NOT NULL, decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (organization_id, execution_id)
  );`);
}

function assertOutcome(outcome) { if (!OUTCOMES.has(outcome)) throw new Error('DECISION_OUTCOME_INVALID'); }

export async function recordControlDecision({ organizationId, executionId, controlId, scopeKey, outcome, evidenceHash = null, verificationHash = null, rationale = {} } = {}) {
  await ensureDecisionSchema(); assertOutcome(outcome);
  if (!organizationId || !executionId || !controlId || !scopeKey) throw new Error('DECISION_INPUT_INVALID');
  const id = `decision_${crypto.createHash('sha256').update(`${organizationId}:${executionId}:${scopeKey}`).digest('hex').slice(0, 32)}`;
  const result = await pool.query(`INSERT INTO compliance_decisions (id,organization_id,execution_id,control_id,scope_key,outcome,evidence_hash,verification_hash,rationale) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) ON CONFLICT (organization_id,execution_id,scope_key) DO UPDATE SET outcome=EXCLUDED.outcome,evidence_hash=EXCLUDED.evidence_hash,verification_hash=EXCLUDED.verification_hash,rationale=EXCLUDED.rationale,decided_at=NOW() RETURNING *`, [id, organizationId, executionId, controlId, scopeKey, outcome, evidenceHash, verificationHash, JSON.stringify(rationale)]);
  return result.rows[0];
}

export async function deriveExecutionDecisions({ organizationId, executionId } = {}) {
  await ensureDecisionSchema();
  await promoteLegacyExecutionEvidence({ organizationId, executionId });
  await promoteExecutionVerifications({ organizationId, executionId });
  const nodes = await pool.query(`SELECT id,node_type,logical_key,status,metadata FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2 AND node_type IN ('CONTROL_EVALUATION','VERIFICATION') ORDER BY created_at ASC`, [organizationId, executionId]);
  const attempts = await pool.query(`SELECT DISTINCT ON (node_id) node_id,status,metadata FROM execution_attempts WHERE organization_id=$1 AND execution_id=$2 ORDER BY node_id,attempt_number DESC`, [organizationId, executionId]);
  const latest = new Map(attempts.rows.map(row => [row.node_id, row]));
  const verificationByKey = new Map();
  const verificationRows = await pool.query('SELECT * FROM execution_verifications WHERE organization_id=$1 AND execution_id=$2 ORDER BY created_at DESC', [organizationId, executionId]);
  for (const row of verificationRows.rows) verificationByKey.set(row.node_id, row);
  const decisions = [];
  for (const node of nodes.rows.filter(row => row.node_type === 'CONTROL_EVALUATION')) {
    const attempt = latest.get(node.id);
    const result = attempt?.metadata?.result || {};
    const verificationNode = nodes.rows.find(candidate => candidate.node_type === 'VERIFICATION' && candidate.logical_key.startsWith(node.logical_key.replace(/:evaluate:[^:]+$/, '') + ':verify:'));
    const verification = verificationNode ? verificationByKey.get(verificationNode.id) : null;
    let outcome;
    if (verification?.outcome) outcome = verification.outcome;
    else if (attempt?.status === 'SUCCEEDED') outcome = result.assessment === 'PASS' ? 'PASS' : result.assessment === 'FAIL' ? 'FAIL' : 'INSUFFICIENT_EVIDENCE';
    else outcome = 'INSUFFICIENT_EVIDENCE';
    decisions.push(await recordControlDecision({ organizationId, executionId, controlId: node.metadata?.controlId, scopeKey: node.logical_key, outcome, evidenceHash: result.evidenceHash || null, verificationHash: verification?.verification_hash || null, rationale: { evaluation: result, evaluationAttemptStatus: attempt?.status || 'MISSING', verification: verification ? { outcome: verification.outcome, id: verification.id } : null, nodeId: node.id } }));
  }
  return decisions;
}

export async function finalizeExecutionDecision({ organizationId, executionId } = {}) {
  await ensureDecisionSchema();
  const graph = await pool.query(`SELECT node_type,status FROM execution_graph_nodes WHERE organization_id=$1 AND execution_id=$2`, [organizationId, executionId]);
  const active = graph.rows.some(node => ['PENDING', 'RUNNING'].includes(node.status) && ['EVIDENCE_COLLECTION','CONTROL_EVALUATION','APPROVAL','REMEDIATION','VERIFICATION'].includes(node.node_type));
  if (active) throw new Error('DECISION_EXECUTION_NOT_TERMINAL');
  await deriveExecutionDecisions({ organizationId, executionId });
  const result = await pool.query('SELECT * FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2 ORDER BY control_id,scope_key', [organizationId, executionId]);
  if (!result.rows.length) throw new Error('DECISION_INPUTS_MISSING');
  const outcomes = result.rows.map(row => row.outcome);
  let outcome = 'PASS';
  if (outcomes.includes('FAIL')) outcome = 'FAIL'; else if (outcomes.includes('INSUFFICIENT_EVIDENCE')) outcome = 'INSUFFICIENT_EVIDENCE'; else if (outcomes.every(value => value === 'NOT_APPLICABLE')) outcome = 'NOT_APPLICABLE';
  const summary = { controls: result.rows.map(row => ({ controlId: row.control_id, scopeKey: row.scope_key, outcome: row.outcome, evidenceHash: row.evidence_hash, verificationHash: row.verification_hash })), counts: outcomes.reduce((acc, value) => { acc[value] = (acc[value] || 0) + 1; return acc; }, {}) };
  const decisionHash = crypto.createHash('sha256').update(JSON.stringify({ executionId, outcome, summary })).digest('hex');
  const id = `final_decision_${crypto.createHash('sha256').update(`${organizationId}:${executionId}`).digest('hex').slice(0, 32)}`;
  const stored = await pool.query(`INSERT INTO execution_final_decisions (id,organization_id,execution_id,outcome,decision_hash,summary) VALUES ($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT (organization_id,execution_id) DO UPDATE SET outcome=EXCLUDED.outcome,decision_hash=EXCLUDED.decision_hash,summary=EXCLUDED.summary,decided_at=NOW() RETURNING *`, [id, organizationId, executionId, outcome, decisionHash, JSON.stringify(summary)]);
  return stored.rows[0];
}
