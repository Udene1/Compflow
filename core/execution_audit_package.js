import crypto from 'crypto';
import pool from './db.js';
import { getExecutionGraph } from './execution_engine.js';
import { getEvidenceFreshness, verifyEvidenceIntegrity } from './evidence.js';

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  return value;
}

function sha256(value) {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
}

function signingSecret() {
  const secret = process.env.AUDITOR_SIGNING_SECRET;
  if (!secret) throw new Error('AUDITOR_SIGNING_SECRET_REQUIRED');
  return secret;
}

export async function buildExecutionAuditPackage({ organizationId, executionId } = {}) {
  if (!organizationId || !executionId) throw new Error('AUDIT_PACKAGE_INPUT_INVALID');
  const executionResult = await pool.query('SELECT id,status,started_at,finished_at,error_code,metadata,created_at,updated_at FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
  if (!executionResult.rows[0]) throw new Error('EXECUTION_NOT_FOUND');
  const graph = await getExecutionGraph(organizationId, executionId);
  const evidenceResult = await pool.query(`SELECT id,node_id,attempt_id,control_id,provider,connection_id,resource_id,source_type,source_ref,collected_at,evidence_hash,evidence_kind,observed_at,freshness_expires_at,lineage FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 ORDER BY collected_at ASC,id ASC`, [organizationId, executionId]);
  const decisionResult = await pool.query('SELECT id,control_id,scope_key,outcome,evidence_hash,verification_hash,rationale,decided_at FROM compliance_decisions WHERE organization_id=$1 AND execution_id=$2 ORDER BY control_id,scope_key', [organizationId, executionId]);
  const historyResult = await pool.query('SELECT id,decision_id,control_id,scope_key,outcome,evidence_hash,verification_hash,decided_at FROM compliance_decision_history WHERE organization_id=$1 AND execution_id=$2 ORDER BY decided_at ASC,id ASC', [organizationId, executionId]);
  const finalResult = await pool.query('SELECT id,outcome,decision_hash,summary,decided_at FROM execution_final_decisions WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  const eventsResult = await pool.query('SELECT sequence,event_id,event_type,node_id,result,created_at FROM execution_events WHERE organization_id=$1 AND execution_id=$2 ORDER BY sequence ASC', [organizationId, executionId]);

  const evidence = evidenceResult.rows.map(row => ({ ...row, integrityValid: verifyEvidenceIntegrity(row), freshness: getEvidenceFreshness(row) }));
  const integrityFailures = evidence.filter(row => !row.integrityValid).map(row => row.id);
  const packageBody = {
    packageVersion: '2.0.0-DURABLE-EXECUTION',
    organizationId,
    execution: executionResult.rows[0],
    graph: { nodes: graph.nodes, edges: graph.edges },
    evidence,
    decisions: decisionResult.rows,
    decisionHistory: historyResult.rows,
    finalDecision: finalResult.rows[0] || null,
    events: eventsResult.rows,
    integrity: { evidenceFailures: integrityFailures, evidenceCount: evidence.length, eventCount: eventsResult.rows.length }
  };
  const manifestHash = sha256(packageBody);
  const secret = signingSecret();
  const signature = crypto.createHmac('sha256', secret).update(manifestHash).digest('hex');
  return {
    packageVersion: packageBody.packageVersion,
    generatedAt: new Date().toISOString(),
    manifestHash,
    signatureAlgorithm: 'HMAC-SHA256',
    digitalSignature: signature,
    verified: integrityFailures.length === 0 && (!packageBody.finalDecision || packageBody.finalDecision.decision_hash === sha256({ organizationId, executionId, outcome: packageBody.finalDecision.outcome, summary: packageBody.finalDecision.summary })),
    package: packageBody
  };
}

export function verifyExecutionAuditPackage(auditPackage, secret = process.env.AUDITOR_SIGNING_SECRET) {
  if (!auditPackage?.manifestHash || !auditPackage?.digitalSignature || !auditPackage?.package) return { verified: false, reason: 'AUDIT_PACKAGE_INVALID' };
  if (!secret) return { verified: false, reason: 'AUDITOR_SIGNING_SECRET_REQUIRED' };
  const expectedManifestHash = sha256(auditPackage.package);
  if (expectedManifestHash !== auditPackage.manifestHash) return { verified: false, reason: 'AUDIT_PACKAGE_MANIFEST_MISMATCH' };
  const expectedSignature = crypto.createHmac('sha256', secret).update(expectedManifestHash).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(String(auditPackage.digitalSignature), 'hex'), Buffer.from(expectedSignature, 'hex'))) return { verified: false, reason: 'AUDIT_PACKAGE_SIGNATURE_MISMATCH' };
  return { verified: true, manifestHash: expectedManifestHash };
}
