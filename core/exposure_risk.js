import { severityWeight } from './risk_contract.js';

const NODE_SENSITIVITY = Object.freeze({ SECRETS: 4, KEYVAULT: 4, RDS: 4, SQL: 4, DYNAMODB: 4, S3: 4, IAM: 4, COMPUTE: 3, NETWORK: 3, RESOURCE: 2 });

function normalize(value) { return String(value ?? '').trim().toUpperCase(); }

export function exposurePathCriticality(path = {}) {
  const nodes = Array.isArray(path.nodes) ? path.nodes : [];
  const maxSensitivity = nodes.reduce((max, node) => Math.max(max, NODE_SENSITIVITY[normalize(node.node_type || node.nodeType || node.type)] || 1), 1);
  const verified = String(path.status || '').toUpperCase() === 'VERIFIED';
  const complete = Boolean(path.evidence_complete ?? path.evidenceComplete);
  const confidence = Math.max(0, Math.min(1, Number(path.confidence) || 0));
  return {
    sensitivity: maxSensitivity,
    verified,
    evidenceComplete: complete,
    confidence,
    criticality: Math.max(0, Math.min(1, ((maxSensitivity - 1) / 3) * 0.4 + (verified ? 0.25 : 0) + (complete ? 0.15 : 0) + confidence * 0.2))
  };
}

/**
 * Deterministic path score. Severity supplies the risk band; exposure evidence,
 * verification, confidence and terminal-resource sensitivity refine the score
 * inside that band. Potential paths can contribute risk but never receive the
 * verified-path bonus.
 */
export function scoreExposurePath(path = {}) {
  const severity = severityWeight(path.severity);
  const criticality = exposurePathCriticality(path);
  const base = severity * 25;
  const bandBonus = Math.round(criticality.criticality * 24);
  return Math.min(100, base + bandBonus);
}
