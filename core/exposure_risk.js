import { severityWeight } from './risk_contract.js';

const NODE_SENSITIVITY = Object.freeze({ SECRETS: 4, KEYVAULT: 4, RDS: 4, SQL: 4, DYNAMODB: 4, S3: 4, IAM: 4, COMPUTE: 3, NETWORK: 3, RESOURCE: 2 });
const DATA_CLASSIFICATION = Object.freeze({ RESTRICTED: 4, CONFIDENTIAL: 3, INTERNAL: 2, PUBLIC: 1 });
const RELATIONSHIP_WEIGHT = Object.freeze({ REACHES: 1.15, CONNECTS_TO: 1.1, ASSUMES_ROLE: 1.2, READS: 1.1, WRITES: 1.1, ACCESS: 1.1, RELATED_TO: 1 });

function normalize(value) { return String(value ?? '').trim().toUpperCase(); }

function nodeSensitivity(node = {}) {
  const typeScore = NODE_SENSITIVITY[normalize(node.node_type || node.nodeType || node.type)] || 1;
  const metadata = node.metadata && typeof node.metadata === 'object' ? node.metadata : {};
  const classification = DATA_CLASSIFICATION[normalize(node.data_classification || node.dataClassification || metadata.dataClassification || metadata.data_classification)] || 0;
  const explicit = Number(node.sensitivity ?? metadata.sensitivity ?? 0);
  return Math.max(typeScore, classification, Number.isFinite(explicit) ? Math.max(1, Math.min(4, explicit)) : 1);
}

export function exposurePathCriticality(path = {}) {
  const nodes = Array.isArray(path.nodes) ? path.nodes : [];
  const edges = Array.isArray(path.edges) ? path.edges : [];
  const maxSensitivity = nodes.reduce((max, node) => Math.max(max, nodeSensitivity(node)), 1);
  const verified = String(path.status || '').toUpperCase() === 'VERIFIED';
  const complete = Boolean(path.evidence_complete ?? path.evidenceComplete);
  const confidence = Math.max(0, Math.min(1, Number(path.confidence) || 0));
  const relationshipMultiplier = Math.min(1.25, edges.reduce((product, edge) => product * (RELATIONSHIP_WEIGHT[normalize(edge.relationship || edge.type)] || 1), 1));
  const criticality = Math.max(0, Math.min(1,
    (((maxSensitivity - 1) / 3) * 0.35) +
    (verified ? 0.25 : 0) +
    (complete ? 0.15 : 0) +
    (confidence * 0.15) +
    ((relationshipMultiplier - 1) * 0.4)
  ));
  return { sensitivity: maxSensitivity, verified, evidenceComplete: complete, confidence, relationshipMultiplier, criticality };
}

export function scoreExposurePath(path = {}) {
  const severity = severityWeight(path.severity);
  const criticality = exposurePathCriticality(path);
  const base = severity * 25;
  const bandBonus = Math.round(criticality.criticality * 24);
  return Math.min(100, base + bandBonus);
}
