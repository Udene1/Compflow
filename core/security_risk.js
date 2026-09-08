import crypto from 'crypto';
import { normalizeSeverity, severityWeight, riskLevel, capScore, RISK_CONTRACT_VERSION } from './risk_contract.js';

const MAX_WEAKNESSES = 200;
const MAX_PATHS = 100;

function clean(value, fallback = '') {
  return String(value ?? fallback).trim().slice(0, 255);
}

function stableId(prefix, value) {
  return `${prefix}_${crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 32)}`;
}

export function deriveWeaknesses(findings = []) {
  const groups = new Map();
  for (const finding of findings) {
    if (!finding?.id) continue;
    const code = clean(finding.code, 'UNKNOWN').toUpperCase();
    const controlId = clean(finding.control_id || finding.controlId, 'UNKNOWN');
    const resourceId = clean(finding.resource_id || finding.resourceId, 'UNKNOWN');
    const key = `${controlId}:${code}:${resourceId}`;
    const list = groups.get(key) || [];
    list.push(finding);
    groups.set(key, list);
  }
  return [...groups.entries()].slice(0, MAX_WEAKNESSES).map(([key, rows]) => {
    const maxScore = rows.reduce((max, row) => Math.max(max, severityWeight(row.severity)), 1);
    return {
      id: stableId('weakness', key), key,
      code: clean(rows[0].code, 'UNKNOWN'),
      controlId: clean(rows[0].control_id || rows[0].controlId, 'UNKNOWN'),
      resourceId: clean(rows[0].resource_id || rows[0].resourceId, 'UNKNOWN'),
      severity: normalizeSeverity(rows.find(row => severityWeight(row.severity) === maxScore)?.severity),
      findingIds: rows.map(row => clean(row.id)).filter(Boolean),
      findingCount: rows.length,
      issue: clean(rows[0].issue || rows[0].title || rows[0].description || rows[0].code, 255)
    };
  });
}

function pathFindingIds(path) {
  return new Set((path?.nodes || []).flatMap(node => Array.isArray(node.finding_ids)
    ? node.finding_ids
    : Array.isArray(node.findingIds) ? node.findingIds : []));
}

export function aggregateSecurityRisk({ findings = [], paths = [] } = {}) {
  const weaknesses = deriveWeaknesses(findings);
  const weaknessByFinding = new Map();
  for (const weakness of weaknesses) for (const findingId of weakness.findingIds) weaknessByFinding.set(findingId, weakness);

  const riskPaths = paths.slice(0, MAX_PATHS).map(path => {
    const ids = pathFindingIds(path);
    const linkedWeaknesses = [...ids].map(id => weaknessByFinding.get(id)).filter(Boolean);
    const pathScore = severityWeight(path.severity);
    const weaknessScore = linkedWeaknesses.reduce((max, item) => Math.max(max, severityWeight(item.severity)), 1);
    const score = Math.max(pathScore, weaknessScore);
    return {
      id: clean(path.id), title: clean(path.title || path.path_key || 'Security exposure path', 255),
      status: clean(path.status, 'POTENTIAL').toUpperCase(), severity: normalizeSeverity(path.severity || riskLevel(score)),
      score, confidence: Math.max(0, Math.min(1, Number(path.confidence) || 0)),
      evidenceComplete: Boolean(path.evidence_complete ?? path.evidenceComplete),
      weaknessIds: [...new Set(linkedWeaknesses.map(item => item.id))], findingIds: [...ids].filter(Boolean)
    };
  });

  const highestWeight = Math.max(
    riskPaths.reduce((max, path) => Math.max(max, path.score), 0),
    weaknesses.reduce((max, item) => Math.max(max, severityWeight(item.severity)), 0)
  );
  const verifiedPaths = riskPaths.filter(path => path.status === 'VERIFIED').length;
  const potentialPaths = riskPaths.filter(path => path.status === 'POTENTIAL').length;
  const affectedFindingIds = new Set(riskPaths.flatMap(path => path.findingIds));
  const score = capScore(highestWeight * 25);

  return {
    contractVersion: RISK_CONTRACT_VERSION,
    riskLevel: riskLevel(score), score,
    findingCount: findings.length, weaknessCount: weaknesses.length, pathCount: riskPaths.length,
    verifiedPathCount: verifiedPaths, potentialPathCount: potentialPaths,
    correlatedFindingCount: affectedFindingIds.size, compromiseConfirmed: false,
    weaknesses, paths: riskPaths
  };
}
