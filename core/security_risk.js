import crypto from 'crypto';

const SEVERITY_SCORE = Object.freeze({ LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 });
const MAX_WEAKNESSES = 200;
const MAX_PATHS = 100;

function clean(value, fallback = '') {
  return String(value ?? fallback).trim().slice(0, 255);
}

function severity(value) {
  const normalized = clean(value, 'LOW').toUpperCase();
  return SEVERITY_SCORE[normalized] ? normalized : 'LOW';
}

function severityForScore(score) {
  if (score >= 4) return 'CRITICAL';
  if (score >= 3) return 'HIGH';
  if (score >= 2) return 'MEDIUM';
  return 'LOW';
}

function stableId(prefix, value) {
  return `${prefix}_${crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 32)}`;
}

/**
 * Deterministically groups findings into underlying weaknesses. A weakness is
 * only created from findings sharing a control/code/resource identity; AI is
 * never used to invent correlations.
 */
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
    const maxScore = rows.reduce((max, row) => Math.max(max, SEVERITY_SCORE[severity(row.severity)]), 1);
    return {
      id: stableId('weakness', key),
      key,
      code: clean(rows[0].code, 'UNKNOWN'),
      controlId: clean(rows[0].control_id || rows[0].controlId, 'UNKNOWN'),
      resourceId: clean(rows[0].resource_id || rows[0].resourceId, 'UNKNOWN'),
      severity: severityForScore(maxScore),
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

/**
 * Computes risk from deterministic weaknesses and observed exposure paths.
 * Path severity is never increased by AI and a potential path is never treated
 * as confirmed compromise. The score is a prioritization signal, not a breach claim.
 */
export function aggregateSecurityRisk({ findings = [], paths = [] } = {}) {
  const weaknesses = deriveWeaknesses(findings);
  const weaknessByFinding = new Map();
  for (const weakness of weaknesses) for (const findingId of weakness.findingIds) weaknessByFinding.set(findingId, weakness);

  const riskPaths = paths.slice(0, MAX_PATHS).map(path => {
    const ids = pathFindingIds(path);
    const linkedWeaknesses = [...ids].map(id => weaknessByFinding.get(id)).filter(Boolean);
    const pathScore = SEVERITY_SCORE[severity(path.severity)] || 1;
    const weaknessScore = linkedWeaknesses.reduce((max, item) => Math.max(max, SEVERITY_SCORE[item.severity]), 1);
    const score = Math.max(pathScore, weaknessScore);
    return {
      id: clean(path.id),
      title: clean(path.title || path.path_key || 'Security exposure path', 255),
      status: clean(path.status, 'POTENTIAL').toUpperCase(),
      severity: severityForScore(score),
      score,
      confidence: Math.max(0, Math.min(1, Number(path.confidence) || 0)),
      evidenceComplete: Boolean(path.evidence_complete ?? path.evidenceComplete),
      weaknessIds: [...new Set(linkedWeaknesses.map(item => item.id))],
      findingIds: [...ids].filter(Boolean)
    };
  });

  const highestScore = riskPaths.reduce((max, path) => Math.max(max, path.score), weaknesses.reduce((max, item) => Math.max(max, SEVERITY_SCORE[item.severity]), 0));
  const verifiedPaths = riskPaths.filter(path => path.status === 'VERIFIED').length;
  const potentialPaths = riskPaths.filter(path => path.status === 'POTENTIAL').length;
  const affectedFindingIds = new Set(riskPaths.flatMap(path => path.findingIds));

  return {
    riskLevel: severityForScore(highestScore),
    score: highestScore,
    findingCount: findings.length,
    weaknessCount: weaknesses.length,
    pathCount: riskPaths.length,
    verifiedPathCount: verifiedPaths,
    potentialPathCount: potentialPaths,
    correlatedFindingCount: affectedFindingIds.size,
    compromiseConfirmed: false,
    weaknesses,
    paths: riskPaths
  };
}
