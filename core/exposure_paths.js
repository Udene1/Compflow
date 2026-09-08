import crypto from 'crypto';
import pool from './db.js';

const MAX_PATHS = 100;
const MAX_DEPTH = 6;
const TERMINAL_RESOURCE_TYPES = new Set(['S3', 'RDS', 'DYNAMODB', 'KEYVAULT', 'SQL', 'SECRETS']);
const EXPOSURE_CODES = new Set([
  'S3_PUBLIC_ACCESS', 'AZURE_STORAGE_PUBLIC_BLOB', 'RDS_PUBLICLY_ACCESSIBLE', 'AZURE_SQL_PUBLIC_ACCESS',
  'SG_OPEN_SSH_WORLD', 'SG_OPEN_RDP_WORLD', 'SG_OPEN_HTTP_WORLD', 'AZURE_NSG_OPEN_INBOUND'
]);
const PRIVILEGE_CODES = new Set(['IAM_WILDCARD_PERMISSION', 'IAM_ROOT_KEYS']);
const SEVERITY_SCORE = Object.freeze({ LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 });

function clean(value, fallback = '') { return String(value ?? fallback).trim().slice(0, 255); }
function severity(value) { const normalized = clean(value, 'LOW').toUpperCase(); return SEVERITY_SCORE[normalized] ? normalized : 'LOW'; }
function scoreToSeverity(score) { return score >= 4 ? 'CRITICAL' : score === 3 ? 'HIGH' : score === 2 ? 'MEDIUM' : 'LOW'; }
function stableId(prefix, value) { return `${prefix}_${crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 32)}`; }

function resourceType(resource = {}) {
  const value = clean(resource.type || resource.resourceType || resource.kind || '').toUpperCase();
  if (value.includes('S3') || value.includes('BUCKET')) return 'S3';
  if (value.includes('RDS') || value.includes('DATABASE')) return 'RDS';
  if (value.includes('DYNAMO')) return 'DYNAMODB';
  if (value.includes('KEYVAULT') || value.includes('KEY VAULT')) return 'KEYVAULT';
  if (value.includes('SQL')) return 'SQL';
  if (value.includes('SECRET')) return 'SECRETS';
  if (value.includes('IAM') || value.includes('ROLE') || value.includes('USER')) return 'IAM';
  if (value.includes('EC2') || value.includes('VM') || value.includes('COMPUTE')) return 'COMPUTE';
  if (value.includes('SECURITY') || value.includes('FIREWALL') || value.includes('NSG')) return 'NETWORK';
  return value || 'RESOURCE';
}

function extractResources(row) {
  const evidence = row.evidence && typeof row.evidence === 'object' ? row.evidence : {};
  const candidates = Array.isArray(evidence.resources) ? evidence.resources : [];
  return candidates.filter(item => item && typeof item === 'object' && clean(item.id || item.resourceId));
}

function extractRelationships(row) {
  const evidence = row.evidence && typeof row.evidence === 'object' ? row.evidence : {};
  const candidates = [];
  if (Array.isArray(evidence.relationships)) candidates.push(...evidence.relationships.map(item => ({ ...item, evidenceId: row.id })));
  for (const resource of extractResources(row)) {
    if (Array.isArray(resource.relationships)) candidates.push(...resource.relationships.map(item => ({ ...item, evidenceId: row.id })));
  }
  return candidates.map(item => ({
    fromResourceId: clean(item.fromResourceId || item.from || item.sourceResourceId),
    toResourceId: clean(item.toResourceId || item.to || item.targetResourceId),
    relationship: clean(item.relationship || item.type || item.relation || 'RELATED_TO').toUpperCase(),
    verified: item.verified === true || String(item.status || '').toLowerCase() === 'verified',
    evidenceId: item.evidenceId
  })).filter(item => item.fromResourceId && item.toResourceId && item.fromResourceId !== item.toResourceId);
}

function isExposure(finding) { return EXPOSURE_CODES.has(clean(finding.code).toUpperCase()); }
function isPrivilege(finding) { return PRIVILEGE_CODES.has(clean(finding.code).toUpperCase()); }
function isTerminal(resource) { return TERMINAL_RESOURCE_TYPES.has(resource.type); }

function buildGraph(evidenceRows, findingRows) {
  const resources = new Map();
  const edges = [];
  const findingsByResource = new Map();
  const evidenceByResource = new Map();

  for (const finding of findingRows) {
    const id = clean(finding.resource_id);
    if (!id) continue;
    const list = findingsByResource.get(id) || [];
    list.push(finding);
    findingsByResource.set(id, list);
  }

  for (const row of evidenceRows) {
    const rowResources = extractResources(row);
    for (const item of rowResources) {
      const id = clean(item.id || item.resourceId);
      const existing = resources.get(id) || { id, type: resourceType(item), label: clean(item.name || item.label || id), evidenceIds: [] };
      existing.type = resourceType(item) || existing.type;
      existing.label = clean(item.name || item.label || existing.label);
      if (!existing.evidenceIds.includes(row.id)) existing.evidenceIds.push(row.id);
      resources.set(id, existing);
      const ids = evidenceByResource.get(id) || [];
      if (!ids.includes(row.id)) ids.push(row.id);
      evidenceByResource.set(id, ids);
    }
    edges.push(...extractRelationships(row));
  }

  // Findings may refer to resources that the evidence payload did not enumerate.
  // They remain nodes, but a path never becomes evidence-complete without evidence.
  for (const finding of findingRows) {
    const id = clean(finding.resource_id);
    if (!id) continue;
    if (!resources.has(id)) resources.set(id, { id, type: 'RESOURCE', label: id, evidenceIds: [] });
  }

  return { resources, edges, findingsByResource, evidenceByResource };
}

function findPaths(graph) {
  const { resources, edges, findingsByResource, evidenceByResource } = graph;
  const adjacency = new Map();
  for (const edge of edges) {
    const list = adjacency.get(edge.fromResourceId) || [];
    list.push(edge);
    adjacency.set(edge.fromResourceId, list);
  }

  const starts = [...resources.values()].filter(resource => (findingsByResource.get(resource.id) || []).some(isExposure));
  const paths = [];
  const seen = new Set();

  function walk(resourceId, nodes, traversedEdges, visited) {
    if (nodes.length > MAX_DEPTH) return;
    const resource = resources.get(resourceId);
    if (!resource) return;
    const nextFindings = findingsByResource.get(resourceId) || [];
    const terminal = isTerminal(resource) && (nextFindings.length > 0 || resource.type !== 'RESOURCE');
    const privileged = nextFindings.some(isPrivilege);
    if ((terminal || privileged) && nodes.length > 1) {
      const pathKey = nodes.map(node => node.id).join('>');
      if (!seen.has(pathKey)) {
        seen.add(pathKey);
        const allNodeEvidence = nodes.every(node => (evidenceByResource.get(node.id) || []).length > 0);
        const allEdgeEvidence = traversedEdges.every(edge => Boolean(edge.evidenceId));
        const maxFinding = nodes.flatMap(node => findingsByResource.get(node.id) || []).reduce((max, finding) => Math.max(max, SEVERITY_SCORE[severity(finding.severity)]), 1);
        const verifiedEdges = traversedEdges.filter(edge => edge.verified).length;
        const confidence = Math.min(1, 0.25 + (allNodeEvidence ? 0.25 : 0) + (allEdgeEvidence ? 0.25 : 0) + (verifiedEdges === traversedEdges.length && traversedEdges.length ? 0.25 : 0));
        const status = traversedEdges.length && traversedEdges.every(edge => edge.verified) && allNodeEvidence ? 'VERIFIED' : 'POTENTIAL';
        paths.push({
          pathKey,
          status,
          severity: scoreToSeverity(maxFinding),
          confidence,
          evidenceComplete: allNodeEvidence && allEdgeEvidence,
          nodes: nodes.map(node => ({ ...node, findingIds: (findingsByResource.get(node.id) || []).map(f => f.id), evidenceIds: evidenceByResource.get(node.id) || [] })),
          edges: traversedEdges,
          title: `Potential exposure path: ${nodes.map(node => node.type).join(' → ')}`,
          summary: `${nodes.map(node => node.label).join(' → ')}. This is an evidence-backed security path candidate, not a claim of compromise.`
        });
      }
    }
    if (nodes.length === MAX_DEPTH) return;
    for (const edge of adjacency.get(resourceId) || []) {
      if (visited.has(edge.toResourceId)) continue;
      const target = resources.get(edge.toResourceId);
      if (!target) continue;
      walk(edge.toResourceId, [...nodes, target], [...traversedEdges, edge], new Set([...visited, edge.toResourceId]));
    }
  }

  for (const start of starts) walk(start.id, [start], [], new Set([start.id]));
  return paths.slice(0, MAX_PATHS);
}

export function analyzeExposurePaths({ evidenceRows = [], findingRows = [] } = {}) {
  return findPaths(buildGraph(evidenceRows, findingRows));
}

export async function ensureExposurePathSchema() {
  await pool.query('SELECT 1 FROM exposure_paths LIMIT 0');
  await pool.query('SELECT 1 FROM exposure_path_nodes LIMIT 0');
  await pool.query('SELECT 1 FROM exposure_path_edges LIMIT 0');
}

export async function analyzeExecutionExposurePaths({ organizationId, executionId } = {}) {
  if (!organizationId || !executionId) throw new Error('EXPOSURE_PATH_INPUT_INVALID');
  await ensureExposurePathSchema();
  const evidence = await pool.query('SELECT * FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2 ORDER BY collected_at ASC', [organizationId, executionId]);
  const execution = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
  const scanId = execution.rows[0]?.metadata?.scanId || execution.rows[0]?.metadata?.scan_id || null;
  const findings = scanId
    ? await pool.query('SELECT * FROM findings WHERE organization_id=$1 AND scan_id=$2 ORDER BY created_at ASC', [organizationId, scanId])
    : await pool.query(`SELECT f.* FROM findings f JOIN scans s ON s.id=f.scan_id WHERE f.organization_id=$1 AND s.connection_id IN (SELECT DISTINCT connection_id FROM execution_evidence_records WHERE organization_id=$1 AND execution_id=$2) ORDER BY f.created_at ASC`, [organizationId, executionId]);
  const paths = analyzeExposurePaths({ evidenceRows: evidence.rows, findingRows: findings.rows });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM exposure_paths WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
    for (const path of paths) {
      const pathId = stableId('path', `${organizationId}:${executionId}:${path.pathKey}`);
      await client.query(`INSERT INTO exposure_paths (id,organization_id,execution_id,path_key,status,severity,confidence,title,summary,evidence_complete,observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())`, [pathId, organizationId, executionId, path.pathKey, path.status, path.severity, path.confidence, path.title, path.summary, path.evidenceComplete]);
      const nodeIds = [];
      for (let index = 0; index < path.nodes.length; index += 1) {
        const node = path.nodes[index];
        const nodeId = stableId('pathnode', `${pathId}:${index}:${node.id}`);
        nodeIds.push(nodeId);
        await client.query(`INSERT INTO exposure_path_nodes (id,path_id,position,node_type,resource_id,label,observed,finding_ids,evidence_ids,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb)`, [nodeId, pathId, index, node.type, node.id, node.label, node.evidenceIds.length > 0, JSON.stringify(node.findingIds), JSON.stringify(node.evidenceIds), JSON.stringify({ exposure: (findingsByResource(path, node.id).some(isExposure)), privilege: findingsByResource(path, node.id).some(isPrivilege) })]);
      }
      for (let index = 0; index < path.edges.length; index += 1) {
        const edge = path.edges[index];
        const fromIndex = path.nodes.findIndex(node => node.id === edge.fromResourceId);
        const toIndex = path.nodes.findIndex(node => node.id === edge.toResourceId);
        if (fromIndex < 0 || toIndex < 0) continue;
        await client.query(`INSERT INTO exposure_path_edges (id,path_id,position,from_node_id,to_node_id,relationship,evidence_ids,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)`, [stableId('pathedge', `${pathId}:${index}`), pathId, index, nodeIds[fromIndex], nodeIds[toIndex], edge.relationship, JSON.stringify(edge.evidenceId ? [edge.evidenceId] : []), JSON.stringify({ verified: edge.verified })]);
      }
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
  return getExecutionExposurePaths({ organizationId, executionId });
}

function findingsByResource(path, resourceId) {
  return path.nodes.find(node => node.id === resourceId)?.findings || [];
}

export async function getExecutionExposurePaths({ organizationId, executionId, limit = 100 } = {}) {
  if (!organizationId || !executionId) throw new Error('EXPOSURE_PATH_INPUT_INVALID');
  await ensureExposurePathSchema();
  const paths = await pool.query('SELECT * FROM exposure_paths WHERE organization_id=$1 AND execution_id=$2 ORDER BY CASE severity WHEN \'CRITICAL\' THEN 4 WHEN \'HIGH\' THEN 3 WHEN \'MEDIUM\' THEN 2 ELSE 1 END DESC, updated_at DESC LIMIT $3', [organizationId, executionId, Math.max(1, Math.min(Number(limit) || 100, 100))]);
  if (!paths.rows.length) return [];
  const ids = paths.rows.map(row => row.id);
  const nodes = await pool.query('SELECT * FROM exposure_path_nodes WHERE path_id = ANY($1::text[]) ORDER BY path_id, position', [ids]);
  const edges = await pool.query('SELECT * FROM exposure_path_edges WHERE path_id = ANY($1::text[]) ORDER BY path_id, position', [ids]);
  return paths.rows.map(path => ({ ...path, confidence: Number(path.confidence), nodes: nodes.rows.filter(node => node.path_id === path.id), edges: edges.rows.filter(edge => edge.path_id === path.id) }));
}
