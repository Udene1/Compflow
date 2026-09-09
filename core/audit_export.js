import crypto from 'crypto';
import pool from './db.js';

const MAX_ROWS = 5000;

function hash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function requireContext({ organizationId, executionId }) {
  if (!organizationId || !executionId) throw new Error('AUDIT_EXPORT_INPUT_INVALID');
}

/**
 * Builds an auditor package entirely from durable Compflow state.
 * Caller-supplied findings/resources are deliberately not accepted: the export
 * must remain organization-scoped and traceable to provider-backed evidence.
 */
export async function buildAuditExport({ organizationId, executionId } = {}) {
  requireContext({ organizationId, executionId });

  const execution = await pool.query(
    `SELECT id, status, metadata, created_at, started_at, finished_at, error_code
       FROM execution_runs
      WHERE organization_id=$1 AND id=$2`,
    [organizationId, executionId]
  );
  if (!execution.rows[0]) throw new Error('EXECUTION_NOT_FOUND');

  const scanId = execution.rows[0].metadata?.scanId || execution.rows[0].metadata?.scan_id || null;
  const [events, evidence, paths, findings] = await Promise.all([
    pool.query(
      `SELECT id, sequence, event_type, actor_type, actor_id, result, payload, occurred_at
         FROM execution_events
        WHERE organization_id=$1 AND execution_id=$2
        ORDER BY sequence ASC LIMIT $3`,
      [organizationId, executionId, MAX_ROWS]
    ),
    pool.query(
      `SELECT id, node_id, attempt_id, control_id, provider, connection_id, resource_id,
              source_type, source_ref, collected_at, observed_at, freshness_expires_at,
              evidence_kind, evidence, evidence_hash, lineage
         FROM execution_evidence_records
        WHERE organization_id=$1 AND execution_id=$2
        ORDER BY collected_at ASC LIMIT $3`,
      [organizationId, executionId, MAX_ROWS]
    ),
    pool.query(
      `SELECT p.id, p.path_key, p.status, p.severity, p.confidence, p.title, p.summary,
              p.evidence_complete, p.observed_at, p.updated_at,
              COALESCE(jsonb_agg(DISTINCT n) FILTER (WHERE n.id IS NOT NULL),'[]'::jsonb) nodes,
              COALESCE(jsonb_agg(DISTINCT e) FILTER (WHERE e.id IS NOT NULL),'[]'::jsonb) edges
         FROM exposure_paths p
         LEFT JOIN exposure_path_nodes n ON n.path_id=p.id
         LEFT JOIN exposure_path_edges e ON e.path_id=p.id
        WHERE p.organization_id=$1 AND p.execution_id=$2
        GROUP BY p.id
        ORDER BY p.updated_at ASC LIMIT $3`,
      [organizationId, executionId, 1000]
    ),
    scanId
      ? pool.query(
          `SELECT id, scan_id, resource_id, control_id, severity, status, code, created_at
             FROM findings
            WHERE organization_id=$1 AND scan_id=$2
            ORDER BY created_at ASC LIMIT $3`,
          [organizationId, scanId, MAX_ROWS]
        )
      : Promise.resolve({ rows: [] })
  ]);

  const packageData = {
    schemaVersion: 'audit-export-v1',
    generatedAt: new Date().toISOString(),
    organizationId,
    execution: execution.rows[0],
    authoritativeScanId: scanId,
    findings: findings.rows,
    evidence: evidence.rows,
    exposurePaths: paths.rows,
    executionEvents: events.rows
  };

  const manifest = {
    schemaVersion: packageData.schemaVersion,
    organizationId,
    executionId,
    authoritativeScanId: scanId,
    executionStatus: execution.rows[0].status,
    findingCount: findings.rows.length,
    evidenceCount: evidence.rows.length,
    pathCount: paths.rows.length,
    eventCount: events.rows.length,
    evidenceHashes: evidence.rows.map(row => row.evidence_hash).filter(Boolean),
    eventHashes: events.rows.map(row => hash({ id: row.id, sequence: row.sequence, event_type: row.event_type, payload: row.payload })),
    contentHash: hash(packageData)
  };

  return Object.freeze({ manifest, data: packageData });
}
