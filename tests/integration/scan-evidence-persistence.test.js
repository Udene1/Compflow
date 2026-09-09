import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'crypto';
import pool, { initDb } from '../../core/db.js';
import { persistScanGraph, beginExecution } from '../../core/execution_worker_hooks.js';
import { ensureExecutionGraph } from '../../core/execution_engine.js';

const organizationId = `org_scan_evidence_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
const executionId = `scan_evidence_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
const connectionId = `conn_scan_evidence_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;

beforeAll(async () => {
    await initDb();
    await ensureExecutionGraph();
    await pool.query('INSERT INTO organizations (id,name) VALUES ($1,$2)', [organizationId, 'Scan Evidence Integration']);
    await pool.query('INSERT INTO cloud_connections (id,organization_id,provider,status) VALUES ($1,$2,$3,$4)', [connectionId, organizationId, 'aws', 'VERIFIED']);
    await beginExecution({ organizationId, executionId, provider: 'aws', clientId: 'scan-evidence-test', jobId: executionId, connectionId, scanId: executionId });
});

afterAll(async () => {
    await pool.query('DELETE FROM execution_evidence_records WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_attempts WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_events WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_graph_edges WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_graph_nodes WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM execution_runs WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM cloud_connections WHERE organization_id=$1', [organizationId]);
    await pool.query('DELETE FROM organizations WHERE id=$1', [organizationId]);
});

describe('Scan evidence persistence', () => {
    it('persists provider observation evidence with connection and execution lineage', async () => {
        await persistScanGraph({
            organizationId,
            executionId,
            provider: 'aws',
            connectionId,
            resources: [{
                id: 'real-resource-reference',
                name: 'evidence-persistence-resource',
                type: 'S3',
                technicalId: 'S3_PUBLIC',
                severity: 'high',
                status: 'FAIL',
                issue: 'Public access detected',
                controls: { soc2: ['CC6.1'] },
                observedAt: new Date().toISOString()
            }]
        });

        const evidence = await pool.query(
            `SELECT organization_id, execution_id, node_id, attempt_id, control_id, provider, connection_id,
                    resource_id, source_type, source_ref, evidence_kind, evidence_hash, evidence
             FROM execution_evidence_records
             WHERE organization_id=$1 AND execution_id=$2`,
            [organizationId, executionId]
        );

        expect(evidence.rows).toHaveLength(1);
        const row = evidence.rows[0];
        expect(row.organization_id).toBe(organizationId);
        expect(row.execution_id).toBe(executionId);
        expect(row.connection_id).toBe(connectionId);
        expect(row.control_id).toBe('CC6.1');
        expect(row.provider).toBe('aws');
        expect(row.source_type).toBe('cloud_scan');
        expect(row.source_ref).toBe(executionId);
        expect(row.evidence_kind).toBe('provider_observation');
        expect(row.evidence_hash).toMatch(/^[a-f0-9]{64}$/);
        expect(row.evidence.resource.id).toBe('real-resource-reference');
        expect(row.evidence.resource.technicalId).toBe('S3_PUBLIC');
    });
});
