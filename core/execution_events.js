import pool from './db.js';
import crypto from 'crypto';

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS execution_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  execution_id TEXT NOT NULL,
  node_id TEXT,
  attempt_id TEXT,
  sequence BIGINT GENERATED ALWAYS AS IDENTITY,
  event_type TEXT NOT NULL,
  actor_type TEXT NOT NULL DEFAULT 'SYSTEM',
  actor_id TEXT,
  result TEXT,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, id)
);
CREATE INDEX IF NOT EXISTS execution_events_execution_sequence_idx ON execution_events (organization_id, execution_id, sequence);
CREATE INDEX IF NOT EXISTS execution_events_execution_time_idx ON execution_events (organization_id, execution_id, occurred_at, sequence);
CREATE INDEX IF NOT EXISTS execution_events_node_idx ON execution_events (organization_id, execution_id, node_id, sequence);
`;

let schemaPromise;

async function ensureSchema() {
  if (!schemaPromise) schemaPromise = pool.query(SCHEMA_SQL).catch(error => { schemaPromise = null; throw error; });
  return schemaPromise;
}

function sanitize(value) {
  if (Array.isArray(value)) return value.slice(0, 100).map(sanitize);
  if (!value || typeof value !== 'object') return typeof value === 'string' ? value.slice(0, 2000) : value;
  const blocked = /^(authorization|token|secret|password|client_secret|api[_-]?key|credential|private[_-]?key)$/i;
  return Object.fromEntries(Object.entries(value).filter(([key]) => !blocked.test(key)).slice(0, 100).map(([key, val]) => [key, sanitize(val)]));
}

function eventId({ organizationId, executionId, nodeId, attemptId, eventType, idempotencyKey }) {
  const basis = [organizationId, executionId, nodeId || '', attemptId || '', eventType, idempotencyKey || crypto.randomUUID()].join(':');
  return `event_${crypto.createHash('sha256').update(basis).digest('hex')}`;
}

export async function ensureExecutionEventsSchema() { await ensureSchema(); }

export async function appendExecutionEvent({ organizationId, executionId, nodeId = null, attemptId = null, eventType, actorType = 'SYSTEM', actorId = null, result = null, payload = {}, idempotencyKey = null } = {}) {
  await ensureSchema();
  if (!organizationId || !executionId || !eventType) throw new Error('EXECUTION_EVENT_INPUT_INVALID');
  const id = eventId({ organizationId, executionId, nodeId, attemptId, eventType, idempotencyKey });
  const resultRow = await pool.query(
    `INSERT INTO execution_events (id, organization_id, execution_id, node_id, attempt_id, event_type, actor_type, actor_id, result, payload)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
     ON CONFLICT (id) DO NOTHING
     RETURNING *`,
    [id, organizationId, executionId, nodeId, attemptId, eventType, String(actorType).slice(0, 50), actorId ? String(actorId).slice(0, 200) : null, result ? String(result).slice(0, 50) : null, JSON.stringify(sanitize(payload))]
  );
  if (resultRow.rows[0]) return resultRow.rows[0];
  const existing = await pool.query('SELECT * FROM execution_events WHERE id=$1', [id]);
  return existing.rows[0];
}

export async function listExecutionEvents({ organizationId, executionId, afterSequence = 0, limit = 200 } = {}) {
  await ensureSchema();
  if (!organizationId || !executionId) throw new Error('EXECUTION_EVENT_INPUT_INVALID');
  const boundedLimit = Math.max(1, Math.min(Number(limit) || 200, 1000));
  const result = await pool.query(
    `SELECT * FROM execution_events WHERE organization_id=$1 AND execution_id=$2 AND sequence>$3 ORDER BY sequence ASC LIMIT $4`,
    [organizationId, executionId, String(afterSequence || 0), boundedLimit]
  );
  return result.rows;
}

export async function getLatestExecutionEventSequence(organizationId, executionId) {
  await ensureSchema();
  const result = await pool.query('SELECT COALESCE(MAX(sequence),0) AS sequence FROM execution_events WHERE organization_id=$1 AND execution_id=$2', [organizationId, executionId]);
  return result.rows[0]?.sequence || '0';
}
