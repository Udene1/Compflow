import crypto from 'crypto';
import pool from './db.js';

const MAX_STRING = 256;
const MAX_TARGETS = 100;
const MODES = new Set(['AUDIT', 'REMEDIATE']);

function requiredString(value, code, max = MAX_STRING) {
  if (typeof value !== 'string' || value.trim().length < 1 || value.length > max) throw new Error(code);
  return value.trim();
}

function normalizeTargets(targets) {
  if (!Array.isArray(targets) || targets.length < 1 || targets.length > MAX_TARGETS) throw new Error('INTENT_TARGETS_INVALID');
  return targets.map((target, index) => ({
    connectionId: requiredString(target?.connectionId, `INTENT_TARGET_CONNECTION_INVALID:${index}`),
    provider: requiredString(target?.provider, `INTENT_TARGET_PROVIDER_INVALID:${index}`).toLowerCase(),
    resourceId: target?.resourceId == null ? null : requiredString(target.resourceId, `INTENT_TARGET_RESOURCE_INVALID:${index}`)
  }));
}

function canonical(value) { return JSON.stringify(value); }

export function normalizeIntent({ organizationId, intent, targets } = {}) {
  requiredString(organizationId, 'INTENT_ORGANIZATION_REQUIRED');
  if (!intent || typeof intent !== 'object' || Array.isArray(intent)) throw new Error('INTENT_INVALID');
  const normalized = {
    intentVersion: 1,
    id: requiredString(intent.id, 'INTENT_ID_INVALID'),
    version: requiredString(String(intent.version ?? ''), 'INTENT_VERSION_INVALID', 32),
    objective: requiredString(intent.objective, 'INTENT_OBJECTIVE_INVALID', MAX_STRING),
    mode: intent.mode || 'AUDIT',
    frameworks: Array.isArray(intent.frameworks) ? [...new Set(intent.frameworks.map(value => requiredString(value, 'INTENT_FRAMEWORK_INVALID', 64).toLowerCase()))] : [],
    rules: Array.isArray(intent.rules) ? intent.rules : [],
    constraints: intent.constraints && typeof intent.constraints === 'object' && !Array.isArray(intent.constraints) ? intent.constraints : {},
    targets: normalizeTargets(targets || intent.targets)
  };
  if (!MODES.has(normalized.mode)) throw new Error('INTENT_MODE_INVALID');
  if (!normalized.frameworks.length) throw new Error('INTENT_FRAMEWORKS_INVALID');
  const hash = crypto.createHash('sha256').update(canonical(normalized)).digest('hex');
  return { ...normalized, intentHash: hash };
}

export async function ensureIntentSchema() {
  await pool.query(`CREATE TABLE IF NOT EXISTS compliance_intents (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    intent JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, intent_id, intent_version),
    UNIQUE (organization_id, intent_hash)
  );`);
}

export async function persistIntent({ organizationId, intent, client = null } = {}) {
  await ensureIntentSchema();
  const normalized = normalizeIntent({ organizationId, intent: intent.intent || intent, targets: intent.targets });
  const db = client || pool;
  const existing = await db.query('SELECT * FROM compliance_intents WHERE organization_id=$1 AND intent_id=$2 AND intent_version=$3 FOR UPDATE', [organizationId, normalized.id, normalized.version]);
  if (existing.rows[0]) {
    if (existing.rows[0].intent_hash !== normalized.intentHash) throw new Error('INTENT_IMMUTABLE');
    return existing.rows[0];
  }
  const id = `intent_${crypto.createHash('sha256').update(`${organizationId}:${normalized.id}:${normalized.version}`).digest('hex').slice(0, 32)}`;
  const result = await db.query(`INSERT INTO compliance_intents (id,organization_id,intent_id,intent_version,intent_hash,intent) VALUES ($1,$2,$3,$4,$5,$6::jsonb) RETURNING *`, [id, organizationId, normalized.id, normalized.version, normalized.intentHash, canonical(normalized)]);
  return result.rows[0];
}

export function intentToPolicy(intent) {
  const normalized = intent.intent || intent;
  return {
    id: normalized.id,
    version: normalized.version,
    frameworks: normalized.frameworks,
    mode: normalized.mode,
    rules: normalized.rules
  };
}
