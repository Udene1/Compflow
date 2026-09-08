import crypto from 'crypto';
import pool from './db.js';

function lockKey(organizationId, executionId, remediationId) {
  const digest = crypto.createHash('sha256').update(`${organizationId}:${executionId}:${remediationId}`).digest();
  return digest.readInt32BE(0);
}

/**
 * Serialize a single remediation mutation with a PostgreSQL advisory transaction
 * lock. Redis/queue state is deliberately not used as the source of truth.
 * The organization is part of the key so equal identifiers across tenants can
 * never contend with or accidentally serialize against another tenant's work.
 */
export async function withRemediationExecutionLock({ organizationId, executionId, remediationId }, work) {
  if (!organizationId || !executionId || !remediationId || typeof work !== 'function') {
    throw new Error('REMEDIATION_LOCK_INPUT_INVALID');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [lockKey(organizationId, executionId, remediationId)]);
    const result = await work();
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}
