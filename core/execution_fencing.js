import pool from './db.js';

export async function assertExecutionLease({ organizationId, executionId, workerId, leaseToken }) {
  if (!organizationId || !executionId || !workerId || !leaseToken) throw new Error('EXECUTION_LEASE_INPUT_INVALID');
  const result = await pool.query(
    `SELECT id, status, lease_owner, lease_token, lease_expires_at, version
       FROM execution_runs
      WHERE id=$1
        AND organization_id=$2
        AND status='RUNNING'
        AND lease_owner=$3
        AND lease_token=$4
        AND lease_expires_at>NOW()`,
    [executionId, organizationId, workerId, leaseToken]
  );
  if (!result.rows[0]) throw new Error('EXECUTION_LEASE_LOST');
  return result.rows[0];
}
