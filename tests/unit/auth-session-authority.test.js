import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import crypto from 'crypto';
import pool from '../../core/db.js';
import { createSessionToken, validateSessionToken, ROLES } from '../../core/auth.js';

const organizationId = 'org_auth_authority_test';
const userId = 'usr_auth_authority_test';

async function createPrincipal() {
  await pool.query(`
    INSERT INTO users (id, email, name)
    VALUES ($1, $2, $3)
    ON CONFLICT (id) DO NOTHING
  `, [userId, 'auth-authority@compflow.test', 'Auth Authority Test']);

  await pool.query(`
    INSERT INTO organizations (id, name, domain)
    VALUES ($1, $2, $3)
    ON CONFLICT (id) DO NOTHING
  `, [organizationId, 'Auth Authority Test', 'compflow.test']);

  await pool.query(`
    INSERT INTO org_memberships (user_id, org_id, role)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role
  `, [userId, organizationId, ROLES.ADMIN]);
}

describe('Authoritative PostgreSQL session validation', () => {
  beforeAll(async () => {
    await createPrincipal();
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
  });

  afterAll(async () => {
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
  });

  it('rejects a cryptographically valid token after its authoritative session row is deleted', async () => {
    const session = await createSessionToken(
      { id: userId, email: 'auth-authority@compflow.test', name: 'Auth Authority Test' },
      { id: organizationId, name: 'Auth Authority Test' },
      ROLES.ADMIN,
      1
    );

    expect((await validateSessionToken(session.token)).valid).toBe(true);
    await pool.query('DELETE FROM sessions WHERE id = $1', [session.payload.sessionId]);

    const result = await validateSessionToken(session.token);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('not present in authoritative storage');
  });

  it('rejects a session revoked in PostgreSQL even when the signed token remains unchanged', async () => {
    const session = await createSessionToken(
      { id: userId, email: 'auth-authority@compflow.test', name: 'Auth Authority Test' },
      { id: organizationId, name: 'Auth Authority Test' },
      ROLES.ADMIN,
      1
    );

    await pool.query('UPDATE sessions SET is_revoked = true WHERE id = $1', [session.payload.sessionId]);

    const result = await validateSessionToken(session.token);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('revoked');
  });

  it('rejects a validly signed token whose claims no longer match authoritative role state', async () => {
    const session = await createSessionToken(
      { id: userId, email: 'auth-authority@compflow.test', name: 'Auth Authority Test' },
      { id: organizationId, name: 'Auth Authority Test' },
      ROLES.ADMIN,
      1
    );

    await pool.query('UPDATE sessions SET role = $1 WHERE id = $2', [ROLES.VIEWER, session.payload.sessionId]);

    const result = await validateSessionToken(session.token);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('claims do not match authoritative state');
  });

  it('rejects a forged token with a malformed signature length without throwing', async () => {
    const session = await createSessionToken(
      { id: userId, email: 'auth-authority@compflow.test', name: 'Auth Authority Test' },
      { id: organizationId, name: 'Auth Authority Test' },
      ROLES.ADMIN,
      1
    );
    const decoded = JSON.parse(Buffer.from(session.token, 'base64url').toString('utf8'));
    decoded.signature = crypto.randomBytes(3).toString('hex');
    const forged = Buffer.from(JSON.stringify(decoded)).toString('base64url');

    const result = await validateSessionToken(forged);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid or forged session token signature');
  });
});
