import crypto from 'crypto';
import pool from './db.js';
import { createSessionToken, ROLES } from './auth.js';
import { recordAuditEvent } from './audit_events.js';

export const PILOT_INVITATION_STATUS = Object.freeze({ PENDING: 'PENDING', REDEEMED: 'REDEEMED', EXPIRED: 'EXPIRED', REVOKED: 'REVOKED' });
const CODE_PATTERN = /^CFP-[A-Z0-9]{4}(?:-[A-Z0-9]{4}){4}$/;
const DEFAULT_DAYS = 30;
const emailOf = value => String(value || '').trim().toLowerCase();
const companyOf = value => String(value || '').trim().replace(/\s+/g, ' ').slice(0, 255);
const hash = value => crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');

export function normalizePilotCode(code) {
    const value = String(code || '').trim().toUpperCase();
    if (!CODE_PATTERN.test(value)) throw new Error('PILOT_CODE_INVALID');
    return value;
}
export function hashPilotCode(code) { return hash(normalizePilotCode(code)); }
export function generatePilotCode() {
    const raw = crypto.randomBytes(20).toString('base64url').toUpperCase().replace(/[^A-Z0-9]/g, '').padEnd(20, 'X').slice(0, 20);
    return `CFP-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}`;
}
export function buildPilotInvitationUrl(code, appUrl = process.env.APP_URL || 'https://compflow.icu') {
    return `${String(appUrl).replace(/\/$/, '')}/pilot.html?code=${encodeURIComponent(normalizePilotCode(code))}`;
}
export function pilotInvitationExpiry(days = DEFAULT_DAYS, now = new Date()) {
    const n = Number(days);
    if (!Number.isInteger(n) || n < 1 || n > 90) throw new Error('PILOT_DURATION_INVALID');
    const timestamp = new Date(now).getTime();
    if (!Number.isFinite(timestamp)) throw new Error('PILOT_CLOCK_INVALID');
    return new Date(timestamp + n * 86400000);
}
export function validatePilotInvitationInput({ email, companyName, days = DEFAULT_DAYS } = {}) {
    const normalizedEmail = emailOf(email);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) throw new Error('PILOT_EMAIL_INVALID');
    const normalizedCompany = companyOf(companyName);
    if (!normalizedCompany) throw new Error('PILOT_COMPANY_REQUIRED');
    return Object.freeze({ email: normalizedEmail, companyName: normalizedCompany, days: Number(days) });
}
export function isPilotInvitationUsable(row, now = new Date()) {
    if (!row || row.status !== 'PENDING' || row.redeemed_at) return false;
    const expires = new Date(row.expires_at).getTime();
    return Number.isFinite(expires) && expires > new Date(now).getTime();
}

export async function createPilotInvitation({ email, companyName, days = DEFAULT_DAYS, createdByUserId, req = null }) {
    if (!createdByUserId) throw new Error('PILOT_CREATOR_REQUIRED');
    const input = validatePilotInvitationInput({ email, companyName, days });
    const code = generatePilotCode();
    const invitationId = `pinv_${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}`;
    const expiresAt = pilotInvitationExpiry(input.days);
    const result = await pool.query(
        `INSERT INTO pilot_invitations (id, token_hash, email, email_domain, company_name, created_by_user_id, expires_at, status, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'PENDING',$8::jsonb)
         RETURNING id,email,email_domain,company_name,created_by_user_id,created_at,expires_at,status`,
        [invitationId, hash(code), input.email, input.email.split('@')[1], input.companyName, createdByUserId, expiresAt.toISOString(), JSON.stringify({ pilotDays: input.days, accessModel: 'unique_pilot_invitation' })]
    );
    await recordAuditEvent(null, createdByUserId, 'pilot_invitation_created', 'pilot_invitation', invitationId, { email: input.email, emailDomain: input.email.split('@')[1], companyName: input.companyName, expiresAt: expiresAt.toISOString(), pilotDays: input.days }, req);
    return { invitation: result.rows[0], code, url: buildPilotInvitationUrl(code) };
}

export async function listPilotInvitations(limit = 100) {
    const result = await pool.query(`SELECT id,email,email_domain,company_name,created_by_user_id,created_at,expires_at,redeemed_at,redeemed_by_user_id,organization_id,status,metadata FROM pilot_invitations ORDER BY created_at DESC LIMIT $1`, [Math.max(1, Math.min(Number(limit) || 100, 200))]);
    return result.rows;
}

export async function revokePilotInvitation(invitationId, actorUserId, req = null) {
    const result = await pool.query(`UPDATE pilot_invitations SET status='REVOKED',revoked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND status='PENDING' AND redeemed_at IS NULL RETURNING id,email,company_name,status,expires_at`, [invitationId]);
    if (!result.rows.length) throw new Error('PILOT_INVITATION_NOT_REVOCABLE');
    await recordAuditEvent(null, actorUserId, 'pilot_invitation_revoked', 'pilot_invitation', invitationId, { email: result.rows[0].email, companyName: result.rows[0].company_name }, req);
    return result.rows[0];
}

export async function redeemPilotInvitation({ code, email, name, req = null }) {
    const normalizedCode = normalizePilotCode(code);
    const normalizedEmail = emailOf(email);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) throw new Error('PILOT_EMAIL_INVALID');
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const invitationRes = await client.query('SELECT * FROM pilot_invitations WHERE token_hash=$1 FOR UPDATE', [hash(normalizedCode)]);
        const invitation = invitationRes.rows[0];
        if (!invitation) throw new Error('PILOT_INVITATION_INVALID');
        if (!isPilotInvitationUsable(invitation)) {
            if (invitation.status === 'PENDING' && new Date(invitation.expires_at).getTime() <= Date.now()) await client.query("UPDATE pilot_invitations SET status='EXPIRED',updated_at=CURRENT_TIMESTAMP WHERE id=$1", [invitation.id]);
            throw new Error('PILOT_INVITATION_UNAVAILABLE');
        }
        if (emailOf(invitation.email) !== normalizedEmail) throw new Error('PILOT_EMAIL_MISMATCH');
        const existing = await client.query('SELECT id FROM users WHERE email=$1 FOR UPDATE', [normalizedEmail]);
        if (existing.rows.length) throw new Error('PILOT_ACCOUNT_ALREADY_EXISTS');
        const domain = normalizedEmail.split('@')[1];
        const userId = `usr_${crypto.randomUUID().replace(/-/g, '').slice(0,16)}`;
        const orgId = `org_${crypto.randomUUID().replace(/-/g, '').slice(0,16)}`;
        const identityId = `idn_${crypto.randomUUID().replace(/-/g, '').slice(0,16)}`;
        const displayName = String(name || normalizedEmail.split('@')[0]).trim().slice(0,255) || normalizedEmail.split('@')[0];
        await client.query('INSERT INTO users(id,email,name,avatar_url) VALUES($1,$2,$3,$4)', [userId,normalizedEmail,displayName,'']);
        await client.query('INSERT INTO organizations(id,name,domain,sso_provider) VALUES($1,$2,$3,$4)', [orgId,invitation.company_name,domain,'pilot_invitation']);
        await client.query('INSERT INTO identities(id,user_id,provider,provider_subject,provider_email) VALUES($1,$2,$3,$4,$5)', [identityId,userId,'pilot_invitation',invitation.id,normalizedEmail]);
        await client.query('INSERT INTO org_memberships(user_id,org_id,role) VALUES($1,$2,$3)', [userId,orgId,ROLES.OWNER]);
        await client.query("INSERT INTO onboarding_state(org_id,status) VALUES($1,'INVITED')", [orgId]);
        await client.query(`INSERT INTO organization_entitlements(organization_id,plan,status,source,starts_at,expires_at,metadata,updated_at) VALUES($1,'pilot','PILOT','pilot_invitation',CURRENT_TIMESTAMP,$2,$3::jsonb,CURRENT_TIMESTAMP)`, [orgId, invitation.expires_at, JSON.stringify({ invitationId: invitation.id, companyName: invitation.company_name })]);
        const redeemed = await client.query(`UPDATE pilot_invitations SET status='REDEEMED',redeemed_at=CURRENT_TIMESTAMP,redeemed_by_user_id=$2,organization_id=$3,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND status='PENDING' AND redeemed_at IS NULL RETURNING id`, [invitation.id,userId,orgId]);
        if (!redeemed.rows.length) throw new Error('PILOT_INVITATION_RACE_LOST');
        await client.query('COMMIT');
        const user = { id:userId,email:normalizedEmail,name:displayName,avatarUrl:'' };
        const org = { id:orgId,name:invitation.company_name,domain };
        const session = await createSessionToken(user,org,ROLES.OWNER,1);
        await recordAuditEvent(orgId,userId,'pilot_invitation_redeemed','pilot_invitation',invitation.id,{ companyName:invitation.company_name,emailDomain:domain,organizationId:orgId,entitlement:'pilot' },req);
        return { user,org,role:ROLES.OWNER,session,invitationId:invitation.id,expiresAt:invitation.expires_at };
    } catch (error) { await client.query('ROLLBACK').catch(()=>{}); throw error; }
    finally { client.release(); }
}
