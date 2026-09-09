import { Router } from 'express';
import { validateSessionToken } from '../core/auth.js';
import { createPilotInvitation, listPilotInvitations, revokePilotInvitation } from '../core/pilot_invitations.js';

const router = Router();

function cookies(header = '') {
    return Object.fromEntries(String(header).split(';').map(v => v.trim()).filter(Boolean).map(v => { const i = v.indexOf('='); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))]; }));
}

async function requirePlatformAdmin(req, res, next) {
    const cookie = cookies(req.headers.cookie || '');
    const bearer = req.headers.authorization;
    const token = cookie.cf_session || (typeof bearer === 'string' && /^Bearer\s+\S+$/i.test(bearer) ? bearer.replace(/^Bearer\s+/i, '') : null);
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const session = await validateSessionToken(token);
    if (!session.valid || !session.user) return res.status(401).json({ error: 'Unauthorized' });
    const admins = String(process.env.COMPFLOW_PLATFORM_ADMINS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
    if (!admins.length || !admins.includes(String(session.user.email || '').toLowerCase())) return res.status(403).json({ error: 'PLATFORM_ADMIN_REQUIRED' });
    req.user = session.user;
    next();
}

router.use(requirePlatformAdmin);

router.get('/', async (req, res, next) => {
    try { return res.json({ invitations: await listPilotInvitations() }); } catch (error) { return next(error); }
});

router.post('/', async (req, res, next) => {
    try {
        const result = await createPilotInvitation({ ...req.body, createdByUserId: req.user.userId, req });
        return res.status(201).json(result);
    } catch (error) {
        const status = { PILOT_EMAIL_INVALID: 400, PILOT_COMPANY_REQUIRED: 400, PILOT_DURATION_INVALID: 400 }[error?.message] || 500;
        return res.status(status).json({ error: error?.message || 'PILOT_INVITATION_CREATE_FAILED' });
    }
});

router.post('/:id/revoke', async (req, res, next) => {
    try { return res.json({ invitation: await revokePilotInvitation(req.params.id, req.user.userId, req) }); } catch (error) {
        if (error?.message === 'PILOT_INVITATION_NOT_REVOCABLE') return res.status(409).json({ error: error.message });
        return next(error);
    }
});

export default router;
