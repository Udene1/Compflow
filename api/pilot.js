import { Router } from 'express';
import { redeemPilotInvitation } from '../core/pilot_invitations.js';

const router = Router();
const APP_URL = process.env.APP_URL || 'https://compflow.icu';

function setSessionCookie(res, token) {
    const production = process.env.NODE_ENV === 'production';
    const domain = production ? ' Domain=.compflow.icu;' : '';
    res.setHeader('Set-Cookie', `cf_session=${token}; HttpOnly; Secure; SameSite=Lax;${domain} Path=/; Max-Age=86400`);
}

router.post('/redeem', async (req, res) => {
    try {
        const { code, email, name } = req.body || {};
        const result = await redeemPilotInvitation({ code, email, name, req });
        setSessionCookie(res, result.session.token);
        return res.json({
            success: true,
            user: result.session.payload,
            organization: result.org,
            pilot: {
                expiresAt: result.expiresAt,
                invitationId: result.invitationId,
                firstActivation: result.firstActivation
            }
        });
    } catch (error) {
        const status = {
            PILOT_CODE_INVALID: 400,
            PILOT_EMAIL_INVALID: 400,
            PILOT_INVITATION_INVALID: 401,
            PILOT_INVITATION_UNAVAILABLE: 410,
            PILOT_EMAIL_MISMATCH: 403,
            PILOT_ACCOUNT_ALREADY_EXISTS: 409,
            PILOT_ACCOUNT_MISSING: 409,
            PILOT_ACCESS_EXPIRED: 410,
            PILOT_INVITATION_RACE_LOST: 409
        }[error?.message] || 500;
        return res.status(status).json({
            error: error?.message || 'PILOT_AUTHENTICATION_FAILED',
            message: status === 500 ? 'Pilot authentication could not be completed.' : undefined
        });
    }
});

router.get('/status', (req, res) => res.json({ enabled: true, appUrl: APP_URL, accessModel: 'time_limited_code_and_link' }));

export default router;
