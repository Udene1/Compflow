import { Router } from 'express';
import { redeemPilotInvitation } from '../core/pilot_invitations.js';

const router = Router();
const APP_URL = process.env.APP_URL || 'https://compflow.icu';

function setSessionCookie(res, token) {
    const production = process.env.NODE_ENV === 'production';
    const domain = production ? ' Domain=.compflow.icu;' : '';
    res.setHeader('Set-Cookie', `cf_session=${token}; HttpOnly; Secure; SameSite=Lax;${domain} Path=/; Max-Age=86400`);
}

const ERROR_STATUS = Object.freeze({
    PILOT_CODE_INVALID: 400,
    PILOT_EMAIL_INVALID: 400,
    PILOT_INVITATION_INVALID: 401,
    PILOT_INVITATION_UNAVAILABLE: 410,
    PILOT_EMAIL_MISMATCH: 403,
    PILOT_ACCOUNT_ALREADY_EXISTS: 409,
    PILOT_ACCOUNT_MISSING: 409,
    PILOT_ACCESS_EXPIRED: 410,
    PILOT_INVITATION_RACE_LOST: 409
});

function errorResponse(error) {
    const code = error?.code || error?.message || 'PILOT_AUTHENTICATION_FAILED';
    const status = ERROR_STATUS[code] || 500;
    const messages = {
        PILOT_CODE_INVALID: 'The pilot invitation code is invalid. Check the code and try again.',
        PILOT_EMAIL_INVALID: 'Enter a valid company email address.',
        PILOT_INVITATION_INVALID: 'This pilot invitation could not be authenticated.',
        PILOT_INVITATION_UNAVAILABLE: 'This pilot invitation is no longer available.',
        PILOT_EMAIL_MISMATCH: 'The company email does not match the pilot invitation.',
        PILOT_ACCOUNT_ALREADY_EXISTS: 'An account already exists for this email. Use the existing authentication method.',
        PILOT_ACCOUNT_MISSING: 'The pilot account could not be found. Contact team — kenneth@compflow.icu',
        PILOT_ACCESS_EXPIRED: 'Pilot access has expired. Contact team — kenneth@compflow.icu',
        PILOT_INVITATION_RACE_LOST: 'The pilot invitation changed while activation was in progress. Please try again.'
    };
    return {
        status,
        body: {
            error: code,
            code,
            message: status === 500 ? 'Pilot authentication could not be completed.' : messages[code],
            retryable: [409, 500, 503].includes(status)
        }
    };
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
        const result = errorResponse(error);
        if (result.status >= 500) console.error('[PILOT] Redemption failed:', error?.message || error);
        return res.status(result.status).json(result.body);
    }
});

router.get('/status', (req, res) => res.json({ enabled: true, appUrl: APP_URL, accessModel: 'time_limited_code_and_link' }));

export default router;
