import { describe, expect, it } from 'vitest';
import { buildPilotInvitationUrl, generatePilotCode, hashPilotCode, isPilotInvitationUsable, normalizePilotCode, pilotInvitationExpiry, validatePilotInvitationInput } from '../../core/pilot_invitations.js';

describe('pilot invitation security contract', () => {
    it('generates a high-entropy human-enterable code with the expected format', () => {
        const code = generatePilotCode();
        expect(code).toMatch(/^CFP-[A-Z0-9]{4}(?:-[A-Z0-9]{4}){4}$/);
        expect(normalizePilotCode(code)).toBe(code);
        expect(hashPilotCode(code)).toHaveLength(64);
    });

    it('does not generate the same code repeatedly', () => {
        const codes = new Set(Array.from({ length: 100 }, () => generatePilotCode()));
        expect(codes.size).toBe(100);
    });

    it('validates company email and bounded pilot duration', () => {
        expect(validatePilotInvitationInput({ email: '  Jane@Acme.com ', companyName: ' Acme  Security ', days: 30 })).toEqual({ email: 'jane@acme.com', companyName: 'Acme Security', days: 30 });
        expect(() => validatePilotInvitationInput({ email: 'not-an-email', companyName: 'Acme' })).toThrow('PILOT_EMAIL_INVALID');
        expect(() => validatePilotInvitationInput({ email: 'jane@acme.com', companyName: 'Acme', days: 91 })).toThrow('PILOT_DURATION_INVALID');
    });

    it('expires invitations server-side by timestamp', () => {
        const now = new Date('2026-09-09T12:00:00.000Z');
        const expiry = pilotInvitationExpiry(30, now);
        expect(isPilotInvitationUsable({ status: 'PENDING', redeemed_at: null, expires_at: expiry.toISOString() }, now)).toBe(true);
        expect(isPilotInvitationUsable({ status: 'PENDING', redeemed_at: null, expires_at: expiry.toISOString() }, new Date('2026-10-10T12:00:00.000Z'))).toBe(false);
        expect(isPilotInvitationUsable({ status: 'REDEEMED', redeemed_at: now.toISOString(), expires_at: expiry.toISOString() }, now)).toBe(false);
    });

    it('builds a trusted HTTPS activation destination from the configured app URL', () => {
        const url = buildPilotInvitationUrl('CFP-ABCD-EFGH-IJKL-MNOP-QRST', 'https://www.compflow.icu');
        expect(url).toBe('https://www.compflow.icu/pilot.html?code=CFP-ABCD-EFGH-IJKL-MNOP-QRST');
    });
});
