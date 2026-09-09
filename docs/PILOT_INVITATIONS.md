# Compflow pilot invitations

Pilot access is issued per company through a unique invitation. The retired global `PILOT_ACCESS_CODE` is not a customer access path.

## Operator flow

1. A company contacts Compflow about the pilot.
2. A platform administrator opens `/pilot-admin.html` while signed in with an email listed in `COMPFLOW_PLATFORM_ADMINS`.
3. Enter the company name, company email and pilot duration.
4. The console generates a unique invitation **code and link**.
5. Send both to the prospect. The link is convenient; the code can be entered manually at `/pilot.html`.
6. The invitation is single-use and expires at the configured timestamp.
7. Successful redemption creates the organization, owner membership, onboarding state and PILOT entitlement atomically.

## Security properties

- Code entropy comes from Node's cryptographic random generator.
- Only a SHA-256 hash of the code is persisted.
- The invitation is bound to the normalized invited email.
- PostgreSQL is authoritative for redemption and entitlement state.
- `SELECT ... FOR UPDATE` plus the conditional redemption update prevents double redemption.
- A redeemed, expired or revoked invitation cannot be reused.
- Invitation creation, redemption and revocation are auditable.
- The pilot entitlement expires with the invitation.
- Pilot activation is rate limited.
- The global pilot access-code route returns `410 Gone` and does not authenticate anyone.

## Admin configuration

Set `COMPFLOW_PLATFORM_ADMINS` to a comma-separated list of operator email addresses. Do not put customer emails here. The admin API is denied when this list is empty, so an accidentally exposed console cannot create invitations without an explicitly configured platform administrator.

Pilot duration is bounded to 1–90 days by the invitation service. Thirty days is the recommended initial pilot default.

## Customer experience

The prospect receives something like:

`Invitation link: https://www.compflow.icu/pilot.html?code=CFP-....`

`Pilot code: CFP-....`

They may click the link or manually open the activation page and enter the code. The page requires the invited company email before activation.

The code is not displayed by the application after redemption and is never recoverable from PostgreSQL because only its hash is stored.
