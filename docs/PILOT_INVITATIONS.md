# Compflow pilot invitations

Pilot access is issued per company through a unique invitation. The retired global `PILOT_ACCESS_CODE` is not a customer access path.

## Operator flow

1. A company contacts Compflow about the pilot.
2. A platform administrator opens `/pilot-admin.html` while signed in with an email listed in `COMPFLOW_PLATFORM_ADMINS`.
3. Enter the company name, company email and pilot duration.
4. The console generates a unique invitation **code and link**.
5. Send both to the prospect. The link is the convenient login destination; the code is the credential they can enter manually at `/pilot.html`.
6. The first successful use creates the organization, owner membership, onboarding state and PILOT entitlement.
7. After activation, the same code continues to authenticate that pilot user until the invitation expires or is explicitly revoked.

## Security properties

- Code entropy comes from Node's cryptographic random generator.
- Only a SHA-256 hash of the code is persisted.
- The credential is bound to the normalized invited email.
- PostgreSQL is authoritative for invitation, identity, session and entitlement state.
- First activation uses `SELECT ... FOR UPDATE` and a conditional state transition to prevent concurrent account creation.
- A redeemed credential cannot create a second account; it authenticates the existing `pilot_invitation` identity.
- Expired or revoked invitations cannot authenticate.
- Platform-admin revocation also cancels the pilot entitlement, so an existing session cannot continue consuming the protected service.
- Invitation creation, activation, authentication and revocation are auditable.
- The pilot entitlement expires with the invitation.
- Pilot activation/login is rate limited.
- The global pilot access-code route returns `410 Gone` and does not authenticate anyone.

## Admin configuration

Set `COMPFLOW_PLATFORM_ADMINS` to a comma-separated list of operator email addresses. Do not put customer emails here. The admin API is denied when this list is empty, so an accidentally exposed console cannot create invitations without an explicitly configured platform administrator.

Pilot duration is bounded to 1–90 days by the invitation service. Thirty days is the recommended initial pilot default.

## Customer experience

The prospect receives something like:

`Invitation link: https://www.compflow.icu/pilot.html?code=CFP-....`

`Pilot login code: CFP-....`

They may click the link or manually open the pilot page and enter the code. The page requires the invited company email for every login attempt.

The code is never returned by the API after creation and is never recoverable from PostgreSQL because only its hash is stored. Anyone who possesses the code and the invited email should be treated as having pilot access, so it should be shared only with the intended pilot user.
