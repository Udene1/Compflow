# Compflow Pilot Operations

## Pilot model

Compflow pilots are issued through unique invitations. There is no global pilot access code.

Each invitation is:

- tied to one company and one email address
- time-limited (1–90 days; default 30)
- single-use
- stored durably in PostgreSQL
- represented in PostgreSQL only by a SHA-256 token hash
- auditable
- permanently unusable after redemption or revocation

The recipient receives both:

1. a trusted Compflow activation link; and
2. the same invitation code for manual entry if they prefer not to click the link.

The code is an activation credential, not a reusable organization password. Making it reusable would turn the invitation into a persistent bearer credential and would defeat the single-use security property.

## Platform admin setup

Set `COMPFLOW_PLATFORM_ADMINS` in the production API environment to a comma-separated list of platform-operator email addresses. Do not use organization roles as a substitute for platform administration.

Example:

```env
COMPFLOW_PLATFORM_ADMINS=operator@example.com
```

The private console is:

`https://www.compflow.icu/pilot-admin.html`

It is not linked from the public product navigation. The API independently enforces platform-admin authorization, so hiding the page is not a security control.

## Creating an invitation

1. Open the private Pilot Console.
2. Enter the company name.
3. Enter the exact company email that should receive the invitation.
4. Select the pilot duration.
5. Generate the invitation.
6. Send the company both the link and the code.

The plaintext code is returned only at creation time. PostgreSQL stores only its hash.

## Redemption

The recipient can open the link or visit the pilot activation page and enter the code manually. The backend requires the supplied email to match the invitation, locks the invitation row inside a PostgreSQL transaction, creates the organization/user/membership/entitlement, marks the invitation redeemed, and then creates the authenticated session.

A redeemed invitation cannot be used again.

## Revocation

Pending invitations can be revoked from the private console. Expired invitations are rejected server-side. No frontend state can override invitation or entitlement state.

## Legacy pilot code

`PILOT_ACCESS_CODE` and the previous global pilot-login path are retired. The server explicitly returns `410 LEGACY_PILOT_CODE_DISABLED` for the old endpoint and no longer exposes a pilot-access flag through provider discovery.
