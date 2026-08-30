# ComplianceFlow — Auth System Inventory

**Date:** 2026-08-30  
**Scope:** Phase 0 — Read-only audit of all authentication-related files before changes.

---

## Files Audited

| File | Purpose |
|------|---------|
| `api/auth.js` | OAuth routes: Google, GitHub, `/me`, `/providers`, `/logout`, `/pilot-login`, `/dev-login` |
| `core/auth.js` | HMAC-SHA256 session tokens, revocation list, `upsertUserFromOAuth`, role constants |
| `core/auth_guard.js` | `requireAuth()` / `optionalAuth()` Express middleware |
| `server.js` | CORS, rate limiting, route protection mounting |
| `auth-ui.js` | Frontend auth gate, `authFetch`, Mode A/B detection, provider-driven UI |
| `app.html` | Auth gate overlay, account modal, org status strip, all frontend JS modules |

---

## Environment Variables Used

| Variable | Where Used | Required |
|----------|-----------|---------|
| `AUTH_SECRET` / `JWT_SECRET` | `core/auth.js` — token signing | **YES (prod)** |
| `NODE_ENV` | `api/auth.js`, `core/auth.js`, `server.js` | YES |
| `APP_URL` | `api/auth.js` — OAuth redirect after login | YES |
| `API_URL` | `api/auth.js` — OAuth callback URL, providers endpoint | YES |
| `GOOGLE_CLIENT_ID` | `api/auth.js` — Google OAuth flow | YES (for Google login) |
| `GOOGLE_CLIENT_SECRET` | `api/auth.js` — Google token exchange | YES (for Google login) |
| `GITHUB_CLIENT_ID` | `api/auth.js` — GitHub OAuth flow | YES (for GitHub login) |
| `GITHUB_CLIENT_SECRET` | `api/auth.js` — GitHub token exchange | YES (for GitHub login) |
| `PILOT_ACCESS_CODE` | `api/auth.js` — pilot-login route | Optional |
| `ALLOWED_DOMAINS` | `api/auth.js` — email domain allow-list | Optional |
| `ALLOWED_GITHUB_ORGS` | `api/auth.js` — GitHub org membership gate | Optional |
| `REJECT_PERSONAL_EMAILS` | `api/auth.js` — block gmail/yahoo etc. | Optional |

---

## Cookie Flags (Production)

Set by `buildSessionCookies()` in `api/auth.js`:

```
Set-Cookie: cf_session=<token>; HttpOnly; Secure; SameSite=None; Domain=.compflow.icu; Path=/; Max-Age=604800
Set-Cookie: cf_user_email=<email>; Secure; SameSite=None; Domain=.compflow.icu; Path=/; Max-Age=604800
```

**Notes:**
- `SameSite=None` is used because `www.compflow.icu` → `api.compflow.icu` is technically cross-subdomain. `SameSite=Lax` would prevent cookies being sent on initial page-load API calls.
- `Domain=.compflow.icu` allows both `www` and `api` subdomains to share the session cookie.
- `HttpOnly` prevents XSS access to the session token.
- Logout clears cookies with matching `Domain` / `SameSite` / `Secure` attributes (via `buildClearCookies()`).

---

## OAuth Callback URLs

| Provider | Callback URL |
|----------|-------------|
| Google | `https://api.compflow.icu/api/auth/google/callback` |
| GitHub | `https://api.compflow.icu/api/auth/github/callback` |
| Google (dev) | `http://localhost:3000/api/auth/google/callback` |
| GitHub (dev) | `http://localhost:3000/api/auth/github/callback` |

---

## Auth Routes

| Route | Method | Auth Required | Notes |
|-------|--------|--------------|-------|
| `/api/auth/providers` | GET | No | Returns enabled providers + domain restrictions |
| `/api/auth/google` | GET | No | Initiates Google OAuth redirect |
| `/api/auth/google/callback` | GET | No | Google OAuth callback, sets cookie, redirects to app |
| `/api/auth/github` | GET | No | Initiates GitHub OAuth redirect |
| `/api/auth/github/callback` | GET | No | GitHub OAuth callback, sets cookie, redirects to app |
| `/api/auth/me` | GET | Yes (cookie/Bearer) | Returns current user session |
| `/api/auth/logout` | POST | No (best-effort) | Revokes session, clears cookies |
| `/api/auth/pilot-login` | POST | No | Pilot code login (when `PILOT_ACCESS_CODE` set) |
| `/api/auth/dev-login` | POST | No | **403 in production** — dev-only |

---

## Session Token Format

HMAC-SHA256 signed, base64url-encoded JSON:
```json
{
  "payload": {
    "sessionId": "sess_<uuid>",
    "userId": "usr_<sha256-of-email>",
    "email": "user@example.com",
    "name": "User Name",
    "orgId": "org_example_com",
    "orgName": "EXAMPLE.COM Governance",
    "role": "OWNER",
    "issuedAt": "2026-08-30T...",
    "expiresAt": "2026-09-06T..."
  },
  "signature": "<hmac-sha256-hex>"
}
```

Server-side revocation: in-memory `Map` (token hash → expiry). Cleared on logout. **Not Redis-backed** — logging out only takes effect on the same process instance.

---

## Gaps Found & Fixed

| Gap | Severity | File | Fix Applied |
|-----|----------|------|------------|
| `AUTH_SECRET` fallback continues in production | 🔴 Critical | `core/auth.js` | Now **throws** in production — server won't start without it |
| `org-status-strip` always visible (duplicate `display` in inline style) | 🟡 UX bug | `app.html:124` | Removed duplicate `display:flex` — JS controls visibility |
| Duplicate `id="modal-auth"` (cloud settings + auth modal) | 🟡 JS bug | `app.html:1085` | Auth modal renamed to `id="modal-account"` |
| OAuth callback toast fires before auth state resolved | 🟡 UX race | `auth-ui.js` | `handleOAuthCallbackParams()` moved inside `fetchCurrentUser()` |

## Already Correct (No Changes Needed)

- All frontend modules use `authFetch` (not raw `fetch`) — `cloud-connect.js`, `scanner.js`, `tenant-manager.js`, `evidence.js`, `remediation.js`, `monitoring-ui.js`, `scan-history.js`, `chat-engine.js`
- Cookie SameSite/Domain/HttpOnly/Secure flags — correct for cross-subdomain in production
- Dev-login blocked by `NODE_ENV !== 'development'` check — already in production guard
- Auth gate renders only enabled providers from `/api/auth/providers`
- Mode A (activation) / Mode B (app) logic fully implemented
- CORS with `credentials: true` and origin whitelist — correct
- Domain/org restriction logic with configurable env vars — correct
- `.env.example` — all vars documented
