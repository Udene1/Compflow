# Pilot access model

Compflow separates **authentication** from **service entitlement**.

Authentication answers: **who are you?**

Entitlement answers: **is this organization currently allowed to consume Compflow's service?**

## Production rule

A valid session alone does not authorize cloud scanning, evidence inspection, compliance execution, remediation, or other service operations.

The service requires an organization entitlement stored in PostgreSQL, which is the authoritative durable store.

Allowed entitlement states:

- `ACTIVE` — paid service access.
- `TRIAL` — explicitly provisioned trial access.
- `PILOT` — explicitly provisioned pilot access.

Denied states include `PAST_DUE`, `CANCELED`, expired entitlements, and organizations with no entitlement.

The entitlement check fails closed if PostgreSQL cannot be reached.

## Pilot access

The current pilot mechanism is `PILOT_ACCESS_CODE`.

A successful pilot-code authentication produces a durable `user_authenticated` audit event with provider `pilot_code`. The entitlement layer can reconstruct and persist the corresponding time-bounded `PILOT` entitlement from that durable event.

`PILOT_ACCESS_DAYS` controls the pilot duration and defaults to 30 days.

The pilot code is an access credential and must be treated like a secret. It must not be embedded in frontend JavaScript, documentation shown to customers, source control, or client-side configuration.

## Future paid billing

Paid billing should not be implemented as a frontend-only flag. A payment provider/webhook should become an authority that transitions the organization's entitlement to `ACTIVE`, with durable provider/customer/subscription identifiers and auditable state transitions.

The application should continue to authorize service operations from the PostgreSQL entitlement state rather than trusting a browser, URL parameter, local storage value, or client-supplied plan.

## Product behavior

Unauthenticated visitors may view public marketing and trust material.

Authenticated organizations without service entitlement may manage authentication/session state but receive `402 SERVICE_ENTITLEMENT_REQUIRED` when attempting protected service operations.

The dashboard should present this as a clear **Service access required** state rather than allowing a user to discover the restriction only through an opaque API error.

## Security boundary

Entitlement is separate from RBAC:

`Authentication → Organization → Entitlement → Role → Capability`

A paid organization still cannot bypass RBAC, and an administrator cannot grant themselves paid access merely by changing a client-side value.
