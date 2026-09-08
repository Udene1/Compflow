# Engineering Evolution Addendum — 2026-09-08

This addendum records the database-authority and audit-durability milestone completed after the lease/concurrency hardening work.

## Database authority

PostgreSQL is now the only persistence implementation exposed by `core/db.js`.

The previous `MemoryFallbackPool` and non-production fallback path were removed. Database query failures now surface as database failures instead of silently switching to process memory. Transactional `connect()` also requires a real PostgreSQL connection.

Database initialization is fail-closed: `initDb()` rethrows schema initialization failures instead of logging the error and allowing the application to continue against an incomplete schema.

This closes an important architectural loophole:

```text
application state
      ↓
PostgreSQL
      ↓
transaction / lock / constraint semantics
```

There is no second persistence universe for tests or development to accidentally make the system appear healthy.

## Audit durability

The durable execution event stream remains PostgreSQL-backed and authoritative for execution history. Explicit event idempotency keys are persisted in the database, duplicate writes resolve to the existing event, and sensitive event payload fields are sanitized before persistence.

Execution lifecycle transitions and recovery append durable events transactionally with the state changes they describe. Security-critical audit behavior therefore follows the same principle as execution state: if durable persistence cannot be established, the system must surface the failure rather than claim success.

The older DynamoDB audit helper remains separate legacy functionality and is not treated as the authoritative execution timeline.

## Verification rule

The milestone is not considered complete from a code-review perspective until CI validates the changed database layer against real PostgreSQL and the production image still builds. Mocked database behavior is not accepted as evidence.

## Next architectural direction

With fake persistence removed, the next reliability/security work can focus on:

1. audit-path call sites and silent error swallowing;
2. concurrent retry/resume versus recovery;
3. authentication/session authority and cookie boundaries;
4. worker/Redis/recovery shutdown behavior;
5. dependency and secret-leakage review;
6. production integration verification.

## API evolution note

API quality should be improved in a dedicated contract milestone after the current reliability/security boundary is stable. Versioning should be introduced deliberately at that point, preferably as a clean `/api/v1` public contract while internal execution APIs remain free to evolve behind the boundary. We should not add versioning merely for appearance; we should first lock request/response schemas, authentication semantics, idempotency behavior, error codes, pagination/cursors, and compatibility rules.
