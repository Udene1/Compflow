# ComplianceFlow AI — Engineering Evolution & Current Direction

> This is the single living engineering handover for Compflow. It records architectural evolution, reliability/security decisions, failures that changed the design, and the current verification discipline. Add future iterations as dated sections here; do not create a new handover Markdown file for each iteration.
>
> **Security rule:** no production credentials, access tokens, private keys, database passwords, session tokens, or real secret values belong here. Examples use placeholders only.

---

## 1. Architectural Evolution

Compflow began as a cloud-compliance application focused on scanning infrastructure, mapping findings to compliance controls, AI-assisted remediation reasoning, evidence, and audit reporting.

The architecture evolved from a simple:

```text
request → scan → result
```

toward a durable control plane:

```text
request
  → durable execution
  → dependency graph
  → node attempts
  → BullMQ worker dispatch
  → execution leases + heartbeats
  → fencing
  → crash recovery
  → approvals
  → resumable execution
  → durable events/audit
  → live graph/timeline
```

The central engineering rule is:

**PostgreSQL is authoritative for durable execution state. Redis/BullMQ is dispatch infrastructure, not the source of truth. Workers are leased, fenced, recoverable, and never trusted merely because they are still running.**

---

## 2. No-Mocks Discipline

Real infrastructure is part of the correctness boundary. CI starts PostgreSQL 16 and Redis 7, runs the tracked Vitest suite and recorded suite, and builds the production Docker image.

We do not use process-memory persistence or fake queues as a production fallback. If PostgreSQL or Redis is required and unavailable, the operation must fail clearly.

This discipline exists because mocks cannot prove row locking, foreign keys, transaction rollback, database timestamps, unique constraints, BullMQ behavior, Redis connectivity, or actual failure semantics.

**When real infrastructure rejects an assumption, fix the system or fixture—not the reality.**

---

## 3. Durable Execution And Graph

Durable execution records survive process death. The core model is:

```text
Organization
  └── Execution Run
       ├── execution lease
       ├── graph nodes
       │    └── node attempts
       └── execution events
```

Nodes have stable usage identities. Dependency edges use the direction `dependency → dependent`. A node becomes resumable only when its dependency requirements are satisfied.

A node and an attempt are intentionally different concepts: an attempt represents one concrete worker execution. PostgreSQL prevents multiple simultaneous RUNNING attempts for the same node.

The graph therefore supports dependency-aware resume, execution timelines, recovery, auditing, and safe retry rather than simply rerunning failed rows.

---

## 4. Execution Leases And Fencing

A worker receives an execution lease containing owner, token, expiry, and heartbeat information. The owner identifies the worker; the token identifies the specific lease instance.

Terminal execution writes are fenced atomically in PostgreSQL. The terminal writer verifies:

```text
execution is RUNNING
organization matches
lease owner matches
lease token matches
lease has not expired by wall-clock time
```

`clock_timestamp()` is used for fencing decisions because PostgreSQL `NOW()`/`current_timestamp` is transaction-start time and can become stale during a long transaction.

The terminal transition updates the attempt, graph node, execution state, and durable events in one transaction. If fencing is lost, the transaction rolls back instead of leaving a partial terminal state.

The worker is therefore an actor, not the authority. The database decides whether the worker still has authority.

---

## 5. Lease/Concurrency Races

The system explicitly protects against:

- terminal completion versus lease expiry;
- cancellation versus completion;
- recovery versus lease reacquisition;
- resume/retry versus recovery;
- duplicate control requests;
- duplicate queue delivery;
- multiple active node attempts;
- stale workers attempting terminal writes.

Cancellation is transactional and idempotent. Only one transaction can win the terminal transition. A stale worker cannot resurrect a cancelled or recovered execution.

An important invariant is now enforced even for the same worker identity: an active lease cannot be silently replaced by another lease acquisition. Replacing the lease token while the old lease is live would create two possible authorities behind one worker identity.

---

## 6. Crash Recovery

Recovery scans for RUNNING executions whose lease has expired according to `clock_timestamp()`.

Recovery atomically reconciles:

```text
RUNNING execution + expired lease
        ↓
FAILED / STALE_EXECUTION_LEASE
        ↓
lease cleared
active attempts failed
running graph nodes failed
EXECUTION_LEASE_EXPIRED event appended
```

Recovery is idempotent: a second recovery pass cannot create another recovery transition for an execution already reconciled.

The execution-level error `STALE_EXECUTION_LEASE` is authoritative because the key fact is loss of worker authority. Lower-level diagnostic information can remain in event metadata.

---

## 7. Resume And Control Idempotency

Resume is dependency-aware. The engine calculates eligible nodes, requires successful dependencies and approvals where applicable, acquires the durable execution lease, claims nodes without competing RUNNING attempts, and queues real worker work.

Execution controls use durable idempotency keys. Repeated cancel/resume/retry operations must resolve to the same logical operation rather than creating duplicate state transitions or queue jobs.

Execution events persist explicit idempotency keys in PostgreSQL and return the existing event on a duplicate write.

---

## 8. BullMQ/Redis Queue Boundary

Redis/BullMQ is deliberately a dispatch mechanism rather than an authority for execution state.

Queue jobs are sanitized and bounded. Job identity is tenant-scoped using a BullMQ-safe delimiter rather than `:` because BullMQ rejects invalid job IDs containing that character.

The original producer `jobId` remains in the durable payload while the BullMQ identity includes the organization namespace. This prevents cross-organization collisions while preserving application-level identity.

Queue failures surface as queue failures; they do not silently become successful scans.

Queue connections and workers have explicit shutdown handling, and the server drains the worker before closing queue connections and PostgreSQL.

---

## 9. Durable Events And Audit

Execution events provide deterministic history alongside current state. Events include lifecycle, lease, node, recovery, cancellation, and terminal transitions and expose ordered cursors for live consumers.

The durable audit path is PostgreSQL-backed and fail-closed. Audit payloads are recursively sanitized for sensitive keys and bounded in depth, array size, and string length.

Security-critical audit persistence must not be silently swallowed. Authentication/session operations now revoke newly created sessions when their success audit cannot be durably persisted. Logout revokes the session first and then records the audit event; if the audit write fails, the user remains logged out and the response reports audit unavailability.

The older legacy audit helper is not the authoritative execution timeline.

---

## 10. Database Authority

PostgreSQL is the only persistence implementation exposed by `core/db.js`.

The former `MemoryFallbackPool` and non-production persistence fallback were removed. Query failures surface as database failures. Transactional connections require PostgreSQL. Database initialization fails closed rather than allowing the application to continue against an incomplete schema.

This closes the architectural loophole where tests or development could accidentally make an unhealthy application appear healthy.

---

## 11. Authentication And Session Security

Authentication is server-authoritative. Organization and role claims are not trusted from the browser.

Current guarantees include:

- database-authoritative session existence and revocation;
- cryptographic token verification;
- role hierarchy enforcement;
- session rotation;
- OAuth state validation and single-use state clearing;
- Google PKCE;
- GitHub OAuth state protection;
- production-disabled developer login;
- HttpOnly, Secure, SameSite=Lax session cookies;
- bounded authentication rate limiting;
- sanitized authentication errors;
- no session token in JSON responses.

A successful authentication response is not allowed to reach the browser if the corresponding durable success audit cannot be persisted.

---

## 12. HTTP/SSE Hardening

The HTTP boundary includes strict CORS allowlisting, security headers, HSTS when secure, bounded JSON request bodies, general/heavy/auth rate limiting, sanitized JSON/body-size errors, and readiness checks for PostgreSQL and Redis.

The live execution graph surface uses bounded SSE connections, cleanup on disconnect, and non-overlapping stream ticks. Execution IDs, node IDs, idempotency keys, cursors, and control reasons are bounded and validated before expensive work.

The dashboard is a projection of durable state. It is not an execution authority.

---

## 13. Graceful Shutdown And Readiness

Startup requires database initialization and the execution recovery loop before the application begins serving work.

Shutdown stops recovery, closes the HTTP server, closes the durable worker, closes BullMQ/Redis resources, and ends the PostgreSQL pool. A bounded forced-shutdown timer prevents an unhealthy dependency from keeping the process alive indefinitely.

`/health` is liveness-oriented. `/health/ready` verifies PostgreSQL and Redis and returns `503` when the application is not ready to perform its required work.

---

## 14. Recorded Tests And Real Verification

Recorded tests are tracked source code rather than untracked local scripts.

The CI safety boundary is:

```text
PostgreSQL 16
    +
Redis 7
    +
tracked Vitest suite
    +
complete recorded suite
    +
production Docker build
```

The repository has used real CI failures to correct fixture state, database authority, queue semantics, lease fencing, recovery, and authentication behavior rather than weakening infrastructure requirements.

The current baseline has included real PostgreSQL tests for session authority, event idempotency, lifecycle races, terminal fencing, recovery idempotency, and concurrent controls, plus real Redis/BullMQ tests for tenant-safe queue identity and deduplication.

---

## 15. Security And Dependency Hygiene

Dependency vulnerabilities must be reviewed deliberately. We do not use `npm audit fix --force` blindly because forceful major upgrades can destabilize the control plane.

The repository now has grouped weekly Dependabot security updates configured for npm. Current CI has reported a dependency exposure of 31 vulnerabilities (22 moderate, 7 high, 2 critical); this is treated as an active supply-chain work item rather than ignored or hidden.

Direct dependency upgrades must be performed with their lockfile changes and then validated against the real integration suite. In particular, the existing Express 4.19.x baseline is behind the maintained 4.x line, so it must be upgraded through a controlled dependency update rather than a speculative manifest-only edit.

Secret-leakage review also checks the repository for private-key and common GitHub-token patterns. Documentation is sanitized separately from credential rotation: if a historical value was ever live, it must be revoked/rotated at its provider.

---

## 16. Documentation Hygiene

This file is the single living handover. Future iterations should append dated sections here rather than creating `HANDOVER_EVOLUTION_<date>.md` files.

Historical credential-shaped examples have been replaced with placeholders such as:

```text
<REDACTED_AUDITOR_TOKEN>
<REDACTED_API_KEY>
<REDACTED_CLIENT_SECRET>
<REDACTED_DATABASE_PASSWORD>
<REDACTED_PRIVATE_KEY>
<REDACTED_SIGNING_SECRET>
```

Removing a credential from Git does not make a previously live credential safe; live credentials must be rotated at their provider.

---

## 17. Current Engineering Rules

### No production mocks
Mocks may exist only where they cannot conceal infrastructure semantics. They are not an alternative to real PostgreSQL, Redis, or durable execution behavior.

### No in-memory authoritative state
If PostgreSQL is unavailable for a durable operation, fail clearly.

### No fake queue success
If BullMQ/Redis cannot accept work, do not report durable queue success.

### No unfenced worker writes
A worker that lost its lease cannot mutate authoritative terminal state.

### No UI-only security
Authorization is enforced server-side.

### No secrets in documentation
The handover is not a secret store.

### No knowingly impossible architecture
Ambitious integrations must model real external capabilities and explicit failure modes rather than pretending unavailable capabilities already exist.

---

## 18. API Evolution Boundary

API versioning is intentionally deferred until the reliability/security boundary is stable.

The next API contract milestone should establish:

- request/response schemas;
- authentication semantics;
- durable idempotency behavior;
- stable error codes;
- pagination and event cursors;
- compatibility/deprecation rules;
- organization isolation guarantees.

At that point, a clean `/api/v1` public boundary can be introduced while internal execution APIs remain free to evolve behind it.

Versioning should be a compatibility contract, not decoration.

---

## 19. Current Verification Baseline

A reliability milestone is not complete merely because a local test command passes. The accepted gate is:

- PostgreSQL starts;
- Redis starts;
- schema initialization succeeds;
- deterministic test fixtures seed successfully;
- tracked Vitest suite passes;
- complete recorded suite passes;
- production Docker image builds;
- infrastructure cleanup completes.

The most recent verified queue-namespacing CI run completed all of those steps successfully on commit `f56e11a9d2ce3bd3c8f8549068eae3a8f1c3bc68`.

---

## 20. 2026-09-08 Reliability/Security Milestone

The 2026-09-08 hardening cycle consolidated the following changes:

- PostgreSQL-only durable persistence;
- fail-closed database initialization;
- fail-closed durable audit writes and recursive audit sanitization;
- authoritative database session state and removal of non-authoritative session fallback;
- atomic terminal fencing with wall-clock lease checks;
- lifecycle recovery and recovery idempotency;
- cancellation concurrency coverage;
- recovery versus lease reacquisition race coverage;
- same-identity active lease replacement prevention;
- BullMQ-safe tenant namespacing and real Redis queue dedupe coverage;
- explicit worker/queue shutdown;
- SSE resource caps and cleanup;
- strict execution-control input validation;
- durable control idempotency;
- authentication audit fail-closed behavior;
- grouped npm security-update automation;
- repository secret-pattern checks;
- consolidation of this document into the single living handover.

### Verification rule

No milestone is considered complete until the changed behavior is exercised against real infrastructure and the production image still builds. Mocked infrastructure is not accepted as evidence for these boundaries.

---

## 21. What Comes After The Reliability Boundary

Once the current reliability/security work is fully green and the dependency findings have been individually triaged, the next architectural work should proceed in this order:

1. lock the stable execution/API behavioral contracts;
2. introduce the public `/api/v1` boundary;
3. integrate the execution graph/timeline into the existing dashboard rather than maintaining a disconnected UI layer;
4. add production-oriented live refresh and control UX on top of durable state;
5. perform final production verification and operational review.

Features should be added only when they preserve the authority, fencing, recovery, audit, idempotency, and tenant-isolation invariants established here.

---

## 22. 2026-09-08 Intent → Plan → Execution → Evidence → Verification → Decision Product Boundary

The compliance domain is now being treated as a durable chain rather than a collection of loosely related scan functions:

```text
Intent
  → immutable normalized intent + hash
  → policy/plan compilation
  → immutable persisted plan + stable graph identities
  → durable node attempts + real BullMQ dispatch
  → authoritative evidence records
  → verification records
  → deterministic control decisions
  → immutable final decision artifact
```

Evidence is first-class durable data with provider/connection/resource provenance, source references, observation time, freshness expiry, bounded lineage, integrity hashes, and legacy promotion. Verification consumes durable evidence rather than treating worker output as the final truth. Decision derivation is idempotent when its substantive inputs are unchanged.

The public `/api/v1` boundary is authenticated and organization-scoped. It exposes durable execution state, evidence, decisions, provider capabilities, live graph streaming, and execution controls. The existing dashboard consumes this boundary as a projection rather than becoming an execution authority.

The plan boundary also canonicalizes provider aliases into the provider registry's supported identities. This prevents values such as `DO` from leaking into durable execution metadata as a second provider identity.

Final decisions are now immutable artifacts before re-derivation: replay returns the stored artifact, and the stored SHA-256 is checked against its persisted outcome/summary so direct corruption is detected rather than silently accepted.

### Verification status

The latest known CI failure was based on an older checkout (`4f0f63fc675ccb521201a3e24fe9a8a9b332e527`) and therefore did not include several subsequent fixes. That run reported 8 failures: the queue integration test expected an export that the later queue boundary already provides, the planner had not yet received the technical-control/provider-boundary fixes, and final-decision history behavior exposed a replay-ordering flaw. Subsequent commits address those issues. The full post-fix CI gate remains mandatory before this milestone is declared green.

*Last updated: September 8, 2026*
*Purpose: preserve the architectural history, reliability discipline, security decisions, and current engineering direction of Compflow.*
