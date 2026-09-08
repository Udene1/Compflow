# ComplianceFlow AI — Engineering Evolution & Current Direction

> This document is the living continuation of `HANDOVER.md`. It explains not only **what** was integrated, but **why the architecture changed**, what failures taught us, and what engineering principle each integration is protecting. It is intentionally written for the next engineer who needs to understand how the system evolved rather than merely copy its current file map.
>
> **Security note:** This document contains no production credentials, access tokens, private keys, database passwords, session tokens, or real secret values. Examples use placeholders only. Never put live credentials in Markdown, source control, CI logs, fixtures, or screenshots.

---

## 1. Why The Architecture Changed

ComplianceFlow started as a cloud-compliance application whose central concern was scanning infrastructure, mapping findings to compliance controls, using AI to reason about remediation, and producing audit evidence.

That foundation is still important, but the engineering problem became larger as we moved toward a system that can perform long-running, asynchronous, dependency-aware work safely.

A scan is no longer just:

```text
request → scan → result
```

The system increasingly needs to behave like:

```text
request
  → durable execution
  → dependency graph
  → node attempts
  → background worker
  → leases + heartbeats
  → recovery after crashes
  → human approval where required
  → resumable execution
  → durable audit events
  → live execution timeline
```

That change is deliberate. A system that can eventually orchestrate real infrastructure cannot rely on process memory, optimistic state, fake infrastructure, or an assumption that a worker will always finish what it started.

### The engineering rule that emerged

**PostgreSQL is authoritative for durable execution state. Redis/BullMQ is infrastructure for dispatch, not the source of truth. Workers are leased, fenced, recoverable, and never trusted merely because they are still running.**

This is why recent work has concentrated on lifecycle correctness and failure semantics rather than adding superficial UI features.

---

## 2. The No-Mocks Discipline

One of the most important changes in the project's development discipline was the decision to stop treating mocked infrastructure as evidence that the production architecture works.

### Before

Tests could pass while PostgreSQL or Redis was absent because fallback implementations could simulate the database or queue.

That is useful for a prototype, but dangerous for a system whose correctness depends on transactions, locks, leases, queue semantics, and persistence.

### Now

The integration test path deliberately starts real infrastructure:

```text
GitHub Actions
   │
   ├── PostgreSQL 16
   ├── Redis 7
   │
   └── Vitest + recorded suite
           │
           └── real SQL + real queue infrastructure
```

The CI workflow also builds the production Docker image. This gives us a stronger statement than “the JavaScript tests passed”: the application can initialize against the infrastructure it actually depends on.

### Why this matters

A mocked PostgreSQL connection cannot prove:

- row locking behaves correctly;
- foreign keys reject invalid state;
- concurrent transactions serialize correctly;
- transaction rollback really restores state;
- database timestamps behave correctly;
- unique constraints prevent duplicate active attempts.

Likewise, a fake Redis client cannot prove BullMQ integration or real queue connectivity.

**Tests are therefore part of the architecture, not a separate simulation of it.**

---

## 3. Durable Execution State Became The Core Primitive

The project introduced durable execution records and graph persistence because long-running compliance work needs an identity that survives process death.

The important entities are now conceptually:

```text
Organization
   │
   └── Execution Run
          │
          ├── Execution lease
          ├── Node
          │    └── Node attempts
          │
          └── Execution events
```

An execution has a stable identity. Nodes have stable usage identities. Attempts represent actual work rather than merely a UI status.

This separation lets the dashboard answer questions that a simple “job status” record cannot answer:

- What was supposed to run?
- Which dependency blocked this node?
- Which worker claimed the attempt?
- Did the attempt finish or become stale?
- Was the execution recovered after a worker disappeared?
- Can this node be safely resumed?
- What happened, and in what durable order?

---

## 4. Stable Usage IDs And Dependency Edges

The execution graph introduced stable usage/node identifiers and stable dependency-edge identifiers.

This was done because generated random IDs are poor identities for a workflow that can be retried, resumed, displayed live, and audited.

The graph direction is intentionally:

```text
dependency → dependent
```

For example:

```text
Discover AWS account
        │
        ▼
Scan S3
        │
        ▼
Evaluate S3 finding
        │
        ▼
Remediate
```

A dependent node can only become runnable when its required dependencies have reached the appropriate terminal-success state.

This prevents the engine from “resuming everything that failed” without understanding the workflow it is resuming.

---

## 5. Real Node Attempts And Recovery

A node is not the same thing as an attempt.

A node describes work that should exist in the execution graph. An attempt describes one concrete worker execution of that node.

This distinction became necessary for crash recovery.

### Example

```text
Node: scan-s3

Attempt #1
  worker-A
  RUNNING
  worker disappears

Recovery
  ↓
Attempt #1 → FAILED / STALE_ATTEMPT
Node       → resumable

Resume
  ↓
Attempt #2
  worker-B
  RUNNING
```

PostgreSQL enforces the important invariant that a node cannot have multiple simultaneously RUNNING attempts.

This is not a cosmetic status rule. It is protection against two workers performing the same real-world action concurrently.

---

## 6. Execution Leases And Why They Exist

The next architectural step was a durable execution lease.

A worker does not get permanent authority over an execution. It receives a lease containing ownership information and an expiry.

Conceptually:

```text
execution_runs
  lease_owner
  lease_token
  lease_expires_at
  heartbeat_at
```

A worker must heartbeat while it owns the execution.

If it disappears, its lease eventually expires and recovery can take over.

### Why both owner and token?

The worker identity answers **who** claims the lease.

The lease token answers **which specific lease instance** is authorized.

This prevents an old worker from accidentally becoming authoritative again after a newer worker has acquired a later lease.

---

## 7. The Important Lease Race We Found

A subtle race appeared when terminal execution state was committed after the lease had expired.

The first instinct was to check whether the lease was valid using a transaction timestamp. PostgreSQL's `NOW()` / `current_timestamp` is tied to the transaction start time, so a long transaction can observe an earlier time even though real wall-clock time has moved past the lease expiry.

For a fencing decision, that is unsafe.

The terminal writer therefore uses PostgreSQL `clock_timestamp()` when checking lease expiry.

The terminal commit now requires all of these at the point of locking/updating:

```text
execution is RUNNING
AND organization matches
AND lease owner matches
AND lease token matches
AND lease has not expired according to wall-clock time
```

### Why this matters

Suppose:

```text
T0   worker A owns lease
T1   worker A starts terminal transaction
T2   lease expires
T3   worker A tries to commit
```

The correct result is that worker A no longer has authority merely because its transaction started at T1.

This is one of the reasons the terminal transition is now fenced atomically inside PostgreSQL.

---

## 8. Atomic Terminal Fencing

The terminal execution transition was hardened so that the worker cannot independently update an attempt, graph node, and execution record and hope all three remain valid.

`finishExecutionFenced(...)` performs the terminal transition inside one database transaction.

The transaction:

1. Locks the authoritative execution row.
2. Re-validates organization and lease ownership.
3. Re-validates wall-clock lease expiry.
4. Updates the running attempt.
5. Updates the graph node.
6. Records the durable `NODE_ATTEMPT_FINISHED` event.
7. Updates the execution to `SUCCEEDED` or `FAILED`.
8. Records `EXECUTION_FINISHED`.
9. Commits all state together.

If the final execution update fails because fencing has been lost, the transaction rolls back the preceding attempt/node/audit changes.

### Why we chose this design

A partial terminal transition is worse than a failed transition.

For example, this state must never survive:

```text
attempt = SUCCEEDED
node    = SUCCEEDED
execution = RUNNING
```

The database transaction makes the terminal state an atomic decision.

---

## 9. Cancellation Vs Completion

Another race we explicitly hardened is cancellation against a worker that is finishing at the same time.

The desired invariant is:

```text
CANCELLED wins → stale worker cannot resurrect execution

valid fenced completion wins → cancellation cannot overwrite it
```

The worker therefore cannot finish an execution merely because its handler returned successfully. It must still possess a valid execution lease at terminal commit time.

Cancellation also updates the relevant active attempts and non-terminal graph nodes transactionally.

This is important for a real control plane: “Cancel” must mean cancellation of the durable execution, not merely a browser button that asks a worker to stop.

---

## 10. Crash Recovery Became A First-Class Integration

Recovery was added because workers can disappear for reasons outside application control:

- container restart;
- VM failure;
- process crash;
- network partition;
- deployment;
- worker termination;
- infrastructure outage.

Recovery scans for expired execution leases and reconciles the durable state rather than relying on the dead worker to report failure.

The authoritative recovery result is:

```text
RUNNING execution with expired lease
        ↓
FAILED
error_code = STALE_EXECUTION_LEASE
lease cleared
running attempts reconciled
running graph nodes reconciled
EXECUTION_LEASE_EXPIRED event appended
```

Recovery is transactional so the execution cannot be marked failed while its active attempt remains indefinitely RUNNING.

The design intentionally fails closed: uncertainty about who owns an execution must not become permission for another worker to assume success.

---

## 11. Why `STALE_EXECUTION_LEASE` Became The Authoritative Recovery Error

Earlier layers had their own stale-attempt concept, which remains useful when recovering an individual node attempt.

But once an execution lease expires, the execution-level fact is more important: **the worker no longer has authoritative execution ownership**.

Therefore execution-lease recovery records:

```text
STALE_EXECUTION_LEASE
```

for the affected execution and its active attempts.

This gives operators a coherent explanation instead of contradictory errors such as an execution saying “lease expired” while its active attempt says it merely “timed out”.

Lower-level diagnostic detail can still be preserved in event metadata where useful.

---

## 12. Resume Became Dependency-Aware

A resume operation is not “rerun every failed row”.

The engine now determines which nodes are actually resumable based on dependency state.

A node is eligible only when:

- it is in an allowed resumable state;
- all required dependencies have reached terminal success;
- approval-gated remediation has the required successful approval node;
- the node can be claimed without creating a competing active attempt.

The resume path also acquires the durable execution lease before claiming work.

This creates a safer chain:

```text
recover
  ↓
calculate dependency-aware plan
  ↓
acquire execution lease
  ↓
claim resumable nodes
  ↓
queue real worker execution
```

---

## 13. Durable Execution Events And Timeline

The execution event store was introduced so the system can explain how it reached its current state.

Events have a global monotonic sequence and are scoped to the organization/execution.

Examples include:

```text
EXECUTION_CREATED
EXECUTION_LEASE_ACQUIRED
NODE_ATTEMPT_FINISHED
EXECUTION_LEASE_EXPIRED
EXECUTION_CANCELLED
EXECUTION_FINISHED
```

The sequence is especially important for the live dashboard because a timestamp alone is not enough to establish a deterministic ordering when multiple workers act concurrently.

The API exposes event history with an `afterSequence` cursor so clients can incrementally consume changes.

### Why events are separate from current state

Current state answers:

> “What is true now?”

Events answer:

> “How did we get here?”

A production compliance/control system needs both.

---

## 14. Live Graph, Timeline And Refresh Controls

The execution graph API evolved from a static status endpoint into a live execution surface.

It can expose:

- graph nodes;
- dependency edges;
- node attempts;
- execution lifecycle;
- recovery information;
- resumable node IDs;
- ordered event history;
- an incremental event cursor;
- live SSE updates;
- cancellation;
- resume;
- retry.

The browser can therefore observe the same durable state that workers are modifying rather than maintaining an independent fake execution model.

### Design principle

**The dashboard is a projection of durable execution state. It is not the execution engine.**

That distinction is important as the UI becomes richer.

---

## 15. Worker Hardening: The Worker Is Not The Authority

The worker was changed so that terminal state is written only through the fenced terminal transition.

After executing its handler, the worker:

1. refreshes/heartbeats the execution lease;
2. determines terminal status;
3. calls the fenced terminal writer;
4. does not perform a second unfenced terminal write if fencing fails.

If fencing has been lost, recovery owns the durable state transition.

This prevents an old worker from “cleaning up” after it has already lost authority.

### Why this is important

A worker is an actor in the system, not the system's source of truth.

The database decides whether that actor is still authorized to mutate terminal execution state.

---

## 16. Server Hardening

As the backend became a real control plane, the HTTP server was hardened around the same fail-closed philosophy.

Current hardening includes:

- strict CORS allowlisting;
- security response headers;
- HSTS when operating securely;
- bounded JSON request bodies;
- general API rate limiting;
- heavier limits for expensive operations;
- authentication endpoint throttling;
- sanitized malformed JSON/body-size errors;
- readiness checks for PostgreSQL and Redis;
- graceful shutdown on process termination;
- bounded forced shutdown so a dead dependency cannot keep the process alive indefinitely.

The goal is not simply to make requests fail. The goal is to make failure explicit, bounded, and operationally understandable.

---

## 17. Authentication And Session Security Direction

Authentication evolved from UI-level login behavior toward server-enforced authorization.

The backend is responsible for:

- validating authenticated identity;
- enforcing organization scope;
- enforcing role hierarchy;
- validating session state;
- rejecting revoked sessions;
- restricting sensitive routes;
- keeping development login disabled in production unless explicitly enabled.

The browser must never be treated as the authority for organization or role claims.

### Security documentation rule

OAuth client secrets, HMAC secrets, database passwords, API tokens, session tokens, private keys, and signed bearer tokens must never appear in this handover.

Use placeholders such as:

```bash
AUTH_SECRET=<set-in-secret-manager>
POSTGRES_PASSWORD=<set-in-secret-manager>
GOOGLE_CLIENT_SECRET=<set-in-secret-manager>
GITHUB_CLIENT_SECRET=<set-in-secret-manager>
AUDITOR_SIGNING_SECRET=<set-in-secret-manager>
```

If a credential has ever been accidentally committed, sanitizing the documentation is not enough: the credential must be rotated at its provider.

---

## 18. CI Became A Product Safety Boundary

CI is now intentionally stricter than a developer's local convenience workflow.

The main validation path is designed to prove:

```text
real PostgreSQL
      +
real Redis
      +
real Vitest suite
      +
complete recorded suite
      +
production Docker build
```

The repository has repeatedly used CI failures to expose assumptions that ordinary unit tests did not catch.

One example was a real PostgreSQL foreign-key failure caused by incomplete test fixture state. The fix was to seed the required organization summary rather than weaken the database constraint.

That is the intended pattern:

> **When real infrastructure rejects our assumptions, fix the system or fixture—not the reality.**

---

## 19. Recorded Tests Became Reproducible

The old approach of local/untracked test scripts made historical test claims difficult to reproduce.

The recorded test suites were brought under version control so CI executes the same tracked test logic every time.

This matters because an audit/security platform should be able to answer:

- What was tested?
- Which code was tested?
- Was the test logic itself committed?
- Did it run against real infrastructure?
- Did the production image build?

A timestamped result without reproducible test code is weak evidence.

---

## 20. What We Are Building Now — And Why

The current engineering focus is **reliability and security hardening around durable execution**.

The work is not being driven by a desire to add more endpoints. It is driven by the question:

> **Can Compflow safely continue an important compliance/infrastructure workflow when multiple actors race, workers disappear, infrastructure fails, requests are duplicated, or a user asks for control at exactly the wrong moment?**

The current priority areas are:

### A. Lease/concurrency races
Finish hardening cancellation, terminal completion, retry/resume, and recovery so only one authoritative transition wins.

### B. Recovery consistency
Ensure expired executions, attempts, nodes, and events are reconciled atomically and idempotently.

### C. Control idempotency
Repeated cancel/resume/retry requests must not accidentally create multiple logical operations or multiple queue jobs.

### D. SSE resource safety
Live execution streams need bounded connection counts, deterministic cleanup, and protection against overlapping polling work.

### E. Strict input validation
Execution IDs, node IDs, action names, reasons, cursors, and idempotency keys must be bounded and validated before expensive work begins.

### F. Audit durability
The event log needs stronger append-only and retention semantics so historical execution evidence cannot silently be rewritten.

### G. Shutdown/readiness correctness
A process restart must stop accepting new work, stop recovery loops, close workers/queues, and drain database resources predictably.

### H. Dependency/security hygiene
Third-party dependency vulnerabilities must be reviewed deliberately. We do not blindly use forceful dependency upgrades that could destabilize the control plane.

### I. Production verification
The final gate remains real integration testing plus a production Docker build. A green unit suite alone is not considered sufficient.

---

## 21. Why We Are Not Adding Features Randomly

The long-term product direction is bigger than a conventional compliance dashboard. The system is being shaped toward a platform that can understand an organization's desired state, inspect real infrastructure, reason about risk, perform controlled actions, and continuously prove what happened.

That future requires foundations first.

For example, an eventual automated domain/infrastructure provisioning capability would need to know:

```text
who requested the action
        ↓
what organization owns it
        ↓
what was approved
        ↓
what external resource was changed
        ↓
which worker performed it
        ↓
whether the worker still had authority
        ↓
what actually happened
        ↓
whether the operation can be resumed safely
        ↓
what evidence proves the result
```

Building that on ephemeral memory, fake queues, or unfenced workers would create a system that looks autonomous but cannot be trusted.

The current reliability work is therefore foundational to the larger vision, not a detour from it.

---

## 22. Integration Principles Going Forward

Every new integration should answer four questions before implementation:

### 1. What real problem does this solve?
Do not add an integration merely because a technology is popular.

### 2. What becomes authoritative?
The source of truth must be explicit. For durable execution, PostgreSQL is authoritative.

### 3. What happens when the dependency disappears?
Every external dependency needs a defined failure mode. For critical execution state, failure must not silently become success.

### 4. Can the behavior be proven against real infrastructure?
If correctness depends on PostgreSQL, Redis, a cloud API, or another external system, the important integration path should eventually be tested against the real dependency.

---

## 23. Things We Explicitly Do Not Want

### No production mocks
Mocks belong in narrowly scoped tests where they do not conceal infrastructure semantics. They must not become a production fallback for authoritative systems.

### No silent in-memory replacement for durable state
If PostgreSQL is required for a durable operation and PostgreSQL is unavailable, the operation should fail clearly.

### No fake queue success
If BullMQ/Redis cannot accept a durable background job, the API must not tell the user that work has definitely been queued.

### No unfenced worker writes
A worker that lost its lease must not be able to mutate authoritative terminal state.

### No UI-only security
Hiding an action in the dashboard is not authorization. The server must enforce it.

### No secrets in documentation
The handover is source-controlled documentation. It is not a secret store.

### No knowingly impossible architecture
We can design toward ambitious future capabilities, but we must not implement fake abstractions that pretend an unavailable external capability already exists.

---

## 24. Current Verification Baseline

The repository has reached a meaningful reliability baseline when CI demonstrates all of the following together:

- real PostgreSQL starts;
- real Redis starts;
- schema initialization succeeds;
- deterministic test principal/fixture setup succeeds;
- the tracked Vitest suite passes;
- the complete recorded test suite passes;
- the production Docker image builds;
- infrastructure cleanup completes.

Recent lifecycle work specifically added coverage around:

- lease ownership;
- lease expiry;
- stale execution recovery;
- fenced terminal completion;
- worker lease loss;
- cancellation versus stale completion;
- dependency-aware resume;
- durable execution events;
- graph persistence.

The baseline is considered a floor, not the finish line.

---

## 25. Handover For The Next Engineer

If you are continuing this project, do not start by asking “what feature should I add?”

Start by asking:

```text
What is authoritative?
What can race?
What can crash?
What can be retried?
What happens if the worker dies here?
What happens if the lease expires here?
Can the same request arrive twice?
Can two workers claim this work?
Can the UI show something the database does not agree with?
Can CI prove this with real infrastructure?
```

Then make the smallest architectural change that preserves those invariants.

When a test fails because PostgreSQL, Redis, a constraint, a lease, or a real integration disagrees with the implementation, treat that failure as information about the system—not as an inconvenience to mock away.

That is the engineering discipline behind the current evolution of Compflow.

---

## 26. Documentation Hygiene / Secret Sanitization

The original handover contained examples that were too close to real credential material, including a bearer-token-shaped auditor response and concrete infrastructure credential values.

Those examples have no value that requires preserving the sensitive-looking material.

Going forward:

- bearer tokens → `<REDACTED_AUDITOR_TOKEN>`;
- API keys → `<REDACTED_API_KEY>`;
- client secrets → `<REDACTED_CLIENT_SECRET>`;
- database passwords → `<REDACTED_DATABASE_PASSWORD>`;
- private keys → `<REDACTED_PRIVATE_KEY>`;
- access keys → `<REDACTED_ACCESS_KEY_ID>` / `<REDACTED_SECRET_ACCESS_KEY>`;
- session cookies → `<REDACTED_SESSION>`;
- signing secrets → `<REDACTED_SIGNING_SECRET>`.

Real production values belong in the deployment secret manager/environment, never in this repository's Markdown.

**Important:** If any value previously committed to Git was actually live rather than an example, rotate/revoke it even after sanitization. Removing it from the latest file does not make the historical credential safe.

---

*Last updated: September 8, 2026*
*Purpose: preserve the architectural history, reasoning, reliability discipline, and current engineering direction of ComplianceFlow/Compflow.*
