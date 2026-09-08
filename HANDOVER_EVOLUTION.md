# ComplianceFlow AI — Engineering Evolution & Current Direction

> This is the single living engineering handover for Compflow. It records architectural evolution, reliability/security decisions, failures that changed the design, and the current verification discipline. Add future iterations as dated sections here; do not create a new handover Markdown file for each iteration.
>
> **Security rule:** no production credentials, access tokens, private keys, database passwords, session tokens, or real secret values belong here. Examples use placeholders only.

---

## 2026-09-08 — Intent → Plan → Execution Graph → Worker → Evidence → Verification → Decision

The compliance domain has now been extended around a canonical durable pipeline:

```text
Intent
  ↓
immutable normalized intent
  ↓
Policy → Plan
  ↓
durable execution graph
  ↓
real BullMQ worker execution
  ↓
provenance-bound evidence
  ↓
fresh verification
  ↓
authoritative control + final decision
```

Intent is normalized, versioned, deterministically hashed, and persisted immutably. Plans retain intent provenance and remain self-verifying and immutable. Plans are materialized into the existing durable graph rather than introducing a second execution state machine.

Worker-produced evidence is now written to the authoritative evidence record with source, provider, connection, resource, node, attempt, timestamp, and SHA-256 integrity metadata. Verification consumes fresh scan results and records its own durable verification result. Final decisions are derived from persisted evaluation/evidence/verification state and are blocked while relevant compliance nodes remain active.

Remediation remains approval-gated where the plan requires approval. The intended closed loop is therefore:

```text
detect → evaluate → propose remediation → approve → remediate → recollect → verify → decide
```

The implementation deliberately uses real PostgreSQL and Redis/BullMQ boundaries. A worker retry is not allowed to masquerade as a durable execution retry: plan-node jobs use one queue delivery attempt, while retry/resume is represented by a new durable PostgreSQL node attempt.

The public `/api/v1` boundary now exposes execution creation, durable graph/status, evidence, decisions, and execution controls. It is authenticated and organization-scoped. The dashboard remains a projection/client and is not an execution authority.

### Current contract direction

The stable product boundary is becoming:

- **Intent** — what outcome the customer wants and the scope/frameworks/rules that constrain it.
- **Plan** — the immutable, hashed explanation of work required to reach that outcome.
- **Execution Graph** — durable dependencies, approvals, attempts, and state.
- **Worker** — an authority-limited executor operating through real provider infrastructure.
- **Evidence** — provenance-bound observations produced by actual execution.
- **Verification** — fresh evidence used to prove whether remediation/evaluation actually changed the observed state.
- **Decision** — durable control-level and execution-level compliance outcomes derived from those records.

The next product work should preserve these contracts while making the reasoning semantics richer: applicability, evidence sufficiency, resource scope, remediation eligibility, verification confidence, and explicit decision rationale.

### Verification gate

The latest full CI run for the pipeline changes completed successfully with PostgreSQL 16, Redis 7, the tracked Vitest suite, the complete recorded suite, production Docker image build, and cleanup. The five-layer domain is not considered fully product-complete merely because its tables/functions exist; future changes must continue to prove the complete remediation → fresh verification → decision loop against real infrastructure.

---

## 2026-09-08 — Existing Reliability/Security Baseline

The preceding hardening cycle established PostgreSQL-only durable persistence, fail-closed audit/database behavior, authoritative sessions, lease fencing/recovery, cancellation and resume idempotency, real BullMQ/Redis dispatch, SSE/input hardening, graceful shutdown, dependency-update automation, and the no-mocks verification discipline.

The single living handover remains the source of architectural continuity. No separate dated handover addenda should be created.

---

## Current Engineering Rules

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
