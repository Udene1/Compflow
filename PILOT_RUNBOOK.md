# Compflow Pilot Runbook

This runbook is the operational contract for a first production pilot. It intentionally avoids demo data and synthetic cloud success states.

## Pilot promise

Compflow should demonstrate this real loop:

**Connect → Verify → Scan → Understand → Recommend → Approve → Execute → Re-scan → Verify → Prove**

A successful pilot outcome is not merely a list of findings. The strongest outcome is a deterministic chain showing what was observed, what changed, what fresh evidence says now, and whether the exposure/risk actually improved.

## Before the pilot

### Platform

- Run Node.js 22+.
- PostgreSQL must be reachable and persistent.
- Redis must be reachable for BullMQ dispatch.
- Initialize the PostgreSQL schema during application startup/deployment.
- Set a high-entropy `AUTH_SECRET`.
- Configure either Google/GitHub OAuth or a short-lived pilot access code.
- Restrict `ALLOWED_DOMAINS` and/or `ALLOWED_GITHUB_ORGS` for a controlled pilot.
- Keep `REJECT_PERSONAL_EMAILS=true` for enterprise pilots unless explicitly required otherwise.
- Store production provider credentials only through the encrypted SecretStore/onboarding flow.
- Never place customer cloud credentials in `.env`, source control, queue payloads, or logs.

### Customer cloud access

Connect only the cloud accounts the pilot has authorized. Compflow supports the current provider registry for:

- AWS
- Azure
- GCP
- DigitalOcean
- Hetzner

Cloud verification must succeed before treating a connection as usable. Missing or invalid credentials must fail closed rather than produce a successful scan.

## First pilot workflow

1. Create the pilot organization and users.
2. Select the compliance objectives/frameworks required by the customer.
3. Register the customer's cloud connection.
4. Complete real provider verification.
5. Run the first scan through the durable queue.
6. Review findings and deterministic risk/exposure paths.
7. Select one low-blast-radius remediation candidate.
8. Review the remediation authority level and affected resource/path context.
9. Require the configured human approval for approval-gated actions.
10. Execute the real cloud operation.
11. Require the targeted post-remediation provider check to verify the changed control.
12. Run fresh reanalysis against a distinct provider scan.
13. Confirm fresh evidence, graph completeness, and deterministic risk are present.
14. Only then expose a security-effect claim. Equal or increased risk must not be described as a reduction.
15. Export/share the resulting audit evidence where appropriate.

## Remediation safety

Compflow's execution boundary is canonical-code driven. A provider must not choose an action from free-form finding text. The policy catalog determines the supported action, resource type, authority level, and approval requirement.

Authority levels are intentionally conservative:

`OBSERVE → RECOMMEND → SAFE_AUTO → APPROVAL_REQUIRED → HIGH_IMPACT_APPROVAL`

Do not bypass approval gates for a pilot. Start with reversible, low-blast-radius controls and expand only after the customer understands the workflow.

## What Compflow may claim

### Strong claim

A remediation can support a security-effect claim only when all of the following are present:

- the remediation reached `VERIFIED`;
- targeted control-verification evidence is fresh and cryptographically linked;
- the fresh reanalysis scan is distinct from the baseline;
- the fresh scan completed successfully and persisted provider resources/findings;
- fresh reanalysis evidence is cryptographically linked;
- exposure analysis completed against fresh evidence;
- deterministic risk is available;
- and there is measurable exposure-path removal or aggregate-risk reduction.

### Claims Compflow must not make

- Do not claim compromise from a correlated relationship.
- Do not claim exploitation from an exposure path alone.
- Do not claim security improvement merely because a cloud API returned success.
- Do not treat an incomplete fresh graph as evidence that paths disappeared.
- Do not treat equal or higher risk as a successful reduction.
- Do not present inferred/correlated relationships as provider-verified relationships.
- Do not present an AI explanation as authoritative security evidence.

## Pilot acceptance checklist

- [ ] PostgreSQL persistence survives application restart.
- [ ] Redis/BullMQ worker is healthy.
- [ ] Authentication and organization isolation are enabled.
- [ ] Customer cloud connection verifies with real credentials.
- [ ] Initial scan produces durable findings/evidence.
- [ ] Findings map to deterministic controls and risk.
- [ ] Exposure paths preserve provenance.
- [ ] Remediation policy and authority gates are enforced.
- [ ] Approval is required where policy says it is required.
- [ ] Real remediation execution is auditable.
- [ ] Post-remediation verification uses fresh provider evidence.
- [ ] Reanalysis uses a distinct fresh scan.
- [ ] Security proof requires dual evidence lineage.
- [ ] Security proof requires measurable reduction.
- [ ] AI cannot introduce ungrounded findings, evidence, paths, or compromise claims.
- [ ] Failed provider authentication is recorded as failure, not success.
- [ ] No customer secrets appear in logs, queue payloads, or API responses.
- [ ] CI is green before inviting the pilot customer.

## Pilot operating principle

If the system cannot prove a result from durable, fresh, provider-backed evidence, the correct product behavior is **inconclusive** — not a prettier success message.
