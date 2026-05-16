# ComplianceFlow Internal Security & Privacy Controls

At ComplianceFlow, we believe in "Eating our own dog food." This document outlines the security controls protecting the platform that manages your cloud governance.

## 1. Data Privacy & Handling
*   **Zero-Persistence Credential Architecture**: We do not store your permanent cloud credentials. Access is obtained via temporary AWS STS tokens, which expire automatically after 1 hour.
*   **Prompt Sanitization**: Our LLM orchestrator (Gemini) interaction layer redacts potential secrets and account IDs before sending context to the model to prevent data leakage.
*   **Region Isolation**: All processing occurs within your specified AWS region; data does not leave your cloud perimeter except for anonymized metadata for report generation.

## 2. Infrastructure Security
*   **Least-Privilege Orchestrator**: Our internal agent operates under a restricted IAM role that can *only* assume client roles matching a strict `ComplianceFlow-Client-*` naming convention.
*   **Encrypted Secrets**: platform keys (SES, Gemini, DynamoDB) are managed via AWS Secrets Manager with automatic rotation.

## 3. Autonomous Safety (Blast Radius)
*   **Hardcoded Mutation Guard**: Destructive API calls (e.g., `DeleteVPC`, `DetachPolicy`) are blocked at the code level, regardless of AI instructions.
*   **Dry-Run Default**: All remediation suggestions must pass a dry-run simulation before execution.

## 4. Audit & Forensics
*   **Immutable Audit Trail**: Every AI decision, API call, and reasoning trace is logged to a write-once DynamoDB table.
*   **SES Signature**: Reports are cryptographically signed to ensure delivery integrity and non-repudiation.

---
*Questions? Contact security@complianceflow.ai*
