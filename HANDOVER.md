# ComplianceFlow AI — Complete Technical Handover

> **What is this?** A comprehensive guide to the ComplianceFlow AI codebase. Written so that someone without prior compliance knowledge can understand the code, the architecture, every integration, and why each piece exists.

---

## Table of Contents

1. [What Does This Product Do?](#1-what-does-this-product-do)
2. [Quick Start (Run It Locally)](#2-quick-start)
3. [Architecture Overview](#3-architecture-overview)
4. [Folder Structure & File Map](#4-folder-structure--file-map)
5. [The Scan Pipeline (How a Scan Works End-to-End)](#5-the-scan-pipeline)
6. [Cloud Providers — What Gets Scanned](#6-cloud-providers--what-gets-scanned)
7. [Compliance Frameworks Explained](#7-compliance-frameworks-explained)
8. [The AI Reasoning Layer (Gemini)](#8-the-ai-reasoning-layer-gemini)
9. [The Remediation Engine](#9-the-remediation-engine)
10. [SOC2 Third-Party Auditor Portal](#10-soc2-third-party-auditor-portal)
11. [Custom Policy Rules Engine](#11-custom-policy-rules-engine)
12. [Autonomous Scheduled Sweeps](#12-autonomous-scheduled-sweeps)
13. [Every Integration & Why It Was Chosen](#13-every-integration--why-it-was-chosen)
14. [Database & Queue Architecture](#14-database--queue-architecture)
15. [Security Model & Credential Handling](#15-security-model--credential-handling)
16. [API Endpoints Reference](#16-api-endpoints-reference)
17. [Frontend Dashboard](#17-frontend-dashboard)
18. [Infrastructure & Deployment](#18-infrastructure--deployment)
19. [Testing Strategy](#19-testing-strategy)
20. [Environment Variables](#20-environment-variables)
21. [Production Domains & URLs](#21-production-domains--urls)
22. [Known Limitations & Future Roadmap](#22-known-limitations--future-roadmap)
23. [Glossary of Compliance Terms](#23-glossary-of-compliance-terms)

---

## 1. What Does This Product Do?

**ComplianceFlow AI** is a cloud security compliance platform that:

1. **Connects** to a customer's cloud account (AWS, Azure, GCP, DigitalOcean, or Hetzner).
2. **Scans** every piece of infrastructure (servers, databases, storage, firewalls, encryption, IAM roles, etc.) in real-time.
3. **Maps** each finding to regulatory compliance controls (SOC2, ISO 27001, HIPAA, GDPR, PCI-DSS).
4. **Decides** using Google Gemini AI whether a finding is safe to auto-fix or must be escalated to a human.
5. **Fixes** low-risk issues automatically (e.g., enabling encryption, turning on backups, closing an open port).
6. **Generates** executive PDF and HTML reports, signed evidence packages, and emails them to the customer.
7. **Provides** an auditor-ready evidence portal with cryptographic proof of compliance for third-party auditors.

**In plain English:** Imagine hiring a senior cloud security engineer who works 24/7, checks your entire cloud infrastructure every day, fixes things that are obviously wrong, flags things that need human judgment, and writes audit-ready reports — that's what this software does automatically.

---

## 2. Quick Start

### Prerequisites
- **Node.js 20+**
- **Docker & Docker Compose** (for production)
- A `.env` file (copy `.env.example` → `.env` and fill in your keys)

### Run Locally (Development)
```bash
# Install dependencies
npm install

# Start the API server
node server.js

# The API will be available at http://localhost:3000
# Health check: http://localhost:3000/health
```

### Run with Docker (Production)
```bash
# This starts the app + Redis + PostgreSQL
docker-compose up -d

# Verify
curl http://localhost:3000/health
# → {"status":"OK","timestamp":"..."}
```

### Run Tests
```bash
# Run all automated tests
npm test

# Run tests AND save timestamped results
npm run test:record
```

---

## 3. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                     COMPLIANCEFLOW AI ENGINE                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  ┌──────────────┐  │
│  │   AWS SDK    │  │  Azure SDK  │  │ GCP SDK  │  │ DO / Hetzner │  │
│  │  (22 svcs)   │  │  (18 svcs)  │  │(15 svcs) │  │  API Client  │  │
│  └──────┬──────┘  └──────┬──────┘  └────┬─────┘  └──────┬───────┘  │
│         │                │              │               │           │
│         └────────┬───────┴──────┬───────┴───────┬───────┘           │
│                  ▼              ▼               ▼                   │
│          ┌──────────────────────────────────┐                       │
│          │      core/scanner.js             │                       │
│          │  (Unified scan dispatcher)       │                       │
│          └──────────────┬──────────────────┘                       │
│                         │                                           │
│                         ▼                                           │
│          ┌──────────────────────────────────┐                       │
│          │  core/controls.js (ControlMatrix)│                       │
│          │  Maps findings → SOC2, GDPR,     │                       │
│          │  HIPAA, ISO 27001 controls       │                       │
│          └──────────────┬──────────────────┘                       │
│                         │                                           │
│                         ▼                                           │
│          ┌──────────────────────────────────┐                       │
│          │  core/gemini.js (AI Reasoning)   │                       │
│          │  "Is this safe to auto-fix?"     │                       │
│          │  AUTO_FIX vs ESCALATE decision   │                       │
│          └──────────────┬──────────────────┘                       │
│                         │                                           │
│              ┌──────────┴──────────┐                                │
│              ▼                     ▼                                │
│    ┌─────────────────┐  ┌──────────────────┐                       │
│    │ AUTO-FIX:       │  │ ESCALATE:        │                       │
│    │ Remediator runs │  │ Advisory logged, │                       │
│    │ safe cloud fix  │  │ human reviews    │                       │
│    └────────┬────────┘  └──────────────────┘                       │
│             │                                                       │
│             ▼                                                       │
│    ┌──────────────────────────────────────────┐                     │
│    │  core/reporter.js                        │                     │
│    │  Generates PDF + HTML executive reports  │                     │
│    │  Emails via AWS SES                      │                     │
│    └──────────────────────────────────────────┘                     │
│                                                                      │
│    ┌──────────────────────────────────────────┐                     │
│    │  core/auditor_portal.js                  │                     │
│    │  Generates signed evidence packages      │                     │
│    │  for third-party compliance auditors     │                     │
│    └──────────────────────────────────────────┘                     │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│  BACKGROUND INFRASTRUCTURE                                           │
│  ┌────────────┐  ┌───────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ PostgreSQL │  │   Redis   │  │   BullMQ     │  │  DynamoDB    │ │
│  │ (Jobs,     │  │  (Queue   │  │  (Worker     │  │  (Audit      │ │
│  │  Tenants)  │  │   broker) │  │   dispatch)  │  │   Trail)     │ │
│  └────────────┘  └───────────┘  └──────────────┘  └──────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Folder Structure & File Map

```
compliance-flow/
│
├── server.js                    # Express HTTP server entry point
├── worker.js                    # Background job worker (scan → reason → fix → report)
├── scheduler.js                 # Autonomous daily/weekly scheduled sweep engine
├── evidence.js                  # Frontend evidence capture & audit bundle download (browser-side)
├── cloud-connect.js             # Frontend cloud credential input & OAuth flow (browser-side)
├── tenant-manager.js            # Frontend tenant CRUD & scan trigger UI (browser-side)
├── drift-engine.js              # Configuration drift detection between scan snapshots
├── chat-engine.js               # Frontend AI chat assistant for compliance questions
├── frameworks.js                # Frontend framework selector (SOC2/GDPR/HIPAA/ISO)
├── scan-history.js              # Frontend scan history timeline viewer
├── agent.js                     # Main AI agent orchestration (scan → reason → fix)
│
├── core/                        # ═══ CORE BACKEND MODULES ═══
│   ├── scanner.js               # Unified scan dispatcher (routes to provider)
│   ├── controls.js              # ControlMatrix: maps findings → regulatory controls
│   ├── compliance_mapper.js     # Cross-framework enrichment & conflict detection
│   ├── gemini.js                # Google Gemini AI reasoning engine
│   ├── remediator.js            # Unified remediation dispatcher (routes to provider)
│   ├── policy_engine.js         # Custom organization governance policies
│   ├── auditor_portal.js        # SOC2 third-party auditor evidence portal
│   ├── reporter.js              # PDF/HTML report generation + SES email delivery
│   ├── mailer.js                # Low-level SES email template engine
│   ├── db.js                    # PostgreSQL connection pool (with memory fallback)
│   ├── queue.js                 # BullMQ/Redis job queue (with fallback)
│   ├── jobs.js                  # Job lifecycle manager (create, update, complete)
│   ├── registry.js              # Tenant/client CRUD in PostgreSQL
│   ├── credentials.js           # AWS STS AssumeRole for cross-account access
│   ├── client-vault.js          # Legacy client registry (JSON file)
│   ├── audit.js                 # DynamoDB audit trail writer
│   ├── logger.js                # Centralized structured logger
│   ├── monitoring.js            # Job monitoring & failure tracking
│   │
│   └── providers/               # ═══ CLOUD PROVIDER MODULES ═══
│       ├── aws.js               # AWS scanner (22 services, 852 lines)
│       ├── aws_remediator.js    # AWS auto-fix engine (512 lines)
│       ├── azure.js             # Azure scanner (18 services, 903 lines)
│       ├── azure_remediator.js  # Azure auto-fix engine
│       ├── gcp.js               # GCP scanner (15 services)
│       ├── gcp_remediator.js    # GCP auto-fix engine
│       ├── digitalocean.js      # DigitalOcean scanner
│       ├── digitalocean_remediator.js
│       ├── hetzner.js           # Hetzner scanner
│       └── hetzner_remediator.js
│
├── api/                         # ═══ HTTP API ROUTE HANDLERS ═══
│   ├── scan.js                  # POST /api/scan — trigger a scan
│   ├── auditor.js               # /api/auditor/* — auditor token, export, verify
│   ├── validate.js              # /api/validate — credential validation
│   ├── tenants.js               # /api/tenants — CRUD tenant management
│   ├── chat.js                  # POST /api/chat — AI compliance assistant
│   ├── remediate.js             # POST /api/remediate — manual remediation
│   ├── job-status.js            # GET /api/job-status — poll job state
│   ├── job-stream.js            # GET /api/job-stream — SSE live job stream
│   ├── audit.js                 # GET /api/audit — fetch audit trail logs
│   ├── trigger.js               # POST /api/trigger — dispatch scan for tenant
│   └── logs.js                  # GET /api/logs — fetch structured logs
│
├── tests/                       # ═══ TEST SUITES ═══
│   ├── unit/                    # Vitest unit tests (auditor_portal, policy_engine, etc.)
│   ├── integration/             # Integration tests (scanner, remediator, reporter)
│   ├── e2e/                     # End-to-end multi-cloud tests
│   └── results/                 # Timestamped test execution archives
│
├── scripts/
│   └── record_all_tests.js      # Runs all test suites & saves timestamped results
│
├── Dockerfile                   # Node.js 20 Alpine container image
├── docker-compose.yml           # Full stack: app + Redis + PostgreSQL
├── package.json                 # Dependencies & npm scripts
├── .env.example                 # Environment variable template
└── README.md                    # Project overview with architecture diagram
```

---

## 5. The Scan Pipeline

Here's exactly what happens when a scan is triggered, step by step:

### Step 1: Trigger
A scan is triggered one of three ways:
- **Manual:** A user clicks "Scan Now" in the dashboard, which calls `POST /api/trigger`.
- **Scheduled:** The `scheduler.js` cron fires on a daily/weekly schedule.
- **API:** An external system calls `POST /api/scan` directly.

### Step 2: Job Creation
```
api/scan.js (or scheduler.js)
  → core/jobs.js: createJob(clientId)
    → Inserts a row into PostgreSQL `jobs` table with status: 'queued'
    → Returns a unique jobId (UUID)
```

### Step 3: Queue Dispatch
```
core/queue.js: enqueueJob({ jobId, clientId, provider, credentials })
  → If Redis is available: dispatches to BullMQ 'scan_jobs' queue
  → If Redis is down: falls back to direct synchronous execution
```

### Step 4: Worker Picks Up the Job
```
worker.js: handler(jobData)
  → Resolves credentials based on provider type:
      AWS:   STS AssumeRole (cross-account)
      Azure: Service Principal (tenantId, clientId, clientSecret)
      GCP:   Service Account JSON key
      DO/Hetzner: API Bearer token
```

### Step 5: Deep Infrastructure Scan
```
core/scanner.js: runScan(provider, credentials)
  → Dynamically imports the correct provider scanner:
      'aws'    → core/providers/aws.js
      'azure'  → core/providers/azure.js
      'gcp'    → core/providers/gcp.js
      'do'     → core/providers/digitalocean.js
      'hetzner'→ core/providers/hetzner.js
  → Scanner calls the cloud provider's native API for EVERY service
  → Returns: { resources: [{name, type, severity, issue, region, ...}] }
```

### Step 6: Control Matrix Mapping
```
core/controls.js: ControlMatrix[technicalId]
  → Each finding (e.g., 'S3_PUBLIC') is mapped to:
      SOC2:    CC6.1, CC6.6
      GDPR:    Art 32(1)(a)
      HIPAA:   §164.312(a)(1)
      ISO27001: A.9.1.1
```

### Step 7: AI Reasoning
```
core/gemini.js: evaluateWithGemini(finding)
  → Sends the finding to Google Gemini 1.5 Flash
  → Prompt asks: "Is this safe to auto-fix?"
  → Returns: { action: 'AUTO_FIX' | 'ESCALATE', reason, safetyScore }
  → Falls back to heuristic rules if API is unavailable
```

### Step 8: Remediation
```
core/remediator.js: runRemediation(provider, credentials, type, name, issue)
  → ONLY executes if:
      1. Gemini said AUTO_FIX (or heuristic fallback agreed)
      2. The tenant has autoRemediate: true
      3. The finding passes the SAFE_WHITELIST blast-radius check
  → If blocked by whitelist, returns an Advisory instead of executing
```

### Step 9: Report Generation & Delivery
```
core/reporter.js: generatePdfReport() + generateReport() + sendReport()
  → Compiles executive PDF with:
      - Compliance score
      - Critical findings
      - Multi-framework compliance matrix
  → Sends HTML email with PDF attachment via AWS SES
```

### Step 10: Audit Trail
```
core/audit.js: saveAuditLog()
  → Writes immutable log to AWS DynamoDB: CompFlowAuditTable
  → Records: clientId, timestamp, level, message, details
```

---

## 6. Cloud Providers — What Gets Scanned

### AWS (22 Services) — `core/providers/aws.js`
| Service | What We Check |
|:--------|:-------------|
| S3 | Public access, versioning, encryption, logging, lifecycle |
| IAM | Root MFA, access key rotation, stale roles, excessive policies |
| EC2 | Open security groups, flow logs, IMDSv2, public IPs, volumes |
| RDS | Public access, encryption, backups, multi-AZ |
| KMS | Key rotation |
| CloudTrail | Multi-region logging, log validation, encryption |
| GuardDuty | Threat detection enabled |
| Lambda | Function configuration |
| WAF/Shield | Web application firewall, DDoS protection |
| Secrets Manager | Secret rotation |
| CloudWatch | Alarms, log retention |
| Config | Configuration recording |
| DynamoDB | PITR (point-in-time recovery) |
| EKS | Cluster security, RBAC |
| Redshift | Encryption, public access |
| API Gateway | HTTPS, WAF, X-Ray tracing |
| CloudFront | HTTPS, TLS version, WAF |
| SQS/SNS | Encryption |

### Azure (18 Services) — `core/providers/azure.js`
| Service | What We Check |
|:--------|:-------------|
| App Service | HTTPS enforcement, TLS version, managed identity |
| Storage Accounts | Public access, encryption, HTTPS-only |
| SQL Databases | Firewall rules, auditing, TDE |
| AKS | RBAC, API server auth, network policy |
| Key Vault | Soft delete, firewall, purge protection |
| Cosmos DB | CMK encryption |
| ACR | Admin user disabled, public access |
| VMs | Public IPs, unmanaged disks, extensions |
| NSGs | Open ports, overly permissive rules |
| Front Door | WAF policies |
| Logic Apps | IP restrictions |
| API Management | HTTPS enforcement |
| Service Bus | Encryption |
| Azure Policy | Compliance health |
| Diagnostic Settings | Log export configuration |

### GCP (15 Services) — `core/providers/gcp.js`
| Service | What We Check |
|:--------|:-------------|
| GCS | Public access, versioning, uniform access, logging |
| GKE | Master auth networks, shielded nodes |
| BigQuery | Public datasets, CMEK encryption |
| Cloud SQL | SSL enforcement, automated backups |
| Compute Engine | Shielded VMs, serial port, default VPC |
| KMS | Key rotation |
| Secret Manager | Secret rotation |
| Pub/Sub | CMEK encryption |
| Snapshots | Stale snapshot cleanup |
| IAM | Service account key rotation |

### DigitalOcean — `core/providers/digitalocean.js`
Droplets, firewalls, databases, load balancers, volumes, Kubernetes clusters.

### Hetzner — `core/providers/hetzner.js`
Servers, firewalls, load balancers, volumes, floating IPs, networks.

---

## 7. Compliance Frameworks Explained

> **What is a compliance framework?** A set of rules that say *"if you store customer data, you must do X, Y, Z."* Different industries have different rules.

### SOC2 Type II
- **Who needs it:** Any SaaS company selling to US businesses.
- **What it checks:** Security, Availability, Processing Integrity, Confidentiality, Privacy.
- **Our controls:** CC6.1 (Access), CC6.6 (Network), CC6.7 (Encryption), CC7.2 (Monitoring).
- **Example:** "Is this S3 bucket publicly accessible?" → violates CC6.1 (Logical Access Controls).

### ISO 27001
- **Who needs it:** International companies, enterprise software.
- **What it checks:** Information Security Management System (ISMS).
- **Our controls:** A.9.x (Access Control), A.12.x (Operations Security), A.13.x (Network Security).

### HIPAA
- **Who needs it:** Healthcare companies handling patient data (PHI).
- **What it checks:** Technical safeguards for protecting health information.
- **Our controls:** §164.312(a)(1) (Access Control), §164.312(e)(1) (Transmission Security).

### GDPR
- **Who needs it:** Anyone handling EU citizen data.
- **What it checks:** Data protection and privacy.
- **Our controls:** Art 32 (Security of Processing), Art 30 (Records of Processing), Art 5(1)(e) (Storage Limitation).

### How the Cross-Walk Works
File: `core/controls.js` — the `ControlMatrix` object.

Each "technical finding" (like `S3_PUBLIC`) maps to controls across ALL frameworks simultaneously:
```javascript
'S3_PUBLIC': {
    name: 'Public Data Exposure',
    soc2: ['CC6.1', 'CC6.6'],      // SOC2 controls violated
    gdpr: ['Art 32(1)(a)'],         // GDPR articles violated
    hipaa: ['§164.312(a)(1)'],      // HIPAA sections violated
    iso27001: ['A.9.1.1']           // ISO 27001 annexes violated
}
```

The `core/compliance_mapper.js` then:
1. Enriches each finding with these mappings.
2. Adds SHA-256 evidence hashes for audit trail integrity.
3. Detects cross-framework conflicts (e.g., GDPR requires 72-hour breach notification, HIPAA allows 60 days).

---

## 8. The AI Reasoning Layer (Gemini)

**File:** `core/gemini.js`

### Why Gemini?
We needed an LLM that could evaluate cloud security findings and make nuanced remediation decisions. Google Gemini 1.5 Flash was chosen because:
- **Fast inference** — decisions in <1 second.
- **Structured output** — reliably returns JSON.
- **Cost-effective** — Flash tier keeps per-scan AI costs minimal.
- **Google Cloud native** — pairs well with GCP scanning.

### How It Works
1. Each finding (e.g., "S3 bucket has public access") is sent to Gemini with a security engineering prompt.
2. Gemini evaluates **blast radius** (will the fix break production?), **confidence** (is this a standard fix?), and **lockout risk** (could this lock out users?).
3. Returns `AUTO_FIX` (safe to auto-remediate) or `ESCALATE` (needs human review) with a safety score (0-1).

### Fallback Reasoning
If the Gemini API is unavailable (rate limit, outage), a local heuristic in `fallbackReasoning()` handles decisions:
- Safe issues (public access, backups disabled, encryption disabled, logging disabled) → `AUTO_FIX`.
- Everything else → `ESCALATE`.

### Retry Strategy
Uses exponential backoff: 1s → 2s → 4s. Maximum 3 retries.

---

## 9. The Remediation Engine

**Files:** `core/remediator.js` + `core/providers/*_remediator.js`

### Blast Radius Protection
This is the most critical safety mechanism. Before executing any fix, the remediator checks a `SAFE_WHITELIST`:

```javascript
const SAFE_WHITELIST = {
    'S3 Bucket': ['Public access', 'Versioning', 'Default encryption', 'Lifecycle'],
    'Security Group': ['port 22', 'RDP', '3389'],
    'RDS Database': ['Backup retention', 'Publicly accessible'],
    // ... only well-understood, non-destructive fixes
};
```

**If a finding is NOT in the whitelist, it is automatically escalated as an Advisory** — even if Gemini said AUTO_FIX. This prevents the AI from hallucinating and executing a dangerous fix.

### What Gets Auto-Fixed (Examples)
| Finding | Auto-Fix Action |
|:--------|:---------------|
| S3 bucket has public access | Block public access (`PutPublicAccessBlockCommand`) |
| S3 bucket missing encryption | Enable AES-256 default encryption |
| S3 bucket missing versioning | Enable versioning |
| Security group open on port 22 | Revoke 0.0.0.0/0 SSH, add restricted CIDR |
| RDS publicly accessible | Modify instance to `PubliclyAccessible: false` |
| KMS key rotation disabled | Enable automatic annual rotation |
| CloudTrail not multi-region | Create multi-region trail |
| GuardDuty disabled | Create detector |

### What Gets Escalated (Advisory)
- IAM policy changes (risk of lockout)
- VPC/networking changes (risk of connectivity loss)
- Database engine changes
- Anything not in the whitelist

---

## 10. SOC2 Third-Party Auditor Portal

**Files:** `core/auditor_portal.js`, `api/auditor.js`, `evidence.js`

### What Problem Does This Solve?
When a company undergoes a SOC2 Type II audit, an external CPA firm (like Schellman, Prescient, A-LIGN, or Coalfire) needs to review evidence that the company's cloud infrastructure meets security controls. Traditionally, this is a manual process involving screenshots, spreadsheets, and weeks of back-and-forth.

This portal automates the entire process into a cryptographically provable, read-only workflow.

---

### 🌐 How the Auditor Portal Is Accessed (Step-by-Step)

The Auditor Portal can be accessed through **two complementary channels**:

#### Method A: Direct UI / One-Click Export (Compliance Manager Flow)
1. Navigate to the ComplianceFlow Dashboard at `https://compflow.icu` (or `app.html`).
2. Open the **Evidence** tab or click **Export Audit Bundle**.
3. `window.Evidence.exportAuditorBundle()` triggers:
   - Compiles all scanned assets into `evidence_manifest.json` with client-side SHA-256 fingerprints.
   - Attaches SOC2, ISO 27001, and HIPAA control cross-walk proofs.
   - Downloads a `.json` / `.zip` provable evidence package ready to upload to the auditor's Vanta/Drata/Audit dashboard.

#### Method B: Auditor API & Portal Access Token (Independent External Auditor Flow)
For external CPAs who want read-only API access directly to the live audit proof:

1. **Tenant issues a time-limited Auditor Token:**
   ```bash
   curl -X POST https://api.compflow.icu/api/auditor/token \
     -H "Content-Type: application/json" \
     -d '{
       "tenantId": "org_acme_corp",
       "auditorEmail": "lead_auditor@schellman.com",
       "expiryHours": 72
     }'
   ```
   **Response:**
   ```json
   {
     "success": true,
     "token": "eyJwYXlsb2FkIjp7InRlbmFudElkIjoib3JnX2FjbWVfY29ycCIsImF1ZGl0b3JFbWFpbCI6ImxlYWRfYXVkaXRvckBzY2hlbGxtYW4uY29tIiwicm9sZSI6IkFVRElUT1JfUkVBRE9OTFkiLCJpc3N1ZWRBdCI6IjIwMjYtMDgtMjRUMTQ6Mjg6MTkuNjQ5WiIsImV4cGlyZXNBdCI6IjIwMjYtMDgtMjdUMTQ6Mjg6MTkuNjQ5WiJ9LCJzaWduYXR1cmUiOiI1YjA5Yzg3NzJmYmM2YjM1YzVjNDlkYTI5ODUzYmU2YmFhZjAzZmNmZjkyNTRiYWIzODcxZThjODk1NDUzMDRlIn0",
     "expiresAt": "2026-08-27T14:28:19.649Z",
     "role": "AUDITOR_READONLY"
   }
   ```

2. **Auditor exports the full cryptographically signed evidence bundle:**
   ```bash
   curl -X GET "https://api.compflow.icu/api/auditor/export?token=YOUR_AUDITOR_TOKEN"
   ```
   **What the auditor receives:**
   - `evidence_manifest.json`: Every asset and setting with an individual SHA-256 cryptographic fingerprint.
   - `control_proof_soc2.json`: Control mapping against CC6.1, CC6.6, CC6.8, CC7.2.
   - `control_proof_iso27001.json`: Annex A controls (A.9, A.12, A.13).
   - `control_proof_hipaa.json`: §164.312 safeguards.
   - `executive_summary.pdf`: Embedded, base64-encoded PDF executive report.
   - `audit_trail.log`: Full chronological event log.
   - `digitalSignature`: HMAC-SHA256 digital signature over the entire package.

3. **Auditor validates the package integrity & proves zero tampering:**
   ```bash
   curl -X POST https://api.compflow.icu/api/auditor/verify \
     -H "Content-Type: application/json" \
     -d '{
       "evidencePackage": { ...downloaded_package... }
     }'
   ```
   **Response:**
   ```json
   {
     "verified": true,
     "tenantName": "Acme Corp",
     "generatedAt": "2026-08-24T14:28:19.649Z",
     "totalAssets": 10,
     "totalDeficiencies": 0,
     "message": "Cryptographic proof verified. Package matches official immutable audit trail."
   }
   ```

---

### Cryptographic Verification Chain
```
Discovered Asset → SHA-256 fingerprint per asset → Evidence Manifest (JSON)
                                                        ↓
                                          HMAC-SHA256 Digital Signature
                                          (using server signing secret)
                                                        ↓
                                           digitalSignature (Hex token)
                                                        ↓
                                   POST /api/auditor/verify asserts validity
```

If anyone modifies a single character or byte in the evidence manifest after generation, `verifyAuditorPackage()` detects the signature or checksum mismatch and returns `verified: false`.

---

## 11. Custom Policy Rules Engine

**File:** `core/policy_engine.js`

### What This Does
Beyond standard compliance frameworks, organizations often have their own internal rules. For example:
- "We only deploy in the US and EU" (data sovereignty).
- "Every resource must have an `Environment` and `Owner` tag" (cost allocation).
- "Only ports 443 and 8443 should be open publicly" (network hardening).

### Built-In Policy Templates

| Policy | ID | What It Checks |
|:-------|:---|:--------------|
| Restricted Regions | `POLICY_UNAUTHORIZED_REGION` | Flags resources outside approved regions |
| Mandatory Tags | `POLICY_MISSING_TAGS` | Flags resources missing required tags |
| Port Whitelist | `POLICY_DISALLOWED_PORT` | Flags open ports not on the approved list |
| Mandatory Backups | `POLICY_MANDATORY_BACKUPS` | Flags resources without automated backups |

### How to Configure
Pass a `customPolicies` object when triggering a scan:
```javascript
{
    allowedRegions: ['us-east-1', 'eu-west-1'],
    requiredTags: ['Environment', 'Owner', 'DataClassification'],
    allowedInboundPorts: [443, 8443]
}
```

Policy violations are injected into the scan results alongside standard compliance findings.

---

## 12. Autonomous Scheduled Sweeps

**File:** `scheduler.js`

### What This Does
Instead of manually triggering scans, the scheduler runs automatically on a cron schedule (daily or weekly) and scans ALL active tenants.

### Flow
1. Loads all tenants from PostgreSQL where `status !== 'paused'`.
2. Filters by schedule frequency (`daily`, `weekly`, `continuous`).
3. For each tenant:
   - Creates a job record in PostgreSQL.
   - If `USE_QUEUE=true`: dispatches to BullMQ for async processing.
   - Otherwise: executes the scan directly.
4. After each scan, generates an HTML compliance report and emails it via AWS SES.

### Trigger Methods
- **Cron:** Set up an external cron (e.g., AWS EventBridge, systemd timer) to `POST /api/trigger`.
- **HTTP:** `POST /api/trigger { frequency: 'daily' }`.

---

## 13. Every Integration & Why It Was Chosen

### Runtime & Language
| Technology | Why |
|:-----------|:----|
| **Node.js 20** | Async I/O is perfect for making hundreds of parallel cloud API calls. ESM modules for modern import/export syntax. |
| **Express.js** | Minimal, battle-tested HTTP framework. Chosen over Fastify/Hapi for simplicity and ecosystem size. |

### AI / LLM
| Technology | Why |
|:-----------|:----|
| **Google Gemini 1.5 Flash** | Fast structured JSON output, low latency (<1s), cost-effective for per-finding evaluation. Better structured output compliance than GPT-4 at the time of selection. |
| **`@google/generative-ai`** | Official Google AI SDK for Node.js. |

### Cloud SDKs
| Technology | Why |
|:-----------|:----|
| **AWS SDK v3 (`@aws-sdk/client-*`)** | Modular SDK — only import the services you need, reducing bundle size. Official AWS SDK for JavaScript. |
| **Azure SDK (`@azure/arm-*`, `@azure/identity`)** | Official Microsoft SDKs for Azure Resource Manager. Each service has its own package. |
| **Google Cloud SDK (`@google-cloud/*`)** | Official Google Cloud client libraries. |
| **`digitalocean` npm** | Community SDK for DigitalOcean API v2. |
| **`hcloud-js`** | Community SDK for Hetzner Cloud API. |

### Database & Queue
| Technology | Why |
|:-----------|:----|
| **PostgreSQL 16** | Relational DB for tenant management and job tracking. JSONB columns for flexible log storage. Chosen over MongoDB for ACID compliance (important for audit trails). |
| **Redis 7** | In-memory message broker for BullMQ job queue. Sub-millisecond dispatch latency. |
| **BullMQ** | Production-grade job queue built on Redis. Supports retries, exponential backoff, concurrency control, and dead letter queues. Chosen over RabbitMQ for simpler deployment (just needs Redis). |
| **AWS DynamoDB** | NoSQL audit trail storage. Serverless, auto-scaling, built-in TTL for data retention compliance. Chosen for the audit trail because it's append-only, highly durable, and works in serverless (Lambda) mode. |

### Reporting & Email
| Technology | Why |
|:-----------|:----|
| **PDFKit** | Pure JavaScript PDF generation. No external dependencies (no wkhtmltopdf, no headless Chrome). Generates compliance reports with headers, tables, and styled text. |
| **Nodemailer + AWS SES** | Nodemailer is the standard Node.js email library. SES provides high-deliverability transactional email at $0.10/1000 emails. Chosen over SendGrid/Mailgun for AWS ecosystem integration. |

### Cryptography
| Technology | Why |
|:-----------|:----|
| **Node.js `crypto` (built-in)** | SHA-256 hashing for evidence fingerprinting. HMAC-SHA256 for digital signatures. `timingSafeEqual` for constant-time signature comparison (prevents timing attacks). No external crypto library needed. |

### Frontend
| Technology | Why |
|:-----------|:----|
| **Vanilla HTML/CSS/JS** | Single-page dashboard (`app.html`). No React/Vue/Angular build step. Deployable as a static file on any CDN. Frontend communicates with API via `fetch()`. |

### DevOps, Security & Rate Limiting
| Technology | Why |
|:-----------|:----|
| **`express-rate-limit`** | Application-level DoS protection and compute-throttling. Enforces tier-based request ceilings (300 req/15min on general API, 30 req/5min on heavy scan/AI endpoints). |
| **Docker (Node.js 20 Alpine)** | Lightweight container (~120MB). Multi-arch support (amd64/arm64). Alpine Linux for minimal attack surface. |
| **Docker Compose** | Single command to spin up the full stack (app + Redis + PostgreSQL) with health checks and volume persistence. |
| **Cloudflare** | DNS management, Edge DDoS mitigation, and SSL termination for `compflow.icu` and `api.compflow.icu`. |

---

## 14. Database & Queue Architecture

### PostgreSQL Tables

#### `tenants` — Registered cloud environments
```sql
CREATE TABLE tenants (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(64) NOT NULL,       -- 'aws', 'azure', 'gcp', 'digitalocean', 'hetzner'
    role_arn TEXT,                        -- AWS IAM Role ARN (null for non-AWS)
    api_token TEXT,                       -- API token (DO, Hetzner)
    email VARCHAR(255),                   -- Reporting email
    auto_remediate BOOLEAN DEFAULT false, -- Allow auto-fixes?
    status VARCHAR(32) DEFAULT 'active',  -- 'active', 'paused', 'disabled'
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

#### `jobs` — Scan job lifecycle tracking
```sql
CREATE TABLE jobs (
    job_id VARCHAR(64) PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL,
    scan_type VARCHAR(32),               -- 'on_demand' or 'scheduled'
    status VARCHAR(32),                  -- 'queued', 'in_progress', 'completed', 'failed'
    progress INT DEFAULT 0,             -- 0-100 percentage
    logs JSONB DEFAULT '[]',            -- Array of {timestamp, level, message}
    resources JSONB DEFAULT '[]',       -- Final scan results
    error_message TEXT,
    created_at TIMESTAMP,
    completed_at TIMESTAMP,
    expires_at INT                       -- Unix timestamp TTL (7 days)
);
```

### Redis (BullMQ Queue)
- Queue name: `scan_jobs`
- Concurrency: 5 workers
- Retry: 3 attempts with exponential backoff (1s, 2s, 4s)
- Failed jobs are retained for debugging; completed jobs are auto-removed.

### DynamoDB (Audit Trail)
- Table: `CompFlowAuditTable`
- Partition Key: `clientId`
- Sort Key: `timestamp`
- TTL: 7-day expiry per item
- Stores every scan event, remediation action, and report delivery.

### Graceful Fallbacks
- **No PostgreSQL?** `core/db.js` falls back to an in-memory `MemoryFallbackPool` that simulates basic queries. Tests run without a database.
- **No Redis?** `core/queue.js` returns a fallback object and the worker processes jobs synchronously (direct mode).

---

## 15. Security Model & Credential Handling

### Principle: ComplianceFlow Never Stores Customer Cloud Credentials

#### AWS: Cross-Account STS AssumeRole
- Customer creates an IAM Role in THEIR account with read-only permissions.
- They add ComplianceFlow's AWS account as a trusted principal.
- We use `STS AssumeRole` to get **temporary** credentials (1-hour TTL).
- A unique `ExternalId` per customer prevents the "Confused Deputy" attack.
- Our platform IAM user has ONLY `sts:AssumeRole` and `ses:SendEmail` permissions.

#### Azure: Service Principal
- Customer creates a Service Principal with Reader role.
- Credentials (tenantId, clientId, clientSecret) are used to authenticate via `@azure/identity`.

#### GCP: Service Account
- Customer creates a Service Account with viewer permissions.
- JSON key file is used for authentication.

#### DigitalOcean / Hetzner: API Tokens
- Customer generates a read-only API token.
- Token is stored in PostgreSQL (encrypted at rest via disk encryption).

### Frontend Credential Obfuscation
Credentials entered in the browser UI are XOR-obfuscated before transit:
```javascript
const XOR_KEY = 'CompFlow_Guard_2026';
// XOR each character, then base64 encode
```
This is **not encryption** — it's obfuscation to prevent plaintext credential exposure in browser dev tools and network logs. In production, HTTPS (TLS 1.3) provides the actual transport encryption.

### Auditor Token Security
- Tokens are HMAC-SHA256 signed and base64url encoded.
- Contain embedded expiry (`expiresAt`) checked on every request.
- Role locked to `AUDITOR_READONLY` with specific permission scopes.
- Signature verification uses `crypto.timingSafeEqual` (constant-time comparison).

### API Rate Limiting & DoS Defense
To protect backend computing power and LLM API quotas from malicious exhaustion:
1. **Edge Protection (Cloudflare)**: Layer 3 & 4 DDoS absorption and SSL offloading.
2. **General API Rate Limiter (`express-rate-limit`)**:
   - Limit: **300 requests per 15 minutes per IP** across all `/api/*` endpoints.
   - Bypasses: `/health` (monitoring) and `/api/job-stream` (SSE streaming updates).
3. **Heavy Action Rate Limiter**:
   - Limit: **30 requests per 5 minutes per IP** on compute-intensive operations:
     - `POST /api/scan` (full multi-service scan)
     - `POST /api/trigger` (autonomous tenant dispatch)
     - `POST /api/chat` (Gemini LLM queries)
4. **Reverse Proxy Trust**:
   - Configured `app.set('trust proxy', 1)` to evaluate client IPs through Cloudflare (`CF-Connecting-IP`) or Nginx (`X-Forwarded-For`).

---

## 16. API Endpoints Reference

**Base URL:** `https://api.compflow.icu`

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/health` | Health check. Returns `{"status":"OK"}`. |
| `POST` | `/api/scan` | Trigger an ad-hoc scan for a provider with credentials. |
| `POST` | `/api/trigger` | Dispatch a scan for a registered tenant by ID. |
| `GET/POST` | `/api/tenants` | List or register cloud environments. |
| `POST` | `/api/tenants/toggle` | Enable/disable auto-remediation for a tenant. |
| `ALL` | `/api/validate` | Validate cloud credentials without scanning. |
| `POST` | `/api/chat` | AI compliance assistant (Gemini-powered). |
| `GET` | `/api/job-status?jobId=X` | Poll the status/progress of a running job. |
| `GET` | `/api/job-stream?jobId=X` | Server-Sent Events (SSE) live stream of job progress. |
| `GET` | `/api/audit?clientId=X` | Fetch DynamoDB audit trail logs. |
| `POST` | `/api/auditor/token` | Generate time-limited auditor access token. |
| `GET` | `/api/auditor/export?token=X` | Download signed evidence bundle. |
| `POST` | `/api/auditor/verify` | Verify evidence package integrity. |
| `POST` | `/api/monitoring` | Submit monitoring/job tracking data. |
| `POST` | `/api/jobs` | Lambda-compatible job management endpoint. |
| `GET` | `/api/auth/providers` | Check status of configured SSO providers (Google, GitHub). |
| `GET` | `/api/auth/google` | Initiate Google Workspace OAuth 2.0 login. |
| `GET` | `/api/auth/google/callback` | Exchange Google OAuth code & issue session cookie. |
| `GET` | `/api/auth/github` | Initiate GitHub Developer OAuth login. |
| `GET` | `/api/auth/github/callback` | Exchange GitHub OAuth code & issue session cookie. |
| `GET` | `/api/auth/me` | Fetch currently authenticated user, tenant org & role. |
| `POST` | `/api/auth/dev-login` | Staging/testing mock login. |
| `POST` | `/api/auth/logout` | Invalidate session and clear HTTP-only session cookie. |

---

## 17. Frontend Dashboard

**File:** `app.html` (48KB single-page application)

The dashboard is a vanilla HTML/CSS/JS single-page app with no build step. Key modules:

| Module | File | Purpose |
|:-------|:-----|:--------|
| Cloud Connect | `cloud-connect.js` | Provider credential input UI + XOR obfuscation |
| Tenant Manager | `tenant-manager.js` | Register/list/remove cloud environments |
| Scanner UI | `scanner.js` | Displays scan results in a sortable table |
| Evidence | `evidence.js` | Evidence capture, audit bundle generation/download |
| Frameworks | `frameworks.js` | Framework selection (SOC2/GDPR/HIPAA/ISO) |
| Chat Engine | `chat-engine.js` | AI compliance Q&A sidebar |
| Drift Engine | `drift-engine.js` | Configuration drift detection between scans |
| Scan History | `scan-history.js` | Timeline of past scans |
| Live Terminal | `live-terminal.js` | Real-time log viewer (SSE-connected) |

The frontend connects to the API at `window.COMPLIANCE_API_URL` (configurable).

---

## 18. Infrastructure & Deployment

### Production Stack
```
┌──────────────┐
│  Cloudflare  │  ← DNS + SSL + DDoS protection
│  compflow.icu│
│  api.compflow│
│  .icu        │
└──────┬───────┘
       │ HTTPS
       ▼
┌──────────────────────────┐
│  Azure VM: 20.245.136.231│
│  Ubuntu 22.04            │
│  Docker Compose          │
│  ┌────────────────────┐  │
│  │ compflow-app       │  │  ← Node.js 20 Alpine
│  │ Port 3000          │  │
│  ├────────────────────┤  │
│  │ compflow-redis     │  │  ← Redis 7 Alpine
│  │ Port 6379          │  │
│  ├────────────────────┤  │
│  │ compflow-postgres  │  │  ← PostgreSQL 16 Alpine
│  │ Port 5432          │  │
│  └────────────────────┘  │
└──────────────────────────┘
```

### Deployment Flow
```bash
# 1. Push code to GitHub
git push origin main

# 2. SSH into VM
ssh -i compflow-backend_key.pem azureuser@20.245.136.231

# 3. Copy files into the running container
docker cp /path/to/file compflow-app:/usr/src/app/file

# 4. Restart
docker restart compflow-app
```

### GitHub Repository
- **URL:** `https://github.com/Udene1/Compflow`
- **Branch:** `main`

---

## 19. Testing Strategy

### Test Suites

| Suite | Command | Files | Tests |
|:------|:--------|:------|:------|
| Vitest Unit & E2E | `npm test` | 8 files | 39 tests |
| Auditor Portal | `node test_auditor_portal.js` | 1 file | 4 tests |
| Scheduled Sweeps | `node test_scheduled_sweeps.js` | 1 file | 3 tests |
| Multi-Cloud E2E | `node test_e2e_all_clouds.js` | 1 file | 5 providers |

### Run All & Record Results
```bash
npm run test:record
# → Saves timestamped results to tests/results/
```

### Test Results Archive
| File | Purpose |
|:-----|:--------|
| `tests/results/latest_test_run.md` | Latest test run (Markdown) |
| `tests/results/test_run_<TIMESTAMP>.md` | Archive of each run |
| `tests/results/test_execution_history.json` | Structured JSON history |
| `tests/results/auditor_portal_runs.log` | Auditor portal execution log |

---

## 20. Environment Variables

Copy `.env.example` → `.env` and configure:

```bash
# ─── REQUIRED ───────────────────────────────────────

# Google Gemini API Key (AI reasoning engine)
GEMINI_API_KEY=AIza...

# Platform AWS IAM credentials (for STS AssumeRole + SES email)
PLATFORM_AWS_ACCESS_KEY_ID=AKIA...
PLATFORM_AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1

# ─── OPTIONAL ───────────────────────────────────────

# Email sender identity (must be SES-verified)
AWS_SES_FROM_EMAIL=reports@complianceflow.ai

# PostgreSQL (defaults used by docker-compose)
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=compflow
POSTGRES_USER=compflow_user
POSTGRES_PASSWORD=compflow_pass_secret

# Redis (defaults used by docker-compose)
REDIS_HOST=redis
REDIS_PORT=6379

# Queue mode (set to 'true' to use BullMQ instead of direct execution)
USE_QUEUE=true

# DynamoDB audit table name
AUDIT_TABLE=CompFlowAuditTable

# Auditor portal signing secret
AUDITOR_SIGNING_SECRET=your-secret-here

# Runtime
NODE_ENV=production
PORT=3000
```

---

## 21. Production Domains & URLs

| Domain | Purpose | Provider |
|:-------|:--------|:---------|
| `compflow.icu` | Main website / dashboard | Cloudflare DNS → Azure VM |
| `api.compflow.icu` | Backend API | Cloudflare DNS → Azure VM :3000 |
| `https://api.compflow.icu/health` | Health check endpoint | Returns `{"status":"OK"}` |

---

## 22. Known Limitations & Future Roadmap

### Current Limitations
| Area | Limitation |
|:-----|:-----------|
| Authentication | No user login/SSO yet. API is open (relies on network-level access control). |
| Multi-Tenant Isolation | Tenant data is logically separated by `client_id`, not physically isolated. |
| PCI-DSS | Framework mapping exists but has fewer control mappings than SOC2/GDPR. |
| Terraform/IaC | Remediation operates via cloud APIs, not Infrastructure as Code. |

### Roadmap
- [x] API Rate Limiting & DDoS Defense (Layer 7 `express-rate-limit` + Cloudflare edge)
- [x] SOC2 Third-Party Auditor Evidence Portal (Cryptographically signed bundles)
- [x] Autonomous Scheduled Compliance Sweeps (Daily/Weekly automated sweeps)
- [x] Custom Organization Governance Policies Engine
- [x] Team Authentication & SSO (Google Workspace, GitHub OAuth 2.0, Multi-Tenant RBAC)
- [ ] Slack / Microsoft Teams Webhook Notifications
- [ ] Terraform Plan Generation (suggest IaC fixes instead of direct API calls)
- [ ] Multi-region PostgreSQL replication

---

## 23. Glossary of Compliance Terms

| Term | Plain English |
|:-----|:-------------|
| **SOC2** | A US standard for SaaS companies proving they handle data securely. |
| **ISO 27001** | An international standard for information security management. |
| **HIPAA** | US law requiring healthcare companies to protect patient data. |
| **GDPR** | EU law requiring companies to protect European citizen data. |
| **PCI-DSS** | Standard for companies that handle credit card payments. |
| **Control** | A specific rule or check (e.g., "CC6.1" means "Logical Access Controls"). |
| **Finding** | Something the scanner detected (e.g., "S3 bucket is publicly accessible"). |
| **Remediation** | Fixing a finding (e.g., blocking public access on the S3 bucket). |
| **Blast Radius** | How much damage a fix could cause if it goes wrong. |
| **AssumeRole** | AWS mechanism for temporary cross-account access without sharing credentials. |
| **ExternalId** | A secret string that prevents the "Confused Deputy" attack in AWS AssumeRole. |
| **HMAC** | Hash-based Message Authentication Code — proves a message hasn't been tampered with. |
| **SHA-256** | A cryptographic hash function that produces a unique fingerprint of data. |
| **SES** | Amazon Simple Email Service — used for sending compliance report emails. |
| **BullMQ** | A Redis-based job queue for processing scans in the background. |
| **SSE** | Server-Sent Events — a protocol for real-time streaming updates to the browser. |
| **CPA** | Certified Public Accountant — the type of firm that conducts SOC2 audits. |
| **Evidence Package** | A bundle of proof that shows an organization meets compliance requirements. |
| **Drift** | When cloud configuration changes from its last known compliant state. |
| **Tenant** | A customer organization registered in ComplianceFlow. |

---

*Last updated: August 24, 2026*
*ComplianceFlow AI v2.0.0*
*Generated from source code analysis by the engineering team.*
