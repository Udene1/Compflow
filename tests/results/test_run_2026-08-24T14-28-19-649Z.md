# ComplianceFlow AI — Test Execution Report

**Execution Timestamp**: `2026-08-24T14:28:19.649Z`  
**Overall Status**: 🟢 ALL SUITES PASSED  
**Total Test Suites**: 4 (Passed: 4, Failed: 0)

---

## 📊 Summary Table

| Test Suite | Command | Status | Duration |
| :--- | :--- | :---: | :---: |
| **Vitest Automated Suite (Unit & E2E)** | `npx vitest run` | **PASSED** | 54.44s |
| **SOC2 Auditor Evidence Portal Engine** | `node test_auditor_portal.js` | **PASSED** | 1.70s |
| **Autonomous Scheduled Sweeps & Custom Policies** | `node test_scheduled_sweeps.js` | **PASSED** | 1.58s |
| **Multi-Cloud E2E Engine** | `node test_e2e_all_clouds.js` | **PASSED** | 35.75s |

---

## 📝 Detailed Execution Outputs


### Vitest Automated Suite (Unit & E2E) (PASSED)
```text
[1m[30m[46m RUN [49m[39m[22m [36mv4.1.8 [39m[90mC:/Users/HP/.gemini/antigravity/scratch/compliance-flow[39m

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect public IP exposure on VMs
[22m[39m2026-08-24T14:28:59.020Z [INFO] [SYSTEM] ➤ Starting High-Performance Parallel Azure Governance Scan...

[90mstdout[2m | tests/unit/auditor_portal.test.js[2m > [22m[2mSOC2 Third-Party Auditor Evidence Portal[2m > [22m[2mshould generate a valid, cryptographically signed auditor access token
[22m[39m2026-08-24T14:29:00.443Z [INFO] [SYSTEM] [AUDITOR-PORTAL] Issued 48h access token for auditor "lead.auditor@schellmancpa.com" (Tenant: tenant-acme-corp-01).

[90mstdout[2m | tests/unit/auditor_portal.test.js[2m > [22m[2mSOC2 Third-Party Auditor Evidence Portal[2m > [22m[2mshould reject forged or tampered auditor access tokens
[22m[39m2026-08-24T14:29:00.457Z [INFO] [SYSTEM] [AUDITOR-PORTAL] Issued 24h access token for auditor "lead.auditor@schellmancpa.com" (Tenant: tenant-acme-corp-01).

[90mstdout[2m | tests/unit/auditor_portal.test.js[2m > [22m[2mSOC2 Third-Party Auditor Evidence Portal[2m > [22m[2mshould compile an evidence bundle with SHA-256 fingerprints and multi-framework control proofs
[22m[39m2026-08-24T14:29:00.459Z [INFO] [SYSTEM] [AUDITOR-PORTAL] Compiling signed evidence package for "Acme Corp"...

[90mstdout[2m | tests/unit/auditor_portal.test.js[2m > [22m[2mSOC2 Third-Party Auditor Evidence Portal[2m > [22m[2mshould compile an evidence bundle with SHA-256 fingerprints and multi-framework control proofs
[22m[39m2026-08-24T14:29:00.733Z [INFO] [SYSTEM] [AUDITOR-PORTAL] ✓ Evidence bundle successfully signed (Sig: b4066977fdbdf8ef...).

[90mstdout[2m | tests/unit/auditor_portal.test.js[2m > [22m[2mSOC2 Third-Party Auditor Evidence Portal[2m > [22m[2mshould cryptographically verify untampered packages and detect modifications
[22m[39m2026-08-24T14:29:00.743Z [INFO] [SYSTEM] [AUDITOR-PORTAL] Compiling signed evidence package for "Secure Corp"...

[90mstdout[2m | tests/unit/auditor_portal.test.js[2m > [22m[2mSOC2 Third-Party Auditor Evidence Portal[2m > [22m[2mshould cryptographically verify untampered packages and detect modifications
[22m[39m2026-08-24T14:29:00.811Z [INFO] [SYSTEM] [AUDITOR-PORTAL] ✓ Evidence bundle successfully signed (Sig: d7474b0361a2b982...).

 [32m✓[39m tests/unit/auditor_portal.test.js [2m([22m[2m4 tests[22m[2m)[22m[33m 428[2mms[22m[39m
[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect public IP exposure on VMs
[22m[39m2026-08-24T14:29:02.891Z [WARN] [SYSTEM] Azure CosmosDB scan failed:
"The provided subscription identifier 'test-sub-id' is malformed or invalid."

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect public IP exposure on VMs
[22m[39m2026-08-24T14:29:02.892Z [INFO] [SYSTEM] Ultra-Fast Parallel Azure Scan complete in 3.87s: 17 resources evaluated (6 critical, 8 warning, 1 pass).

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect open SSH in NSG rules
[22m[39m2026-08-24T14:29:02.895Z [INFO] [SYSTEM] ➤ Starting High-Performance Parallel Azure Governance Scan...

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect open SSH in NSG rules
[22m[39m2026-08-24T14:29:03.055Z [WARN] [SYSTEM] Azure CosmosDB scan failed:
"The provided subscription identifier 'test-sub-id' is malformed or invalid."

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect open SSH in NSG rules
[22m[39m2026-08-24T14:29:03.055Z [INFO] [SYSTEM] Ultra-Fast Parallel Azure Scan complete in 0.16s: 17 resources evaluated (6 critical, 8 warning, 1 pass).

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect public blob access and HTTPS disabled on Storage Accounts
[22m[39m2026-08-24T14:29:03.057Z [INFO] [SYSTEM] ➤ Starting High-Performance Parallel Azure Governance Scan...

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect public blob access and HTTPS disabled on Storage Accounts
[22m[39m2026-08-24T14:29:03.229Z [WARN] [SYSTEM] Azure CosmosDB scan failed:
"The provided subscription identifier 'test-sub-id' is malformed or invalid."

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect public blob access and HTTPS disabled on Storage Accounts
[22m[39m2026-08-24T14:29:03.230Z [INFO] [SYSTEM] Ultra-Fast Parallel Azure Scan complete in 0.17s: 17 resources evaluated (6 critical, 8 warning, 1 pass).

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect HTTPS disabled on App Service
[22m[39m2026-08-24T14:29:03.235Z [INFO] [SYSTEM] ➤ Starting High-Performance Parallel Azure Governance Scan...

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect HTTPS disabled on App Service
[22m[39m2026-08-24T14:29:03.418Z [WARN] [SYSTEM] Azure CosmosDB scan failed:
"The provided subscription identifier 'test-sub-id' is malformed or invalid."

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect HTTPS disabled on App Service
[22m[39m2026-08-24T14:29:03.418Z [INFO] [SYSTEM] Ultra-Fast Parallel Azure Scan complete in 0.18s: 17 resources evaluated (6 critical, 8 warning, 1 pass).

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect SQL public network access
[22m[39m2026-08-24T14:29:03.420Z [INFO] [SYSTEM] ➤ Starting High-Performance Parallel Azure Governance Scan...

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect SQL public network access
[22m[39m2026-08-24T14:29:03.636Z [WARN] [SYSTEM] Azure CosmosDB scan failed:
"The provided subscription identifier 'test-sub-id' is malformed or invalid."

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect SQL public network access
[22m[39m2026-08-24T14:29:03.637Z [INFO] [SYSTEM] Ultra-Fast Parallel Azure Scan complete in 0.22s: 17 resources evaluated (6 critical, 8 warning, 1 pass).

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect insecure recovery vault settings
[22m[39m2026-08-24T14:29:03.638Z [INFO] [SYSTEM] ➤ Starting High-Performance Parallel Azure Governance Scan...

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect insecure recovery vault settings
[22m[39m2026-08-24T14:29:03.846Z [WARN] [SYSTEM] Azure CosmosDB scan failed:
"The provided subscription identifier 'test-sub-id' is malformed or invalid."

[90mstdout[2m | tests/unit/azure.test.js[2m > [22m[2mAzure Enterprise Provider Scanner[2m > [22m[2mshould detect insecure recovery vault settings
[22m[39m2026-08-24T14:29:03.846Z [INFO] [SYSTEM] Ultra-Fast Parallel Azure Scan complete in 0.21s: 17 resources evaluated (6 critical, 8 warning, 1 pass).

 [32m✓[39m tests/unit/azure.test.js [2m([22m[2m6 tests[22m[2m)[22m[33m 4854[2mms[22m[39m
     [33m[2m✓[22m[39m should detect public IP exposure on VMs [33m 3885[2mms[22m[39m
[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect external IP on instances
[22m[39m2026-08-24T14:29:04.961Z [INFO] [SYSTEM] ➤ Starting Ultra-Deep GCP Governance Scan...

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect external IP on instances
[22m[39m2026-08-24T14:29:04.976Z [INFO] [SYSTEM] [GCP-SCAN] VPC Service Controls audit - Access Context Manager required.
2026-08-24T14:29:04.976Z [INFO] [SYSTEM] Ultra-Deep GCP Scan complete: 15 findings identified.

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect old snapshots
[22m[39m2026-08-24T14:29:04.984Z [INFO] [SYSTEM] ➤ Starting Ultra-Deep GCP Governance Scan...

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect old snapshots
[22m[39m2026-08-24T14:29:04.987Z [INFO] [SYSTEM] [GCP-SCAN] VPC Service Controls audit - Access Context Manager required.
2026-08-24T14:29:04.987Z [INFO] [SYSTEM] Ultra-Deep GCP Scan complete: 15 findings identified.

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect insecure GKE settings
[22m[39m2026-08-24T14:29:04.991Z [INFO] [SYSTEM] ➤ Starting Ultra-Deep GCP Governance Scan...

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect insecure GKE settings
[22m[39m2026-08-24T14:29:04.993Z [INFO] [SYSTEM] [GCP-SCAN] VPC Service Controls audit - Access Context Manager required.
2026-08-24T14:29:04.993Z [INFO] [SYSTEM] Ultra-Deep GCP Scan complete: 15 findings identified.

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect public BigQuery datasets
[22m[39m2026-08-24T14:29:04.995Z [INFO] [SYSTEM] ➤ Starting Ultra-Deep GCP Governance Scan...

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect public BigQuery datasets
[22m[39m2026-08-24T14:29:05.002Z [INFO] [SYSTEM] [GCP-SCAN] VPC Service Controls audit - Access Context Manager required.
2026-08-24T14:29:05.002Z [INFO] [SYSTEM] Ultra-Deep GCP Scan complete: 15 findings identified.

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect old Service Account Keys
[22m[39m2026-08-24T14:29:05.004Z [INFO] [SYSTEM] ➤ Starting Ultra-Deep GCP Governance Scan...

[90mstdout[2m | tests/unit/gcp.test.js[2m > [22m[2mGCP Provider Scanner[2m > [22m[2mshould detect old Service Account Keys
[22m[39m2026-08-24T14:29:05.006Z [INFO] [SYSTEM] [GCP-SCAN] VPC Service Controls audit - Access Context Manager required.
2026-08-24T14:29:05.006Z [INFO] [SYSTEM] Ultra-Deep GCP Scan complete: 15 findings identified.

 [32m✓[39m tests/unit/gcp.test.js [2m([22m[2m5 tests[22m[2m)[22m[32m 56[2mms[22m[39m
[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Provider - Deep Scan Logic[2m > [22m[2mshould detect a droplet without backups enabled
[22m[39m2026-08-24T14:29:06.406Z [INFO] [SYSTEM] ➤ Starting DigitalOcean Ultra-Deep Governance Scan...

[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Provider - Deep Scan Logic[2m > [22m[2mshould detect a droplet without backups enabled
[22m[39m2026-08-24T14:29:06.412Z [INFO] [SYSTEM] DigitalOcean Scan complete: 3 resources evaluated.

[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Provider - Deep Scan Logic[2m > [22m[2mshould detect a public Space bucket
[22m[39m2026-08-24T14:29:06.419Z [INFO] [SYSTEM] ➤ Starting DigitalOcean Ultra-Deep Governance Scan...

[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Provider - Deep Scan Logic[2m > [22m[2mshould detect a public Space bucket
[22m[39m2026-08-24T14:29:06.420Z [INFO] [SYSTEM] DigitalOcean Scan complete: 1 resources evaluated.

[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Provider - Deep Scan Logic[2m > [22m[2mshould detect app platform insecurities
[22m[39m2026-08-24T14:29:06.422Z [INFO] [SYSTEM] ➤ Starting DigitalOcean Ultra-Deep Governance Scan...

[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Provider - Deep Scan Logic[2m > [22m[2mshould detect app platform insecurities
[22m[39m2026-08-24T14:29:06.424Z [INFO] [SYSTEM] DigitalOcean Scan complete: 1 resources evaluated.

[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Remediator - Safety Logic[2m > [22m[2mshould handle dryRun mode correctly
[22m[39m2026-08-24T14:29:06.427Z [INFO] [SYSTEM] ⚡ DigitalOcean Auto-Remediation: DO Droplet "test-vm" — backups disabled

[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Remediator - Safety Logic[2m > [22m[2mshould suggest advisory for non-whitelisted fixes
[22m[39m2026-08-24T14:29:06.429Z [INFO] [SYSTEM] ⚡ DigitalOcean Auto-Remediation: DO Firewall "fw-01" — SSH (22) open
2026-08-24T14:29:06.429Z [INFO] [SYSTEM] [DO-FIX] Hardening SSH port on firewall "fw-01"

[90mstdout[2m | tests/unit/digitalocean.test.js[2m > [22m[2mDigitalOcean Remediator - Safety Logic[2m > [22m[2mshould execute whitelisted fixes
[22m[39m2026-08-24T14:29:06.435Z [INFO] [SYSTEM] ⚡ DigitalOcean Auto-Remediation: DO Droplet "web-01" — backups disabled
2026-08-24T14:29:06.435Z [INFO] [SYSTEM] [DO-FIX] Enabling backups for Droplet "web-01"

 [32m✓[39m tests/unit/digitalocean.test.js [2m([22m[2m6 tests[22m[2m)[22m[32m 40[2mms[22m[39m
[90mstdout[2m | tests/unit/hetzner.test.js[2m > [22m[2mHetzner Provider - Deep Scan Logic[2m > [22m[2mshould detect an exposed server (no firewall)
[22m[39m2026-08-24T14:29:07.018Z [INFO] [SYSTEM] ➤ Starting Hetzner Ultra-Deep Governance Scan...

[90mstdout[2m | tests/unit/hetzner.test.js[2m > [22m[2mHetzner Provider - Deep Scan Logic[2m > [22m[2mshould detect an exposed server (no firewall)
[22m[39m2026-08-24T14:29:07.024Z [INFO] [SYSTEM] Hetzner Scan complete: 3 resources evaluated.

[90mstdout[2m | tests/unit/hetzner.test.js[2m > [22m[2mHetzner Provider - Deep Scan Logic[2m > [22m[2mshould detect rescue mode active
[22m[39m2026-08-24T14:29:07.028Z [INFO] [SYSTEM] ➤ Starting Hetzner Ultra-Deep Governance Scan...

[90mstdout[2m | tests/unit/hetzner.test.js[2m > [22m[2mHetzner Provider - Deep Scan Logic[2m > [22m[2mshould detect rescue mode active
[22m[39m2026-08-24T14:29:07.029Z [INFO] [SYSTEM] Hetzner Scan complete: 3 resources evaluated.

[90mstdout[2m | tests/unit/hetzner.test.js[2m > [22m[2mHetzner Provider - Deep Scan Logic[2m > [22m[2mshould detect missing backups on servers
[22m[39m2026-08-24T14:29:07.034Z [INFO] [SYSTEM] ➤ Starting Hetzner Ultra-Deep Governance Scan...

[90mstdout[2m | tests/unit/hetzner.test.js[2m > [22m[2mHetzner Provider - Deep Scan Logic[2m > [22m[2mshould detect missing backups on servers
[22m[39m2026-08-24T14:29:07.035Z [INFO] [SYSTEM] Hetzner Scan complete: 3 resources evaluated.

[90mstdout[2m | tests/unit/hetzner.test.js[2m > [22m[2mHetzner Remediator - Safety Logic[2m > [22m[2mshould handle dryRun mode correctly
[22m[39m2026-08-24T14:29:07.039Z [INFO] [SYSTEM] ⚡ Hetzner Auto-Remediation: Hetzner Server "test-node" — backups disabled

[90mstdout[2m | tests/unit/hetzner.test.js[2m > [22m[2mHetzner Remediator - Safety Logic[2m > [22m[2mshould enforce auto-delete on Primary IPs
[22m[39m2026-08-24T14:29:07.041Z [INFO] [SYSTEM] ⚡ Hetzner Auto-Remediation: Hetzner Primary IP "1.2.3.4" — Auto-delete disabled
2026-08-24T14:29:07.042Z [INFO] [SYSTEM] [HETZNER-FIX] Enabling auto-delete for IP "1.2.3.4"

 [32m✓[39m tests/unit/hetzner.test.js [2m([22m[2m5 tests[22m[2m)[22m[32m 38[2mms[22m[39m
 [32m✓[39m tests/unit/compliance_mapper.test.js [2m([22m[2m4 tests[22m[2m)[22m[32m 48[2mms[22m[39m
[90mstdout[2m | tests/unit/policy_engine.test.js[2m > [22m[2mCustom Governance Policy Rules Engine[2m > [22m[2mshould flag resources deployed in disallowed regions
[22m[39m2026-08-24T14:29:09.377Z [INFO] [SYSTEM] [POLICY-ENGINE] Custom policy evaluation generated 1 findings.

[90mstdout[2m | tests/unit/policy_engine.test.js[2m > [22m[2mCustom Governance Policy Rules Engine[2m > [22m[2mshould flag resources missing required organizational tags
[22m[39m2026-08-24T14:29:09.390Z [INFO] [SYSTEM] [POLICY-ENGINE] Custom policy evaluation generated 1 findings.

[90mstdout[2m | tests/unit/policy_engine.test.js[2m > [22m[2mCustom Governance Policy Rules Engine[2m > [22m[2mshould flag public ports not present in the allowed port whitelist
[22m[39m2026-08-24T14:29:09.393Z [INFO] [SYSTEM] [POLICY-ENGINE] Custom policy evaluation generated 1 findings.

 [32m✓[39m tests/unit/policy_engine.test.js [2m([22m[2m4 tests[22m[2m)[22m[32m 33[2mms[22m[39m
[90mstdout[2m | tests/e2e/all_clouds_e2e.test.js[2m > [22m[2mMulti-Cloud End-to-End (E2E) Compliance Pipeline[2m > [22m[2mshould complete E2E audit lifecycle for DigitalOcean
[22m[39m2026-08-24T14:29:13.682Z [INFO] [SYSTEM] Initiating remediation for prod-droplet-db on DIGITALOCEAN (dryRun: false)...
2026-08-24T14:29:13.694Z [INFO] [SYSTEM] ⚡ DigitalOcean Auto-Remediation: DO Droplet "prod-droplet-db" — backups disabled
2026-08-24T14:29:13.697Z [INFO] [SYSTEM] [DO-FIX] Enabling backups for Droplet "prod-droplet-db"

[90mstdout[2m | tests/e2e/all_clouds_e2e.test.js[2m > [22m[2mMulti-Cloud End-to-End (E2E) Compliance Pipeline[2m > [22m[2mshould complete E2E audit lifecycle for Hetzner
[22m[39m2026-08-24T14:29:13.838Z [INFO] [SYSTEM] Initiating remediation for node-01 on HETZNER (dryRun: false)...
2026-08-24T14:29:13.839Z [INFO] [SYSTEM] ⚡ Hetzner Auto-Remediation: Hetzner Server "node-01" — backups disabled
2026-08-24T14:29:13.839Z [INFO] [SYSTEM] [HETZNER-FIX] Enabling backups for server "node-01"

[90mstdout[2m | tests/e2e/all_clouds_e2e.test.js[2m > [22m[2mMulti-Cloud End-to-End (E2E) Compliance Pipeline[2m > [22m[2mshould complete E2E audit lifecycle for GCP
[22m[39m2026-08-24T14:29:13.841Z [INFO] [SYSTEM] Initiating remediation for vault-bucket on GCP (dryRun: true)...
2026-08-24T14:29:13.842Z [INFO] [SYSTEM] ⚡ GCP Auto-Remediation: GCP Bucket "vault-bucket" — Uniform bucket-level access disabled

[90mstdout[2m | tests/e2e/all_clouds_e2e.test.js[2m > [22m[2mMulti-Cloud End-to-End (E2E) Compliance Pipeline[2m > [22m[2mshould complete E2E audit lifecycle for AWS
[22m[39m2026-08-24T14:29:13.844Z [INFO] [SYSTEM] Initiating remediation for public-data on AWS (dryRun: true)...
2026-08-24T14:29:13.851Z [INFO] [SYSTEM] [DRY-RUN] Would fix S3 Bucket "public-data": Public access enabled

[90mstdout[2m | tests/e2e/all_clouds_e2e.test.js[2m > [22m[2mMulti-Cloud End-to-End (E2E) Compliance Pipeline[2m > [22m[2mshould complete E2E audit lifecycle for Azure
[22m[39m2026-08-24T14:29:13.853Z [INFO] [SYSTEM] Initiating remediation for app-portal on AZURE (dryRun: true)...
2026-08-24T14:29:13.853Z [INFO] [SYSTEM] ⚡ Azure Auto-Remediation: Azure App Service "app-portal" — App Service does not enforce HTTPS-only traffic

 [32m✓[39m tests/e2e/all_clouds_e2e.test.js [2m([22m[2m5 tests[22m[2m)[22m[32m 186[2mms[22m[39m

[2m Test Files [22m [1m[32m8 passed[39m[22m[90m (8)[39m
[2m      Tests [22m [1m[32m39 passed[39m[22m[90m (39)[39m
[2m   Start at [22m 10:28:54
[2m   Duration [22m 18.94s[2m (transform 11.38s, setup 0ms, import 29.02s, tests 5.68s, environment 3ms)[22m
```



### SOC2 Auditor Evidence Portal Engine (PASSED)
```text
================================================================================
⚡ COMPLIANCEFLOW AI — SOC2 AUDITOR EVIDENCE PORTAL & VERIFICATION ENGINE
================================================================================

➤ [1/4] Issuing Cryptographically Signed Auditor Access Token...
2026-08-24T14:29:15.652Z [INFO] [SYSTEM] [AUDITOR-PORTAL] Issued 72h access token for auditor "audit-team@schellmancpa.com" (Tenant: tenant-fintech-99).
  ✓ Token generated for audit-team@schellmancpa.com:
    - Role: AUDITOR_READONLY
    - Expires: 2026-08-27T14:29:15.650Z
    - Token: eyJwYXlsb2FkIjp7InRlbmFudElkIjoi...
  ✓ Token Cryptographic Signature Valid: true

➤ [2/4] Assembling Multi-Framework Auditor Evidence Bundle...
2026-08-24T14:29:15.654Z [INFO] [SYSTEM] [AUDITOR-PORTAL] Compiling signed evidence package for "Fintech Global Inc."...
2026-08-24T14:29:15.769Z [INFO] [SYSTEM] [AUDITOR-PORTAL] ✓ Evidence bundle successfully signed (Sig: 6eebbe823a015876...).
  ✓ Evidence Bundle Assembled:
    - Digital Signature: 6eebbe823a01587669a89b250ce19c53...
    - Assets Evaluated: 3
    - Evidence Manifest Items: 3
    - Embedded PDF Report: Yes (4668 b64 chars)

➤ [3/4] Cryptographically Verifying Evidence Package Authenticity...
  ✓ Package Verified: true
  ✓ Verification Message: "Cryptographic proof verified. Package matches official immutable audit trail."

➤ [4/4] Testing Tamper-Detection Engine against Modified Data...
  ✓ Tamper Detected Successfully: Verified = false
  ✓ Tamper Reason: "Evidence manifest SHA-256 checksum mismatch"

================================================================================
✨ SOC2 AUDITOR EVIDENCE PORTAL ENGINE TEST: 100% OPERATIONAL & VERIFIED
================================================================================
```



### Autonomous Scheduled Sweeps & Custom Policies (PASSED)
```text
================================================================================
⚡ COMPLIANCEFLOW AI — AUTONOMOUS SCHEDULED SWEEPS & POLICY ENGINE TEST
================================================================================

➤ [1/3] Testing Custom Policy Rules Engine...
2026-08-24T14:29:17.174Z [INFO] [SYSTEM] [POLICY-ENGINE] Custom policy evaluation generated 5 findings.
  ✓ Evaluated 3 sample assets against 3 custom policies.
  ✓ Detected 5 custom policy violations:
    - [CRITICAL] legacy-db-02 (POLICY_UNAUTHORIZED_REGION): Resource deployed in unauthorized region "ap-south-1". Approved regions: [eastus, westus, centralus]
    - [WARNING] app-server-01 (POLICY_MISSING_TAGS): Missing required organizational tags: [DataClassification]
    - [WARNING] legacy-db-02 (POLICY_MISSING_TAGS): Missing required organizational tags: [Environment, Owner, DataClassification]
    - [WARNING] public-fw-rule (POLICY_MISSING_TAGS): Missing required organizational tags: [Environment, Owner, DataClassification]
    - [CRITICAL] public-fw-rule (POLICY_DISALLOWED_PORT): Public ingress on port "8080" violates organization port whitelist (Allowed: 80, 443)

➤ [2/3] Triggering Autonomous Scheduled Sweep Handler...
2026-08-24T14:29:17.182Z [INFO] [SYSTEM] 🚀 AUTONOMOUS SCHEDULER: Triggering DAILY compliance sweeps...
2026-08-24T14:29:17.183Z [INFO] [SYSTEM] [REGISTRY] Found 0 active tenants eligible for scheduled sweep.
2026-08-24T14:29:17.183Z [INFO] [SYSTEM] ✨ Autonomous scheduled sweep complete. Dispatched: 0, Completed: 0
  ✓ Sweep Handler returned status 200:
    - Dispatched: 0
    - Completed: 0

➤ [3/3] Compiling Executive PDF Report with Custom Policy Guardrails...
  ✓ Generated Executive PDF Report (4570 bytes) including custom governance policies.

================================================================================
✨ AUTONOMOUS SWEEPS & CUSTOM POLICY ENGINE TEST COMPLETE: 100% OPERATIONAL
================================================================================
```



### Multi-Cloud E2E Engine (PASSED)
```text
================================================================================
⚡ COMPLIANCEFLOW AI — MULTI-CLOUD END-TO-END (E2E) VALIDATION ENGINE
================================================================================

➤ [1/5] Testing AZURE Cloud Provider E2E Pipeline...
2026-08-24T14:29:29.104Z [INFO] [SYSTEM] Initiating AZURE scan...
2026-08-24T14:29:29.222Z [INFO] [SYSTEM] ➤ Starting High-Performance Parallel Azure Governance Scan...
2026-08-24T14:29:52.382Z [INFO] [SYSTEM] Ultra-Fast Parallel Azure Scan complete in 23.16s: 10 resources evaluated (4 critical, 3 warning, 0 pass).
  ✓ Azure Scan Complete in 23.28s: 10 resources, 10 findings.
  ✓ Gemini AI Evaluation for "compflow-backend": Action = ESCALATE, SafetyScore = 0.5
2026-08-24T14:29:52.384Z [INFO] [SYSTEM] Initiating remediation for compflow-backend on AZURE (dryRun: true)...
2026-08-24T14:29:52.384Z [INFO] [SYSTEM] ⚡ Azure Auto-Remediation: Azure VM "compflow-backend" — OS Disk encryption is not explicitly configured with Azure Disk Encryption (ADE)
  ✓ Remediation Safety Check: [DRY-RUN] Validated safety for Azure Azure VM "compflow-backend". Action: Resolve OS Disk encryption is not explicitly configured with Azure Disk Encryption (ADE).
  ✓ Executive PDF Report compiled (5950 bytes)

➤ [2/5] Testing DIGITALOCEAN Cloud Provider E2E Pipeline...
  ✓ Gemini AI Evaluation: Action = AUTO_FIX
2026-08-24T14:29:52.582Z [INFO] [SYSTEM] Initiating remediation for prod-droplet-01 on DIGITALOCEAN (dryRun: false)...
2026-08-24T14:29:52.583Z [INFO] [SYSTEM] ⚡ DigitalOcean Auto-Remediation: DO Droplet "prod-droplet-01" — Automated backups disabled
2026-08-24T14:29:52.583Z [INFO] [SYSTEM] [DO-FIX] Enabling backups for Droplet "prod-droplet-01"
  ✓ Remediation Output: Droplet "prod-droplet-01": Automated weekly backups enabled via DO API.
  ✓ HTML Compliance Report generated (1761 bytes)

➤ [3/5] Testing HETZNER Cloud Provider E2E Pipeline...
  ✓ Gemini AI Evaluation: Action = AUTO_FIX
2026-08-24T14:29:52.584Z [INFO] [SYSTEM] Initiating remediation for srv-primary-node on HETZNER (dryRun: false)...
2026-08-24T14:29:52.584Z [INFO] [SYSTEM] ⚡ Hetzner Auto-Remediation: Hetzner Server "srv-primary-node" — Server backups disabled
2026-08-24T14:29:52.584Z [INFO] [SYSTEM] [HETZNER-FIX] Enabling backups for server "srv-primary-node"
  ✓ Remediation Output: Server "srv-primary-node": Hetzner automated backups enabled (window: weekly).

➤ [4/5] Testing GCP Cloud Provider E2E Pipeline...
  ✓ Gemini AI Evaluation: Action = ESCALATE
2026-08-24T14:29:52.585Z [INFO] [SYSTEM] Initiating remediation for compliance-data-bucket on GCP (dryRun: true)...
2026-08-24T14:29:52.585Z [INFO] [SYSTEM] ⚡ GCP Auto-Remediation: GCP Bucket "compliance-data-bucket" — Uniform bucket-level access disabled
  ✓ Dry-Run Remediation: [DRY-RUN] Validated safety for GCP GCP Bucket "compliance-data-bucket". Action: Resolve Uniform bucket-level access disabled.

➤ [5/5] Testing AWS Cloud Provider E2E Pipeline...
  ✓ Gemini AI Evaluation: Action = AUTO_FIX
2026-08-24T14:29:52.585Z [INFO] [SYSTEM] Initiating remediation for client-audit-vault on AWS (dryRun: true)...
2026-08-24T14:29:52.587Z [INFO] [SYSTEM] [DRY-RUN] Would fix S3 Bucket "client-audit-vault": Public access enabled
  ✓ Dry-Run Remediation: [DRY-RUN] Validated safety. Would execute fix.

================================================================================
📊 MULTI-CLOUD E2E EXECUTION SUMMARY TABLE
================================================================================
┌─────────┬────────────────┬──────────┬───────────┬───────────┬──────────┐
│ (index) │ provider       │ status   │ resources │ anomalies │ latency  │
├─────────┼────────────────┼──────────┼───────────┼───────────┼──────────┤
│ 0       │ 'AZURE'        │ 'PASSED' │ 10        │ 10        │ '23.28s' │
│ 1       │ 'DIGITALOCEAN' │ 'PASSED' │ 2         │ 1         │ '<0.1s'  │
│ 2       │ 'HETZNER'      │ 'PASSED' │ 2         │ 1         │ '<0.1s'  │
│ 3       │ 'GCP'          │ 'PASSED' │ 4         │ 1         │ '<0.1s'  │
│ 4       │ 'AWS'          │ 'PASSED' │ 6         │ 1         │ '<0.1s'  │
└─────────┴────────────────┴──────────┴───────────┴───────────┴──────────┘
```

