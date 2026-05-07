# ComplianceFlow AI

> **Service as Software** — An AI-Native Service (AINS) platform that delivers outcomes, not just dashboards.

ComplianceFlow demonstrates the "Service-as-Software" thesis popularized by Gustaf Alströmer. Traditional compliance software (SaaS) provides tools to help you do the work. **ComplianceFlow AI** uses autonomous agents to **do the work for you**, delivering a completed SOC2 certification outcome.

---

## 🦾 Core Thesis: The AINS Model

ComplianceFlow passes the **Structural Test**: If you remove the AI intelligence layer, the business would collapse or become economically unviable due to human labor costs.

| Traditional SaaS (SOC2) | ComplianceFlow AI (AINS) |
|---|---|
| Sells access to a dashboard | Sells a completed Audit Report |
| Charges per seat | Charges per Outcome |
| Identifies what's broken | Remediates resources automatically |
| Requires human "Evidence Collectors" | Autonomous agents capture and hash evidence |

---

## ✨ Features & Capabilities

### 1. Proof-of-Trust Landing Page
- **Premium Glassmorphic UI**: High-end enterprise aesthetic using vanilla CSS custom properties.
- **Interactive Autopilot Demo**: A real-time terminal simulation in the hero section showing the AI sense-act loop.

### 2. Full-Stack Autonomous Dashboard
- **Real Cloud Connect**: Multi-tenant credential management. Users provide AWS/Azure/GCP keys via the UI which are passed to stateless API endpoints.
- **Official SDK Integration**: Uses the official `@aws-sdk` to perform live enumeration of S3, IAM, and other resources.
- **Stateless API Architecture**: Vercel Serverless Functions (`/api/scan`, `/api/remediate`) handle the backend logic without persisting sensitive keys.
- **AI Remediation Center**: Real-world configuration fixes (e.g., S3 Public Access Block) applied via the API.
- **Evidence Vault**: Automated evidence capture for every real-world action, verified with SHA-256 hashes.

### 3. Audit Engine (Phase 3)
- **SOC2 TSC Mapping**: Evidence automatically mapped to Trust Service Criteria (CC1.0 - CC9.0).
- **Audit-Ready Reports**: Dynamic generation of comprehensive reports with summary stats and detailed evidence logs.
- **One-Click Export**: Download reports as PDF (for auditors) or JSON (for technical review).

---

## 🗺️ Product Roadmap

### ✅ Completed: Phase 1 — Foundation
- [x] Landing page design system.
- [x] Autopilot terminal simulation.
- [x] Outcome-based pricing model UI.

### ✅ Completed: Phase 2 — Autonomous Core
- [x] Dashboard application architecture.
- [x] Cloud connection flow simulation.
- [x] Resource inventory & multi-level scanner.
- [x] Remediation engine with config diffs.

### ✅ Completed: Phase 3 — Audit & Evidence
- [x] Evidence Vault with cryptographic hashing.
- [x] Trust Service Criteria (TSC) mapping logic.
- [x] Dynamic Report Generator & PDF Export.
- [x] Vercel-ready deployment configuration.

### ✅ Completed: Phase 3.5 — Real Cloud Integration
- [x] Full-stack architecture with Vercel API.
- [x] Official AWS SDK integration for direct governance.
- [x] Stateless session-based credential management.

### ✅ Completed: Phase 4 — Multi-Framework Governance
- [x] GDPR, HIPAA, and ISO 27001 mapping via `frameworks.js`.
- [x] Global Focus Switcher for real-time mandate context.
- [x] Multi-framework evidence tagging and reporting.

### 🚀 Upcoming: The Path to v1.0
- **Phase 5: Continuous Monitoring**
    - [ ] Real-time drift detection and auto-rollback for unauthorized changes.
    - [ ] Slack/Teams alerting for critical remediations.
- **Phase 6: Auditor Marketplace**
    - [ ] Third-party auditor portal for asynchronous review.
    - [ ] Public "Verified by ComplianceFlow" trust badges.
- **Phase 7: AI Questionnaire Automation**
    - [ ] Autocomplete security questionnaires (SIG/CAIQ) based on live evidence.

---

## 🛠️ Technology Stack

- **Core**: Vanilla HTML5, Vanilla CSS3 (Custom Properties, Keyframes, Glassmorphism).
- **Logic**: Vanilla JavaScript (ES6 Modules, Event-driven architecture).
- **Design**: Google Fonts (Outfit & JetBrains Mono).
- **Deployment**: Vercel (Configured for static hosting with security headers).

---

## 🚀 Getting Started

### Local Development
```bash
# Clone the repository
git clone https://github.com/udene1/compflow.git
cd compliance-flow

# Run a local server (optional)
# No build step is required as it is 100% vanilla
npm run dev
```

### Deployment to Vercel
1. Push to your GitHub repository.
2. Connect the repository to Vercel.
3. The `vercel.json` will automatically handle routing and security headers.

---

## 📁 Project Structure

```text
compliance-flow/
├── api/                # Vercel Serverless Functions (Node.js)
│   ├── scan.js         # Real AWS SDK scanning logic
│   └── remediate.js    # Real AWS SDK remediation logic
├── index.html          # Landing page
├── app.html            # Core Dashboard
├── styles.css          # Landing page styles
├── dashboard.css       # Dashboard design system
├── service_demo.js     # Landing page simulation
├── cloud-connect.js    # Cloud credentials & session logic
├── scanner.js          # API-driven resource discovery
├── remediation.js      # API-driven fix engine
├── evidence.js         # Audit & Evidence engine
├── live-terminal.js    # Real-time event logging
├── vercel.json         # Vercel deployment config
└── package.json        # Dependencies & scripts
```

---

## 📄 License
MIT © 2026 udene1
