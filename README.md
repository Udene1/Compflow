# ComplianceFlow AI

> **Service as Software** — An AI-Native Service (AINS) prototype inspired by Gustaf Alströmer's thesis on outcome-driven AI companies.

Traditional compliance software shows you what's broken. **ComplianceFlow AI** actually fixes it.

---

## 🧠 The Thesis

ComplianceFlow demonstrates the **AI-Native Service (AINS)** model: instead of selling a **tool** (SaaS) that _helps_ you get compliant, we sell the **completed outcome** — a ready-to-sign SOC2 audit report.

**The Structural Test:** If you remove the AI intelligence layer, the business collapses — you'd need a team of expensive human auditors to replace what the agents do in minutes.

---

## ✅ What's Built (Current Capabilities)

### 1. Premium Landing Page
- **Glassmorphic dark-mode** design system with animated background blobs
- **Outfit** + **JetBrains Mono** typography (Google Fonts)
- Hover effects, smooth transitions, and micro-animations
- Fully responsive layout

### 2. Interactive Autopilot Terminal Demo
A simulated AI agent lifecycle showing the core value loop:

| Phase | Example Log |
|---|---|
| **Detection** | `[Insight] Critical Failure: S3 bucket 'finance-records' is public.` |
| **Remediation** | `[AI Agent] S3 Bucket Policy Updated. Status: Private.` |
| **Evidence** | `[System] Capturing evidence for Audit Control CC1.1...` |
| **Outcome** | `[Output] Outcome Delivered: Readiness score 100%.` |

- Real-time typewriter animation with color-coded log levels
- Single-click "Run AI Autopilot" to watch the full cycle

### 3. Outcome-Based Pricing
Two tiers reflecting value-based (not seat-based) pricing:

| Plan | Price | Delivers |
|---|---|---|
| **Readiness Report** | $500 one-time | Full cloud scan, remediation roadmap, one-click fixes |
| **SOC2 Certification** | $5,000 per outcome | Full 104-control remediation, auto-evidence, guaranteed audit pass |

### 4. Tech Stack
| Layer | Technology |
|---|---|
| Structure | Vanilla HTML5 (semantic) |
| Styling | Vanilla CSS (custom properties, glassmorphism, keyframe animations) |
| Logic | Vanilla JavaScript (event-driven terminal simulation) |
| Fonts | Google Fonts (Outfit, JetBrains Mono) |

---

## 🗺️ Roadmap

### Phase 1 — Foundation ✅ _(Current)_
- [x] Landing page with glassmorphic design system
- [x] Interactive autopilot terminal demo
- [x] Outcome-based pricing UI
- [x] Responsive layout and micro-animations

### Phase 2 — Live Agent Integration ✅
- [x] Connect to real AWS/GCP/Azure APIs via OAuth
- [x] Implement actual cloud resource scanning (IAM policies, S3 buckets, security groups)
- [x] Build LLM-driven remediation engine (auto-close public buckets, enforce MFA, patch configs)
- [x] Real-time WebSocket log streaming to replace simulated terminal

### Phase 3 — Evidence & Audit Engine
- [ ] Automated evidence capture (screenshots, config diffs, timestamped logs)
- [ ] Map findings to SOC2 Trust Service Criteria (CC1–CC9)
- [ ] Generate PDF audit-ready reports with control-by-control evidence
- [ ] Digital signature and chain-of-custody tracking

### Phase 4 — Multi-Framework Compliance
- [ ] Extend beyond SOC2: support **GDPR**, **HIPAA**, **ISO 27001**, **PCI-DSS**
- [ ] Cross-framework control mapping (one remediation satisfies multiple standards)
- [ ] Regulatory change monitoring — auto-update controls when rules change

### Phase 5 — Continuous Compliance Platform
- [ ] Always-on monitoring with drift detection (alert when config regresses)
- [ ] Scheduled re-certification runs (quarterly, annual)
- [ ] Multi-tenant dashboard for MSPs managing multiple client environments
- [ ] API for CI/CD pipeline integration (block deploys that break compliance)

### Phase 6 — Marketplace & Ecosystem
- [ ] Plugin marketplace for custom compliance controls
- [ ] Third-party auditor portal (give auditors read-only access to evidence)
- [ ] SOC2 readiness score as a public trust badge for customer websites

---

## 🚀 Getting Started

```bash
# Clone the repo
git clone <repo-url>
cd compliance-flow

# Open in browser
# No build step required — it's a static site
open index.html
```

Or simply open `index.html` in any modern browser and click **"Run AI Autopilot"** to see the demo.

---

## 📁 Project Structure

```
compliance-flow/
├── index.html          # Landing page & autopilot terminal UI
├── app.html            # Full dashboard application
├── styles.css          # Landing page design system
├── dashboard.css       # Dashboard design system
├── service_demo.js     # Landing page terminal simulation
├── cloud-connect.js    # Simulated OAuth cloud connection
├── scanner.js          # Resource scanning engine
├── remediation.js      # Auto-remediation with config diffs
├── live-terminal.js    # Real-time filterable log stream
└── README.md           # This file
```

---

## 📄 License

MIT
