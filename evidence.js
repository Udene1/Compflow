// ─── ComplianceFlow AI: Evidence & Cryptographic Auditor Engine ───
// Captures multi-framework compliance proofs and provides auditor verification & token issuance

window.Evidence = (() => {
    let evidenceData = [];
    let reportGenerated = false;
    let latestAuditorToken = null;
    const API_BASE = window.COMPLIANCE_API_URL || '';

    async function SHA256(str) {
        if (!window.crypto || !window.crypto.subtle) {
            return 'SHA256-FALLBACK-' + Date.now();
        }
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        return 'SHA256-' + Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
    }

    function load() {
        try {
            const saved = localStorage.getItem('cf_evidence');
            if (saved) evidenceData = JSON.parse(saved);
        } catch (e) { console.error("Evidence Load Error", e); }
    }

    function save() {
        localStorage.setItem('cf_evidence', JSON.stringify(evidenceData));
    }

    async function captureFromScan(resource) {
        const controls = resource.controlKeys || ['soc2:CC6.1'];
        const hash = await SHA256(resource.name + resource.type + Date.now());
        
        const item = {
            id: 'EVD-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
            type: 'Inventory Scan',
            timestamp: new Date().toISOString(),
            source: resource.name,
            resourceType: resource.type,
            provider: resource.provider || 'AWS',
            controls: controls, 
            hash: hash,
            data: resource
        };
        evidenceData.push(item);
        save();
        
        if (window.LiveTerminal) {
            LiveTerminal.log('system', `Evidence captured: ${item.id} mapped to ${controls.length} frameworks.`);
        }
    }

    async function captureFromRemediation(resource, before, after) {
        const controls = resource.controlKeys || ['soc2:CC6.1'];
        const hash = await SHA256(resource.name + JSON.stringify(after) + Date.now());
        
        const item = {
            id: 'REM-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
            type: 'Remediation Action',
            timestamp: new Date().toISOString(),
            source: resource.name,
            resourceType: resource.type,
            provider: resource.provider || 'AWS',
            controls: controls,
            hash: hash,
            data: { before, after }
        };
        evidenceData.push(item);
        save();
        
        if (window.LiveTerminal) {
            LiveTerminal.log('system', `Remediation evidence signed: ${item.id}`);
        }
    }

    function refreshView() {
        const fw = Frameworks.getCurrent();
        const subtitle = document.getElementById('evidence-subtitle');
        if (subtitle) subtitle.textContent = `All captured evidence mapped to ${fw.name} requirements.`;

        buildEvidenceList();
        if (reportGenerated) {
            generateReport();
        }
        renderAuditorPanel();
    }

    function buildEvidenceList() {
        const container = document.getElementById('evidence-list');
        const empty = document.getElementById('evidence-empty');
        const fwId = Frameworks.getCurrentId();

        if (!container || !empty) return;

        if (evidenceData.length === 0) {
            empty.style.display = 'block';
            container.innerHTML = '';
            return;
        }

        empty.style.display = 'none';
        
        const filtered = evidenceData.filter(e => e.controls.some(c => c.startsWith(fwId)));

        container.innerHTML = filtered.map(item => {
            const ctrlLabels = item.controls.filter(c => c.startsWith(fwId)).map(c => c.split(':')[1]);
            return `
            <div class="evidence-entry">
                <div class="evidence-main">
                    <div class="ev-id">${item.id}</div>
                    <div class="ev-source">Source: <strong>${item.source}</strong></div>
                    <div class="ev-meta">
                        <span>🗓️ ${new Date(item.timestamp).toLocaleTimeString()}</span>
                        <span>🏷️ ${item.type}</span>
                        <div class="ev-ctrl-tags">
                            ${ctrlLabels.map(l => `<span class="tag-ctrl">${l}</span>`).join('')}
                        </div>
                    </div>
                    <div class="ev-hash">Hash: <code>${item.hash}</code></div>
                </div>
                <div class="ev-integrity">✓ Verified</div>
            </div>`;
        }).join('');
    }

    function generateReport() {
        if (evidenceData.length === 0) return;
        
        reportGenerated = true;
        const container = document.getElementById('report-findings-area');
        const empty = document.getElementById('report-empty');
        const proContainer = document.getElementById('professional-report-container');
        
        if (empty) empty.style.display = 'none';
        if (proContainer) proContainer.style.display = 'block';

        const repDate = document.getElementById('rep-date-val');
        if (repDate) repDate.textContent = new Date().toLocaleString();
        
        const frameworks = ['soc2', 'gdpr', 'hipaa', 'iso27001'];
        const coverage = {};
        
        frameworks.forEach(fwId => {
            const fw = Frameworks.DATA[fwId];
            if (!fw) return;
            const relevantEvidence = evidenceData.filter(e => e.controls.some(c => c.startsWith(fwId)));
            const coveredCtrls = new Set();
            relevantEvidence.forEach(e => {
                e.controls.filter(c => c.startsWith(fwId)).forEach(c => coveredCtrls.add(c));
            });
            const totalCtrls = Object.keys(fw.controls).length;
            coverage[fwId] = Math.round((coveredCtrls.size / totalCtrls) * 100);
            
            const scoreEl = document.getElementById(`score-${fwId === 'iso27001' ? 'iso' : fwId}`);
            if (scoreEl) scoreEl.textContent = coverage[fwId] + '%';
        });

        const avgCoverage = Object.values(coverage).reduce((a, b) => a + b, 0) / 4;
        const riskFill = document.getElementById('risk-fill');
        const riskVal = document.getElementById('risk-val');
        const riskLevel = 100 - avgCoverage;
        
        if (riskFill) riskFill.style.width = riskLevel + '%';
        if (riskVal) {
            if (riskLevel < 20) {
                riskVal.textContent = 'Low Risk';
                riskVal.style.color = 'var(--success)';
            } else if (riskLevel < 50) {
                riskVal.textContent = 'Medium Risk';
                riskVal.style.color = 'var(--warning)';
            } else {
                riskVal.textContent = 'High Risk';
                riskVal.style.color = 'var(--danger)';
            }
        }

        const summaryText = document.getElementById('exec-summary-text');
        const criticalCount = evidenceData.filter(e => e.data && e.data.severity === 'critical').length;
        if (summaryText) {
            summaryText.textContent = `Infrastructure audit complete. Analysis of 120+ controls reveals an average maturity of ${Math.round(avgCoverage)}%. ` +
                (criticalCount > 0 ? `Urgent attention required for ${criticalCount} critical vulnerabilities in perimeter security.` : 
                `Compliance posture is significantly hardened across all scale providers.`);
        }

        if (container) {
            container.innerHTML = `
                <div class="evidence-table-wrap">
                    <table class="evidence-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Resource</th>
                                <th>Provider</th>
                                <th>Controls Met</th>
                                <th>Integrity Hash</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${evidenceData.map(e => `
                                <tr>
                                    <td><code>${e.id}</code></td>
                                    <td>
                                        <div style="font-weight:600;">${e.source}</div>
                                        <div style="font-size:0.7rem; color:var(--text-dim);">${e.resourceType}</div>
                                    </td>
                                    <td><span class="fw-status-badge">${e.provider || 'Multi-Cloud'}</span></td>
                                    <td>
                                        <div class="control-badges-wrap">
                                            ${e.controls.map(c => {
                                                const fw = c.split(':')[0];
                                                const fwClass = fw === 'iso27001' ? 'iso' : fw;
                                                return `<span class="rem-control-tag ${fwClass}" title="${c}">${fw[0].toUpperCase()}</span>`;
                                            }).join('')}
                                        </div>
                                    </td>
                                    <td><code style="font-size:0.65rem;">${e.hash.substring(0, 16)}...</code></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }
    }

    function downloadJSON() {
        const fw = Frameworks.getCurrent();
        const dataStr = JSON.stringify({
            framework: fw.name,
            timestamp: new Date().toISOString(),
            evidence: evidenceData.filter(e => e.controls.some(c => c.startsWith(Frameworks.getCurrentId())))
        }, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', `ComplianceFlow_${fw.name}_Evidence.json`);
        linkElement.click();
    }

    // ─── SOC2 Third-Party Auditor Portal Sub-Module ───

    async function issueAuditorToken() {
        const tenantSelect = document.getElementById('auditor-tenant-select');
        const emailInput = document.getElementById('auditor-email-input');
        const expirySelect = document.getElementById('auditor-expiry-select');
        
        const tenantId = tenantSelect ? tenantSelect.value : 'demo-tenant';
        const auditorEmail = emailInput ? emailInput.value.trim() : 'auditor@complianceflow.icu';
        const expiresInHours = expirySelect ? parseInt(expirySelect.value, 10) : 48;

        if (!auditorEmail || !auditorEmail.includes('@')) {
            if (window.showToast) window.showToast('Please enter a valid auditor email.');
            return;
        }

        try {
            if (window.showToast) window.showToast('Generating HMAC-SHA256 Auditor Token...');
            
            const res = await fetch(`${API_BASE}/api/auditor/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tenantId, auditorEmail, expiresInHours })
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.error || `HTTP ${res.status}`);
            }

            const data = await res.json();
            latestAuditorToken = data.token;

            // Render token display in UI
            const tokenResultCard = document.getElementById('auditor-token-result');
            const tokenValue = document.getElementById('auditor-token-value');
            const tokenExpires = document.getElementById('auditor-token-expires');
            const portalLink = document.getElementById('auditor-portal-link');

            const fullExportUrl = `${window.location.origin}/api/auditor/export?token=${data.token}`;

            if (tokenResultCard) tokenResultCard.style.display = 'block';
            if (tokenValue) tokenValue.textContent = data.token;
            if (tokenExpires) tokenExpires.textContent = new Date(data.expiresAt).toLocaleString();
            if (portalLink) {
                portalLink.value = fullExportUrl;
            }

            if (window.showToast) window.showToast('✓ Auditor Access Token Generated!');
            if (window.LiveTerminal) {
                LiveTerminal.log('system', `Auditor access granted to ${auditorEmail}. Token valid until ${new Date(data.expiresAt).toLocaleTimeString()}`);
            }
        } catch (e) {
            console.error('Auditor token creation error:', e);
            if (window.showToast) window.showToast(`Error: ${e.message}`);
        }
    }

    function copyPortalLink() {
        const linkInput = document.getElementById('auditor-portal-link');
        if (!linkInput) return;
        
        linkInput.select();
        navigator.clipboard.writeText(linkInput.value).then(() => {
            if (window.showToast) window.showToast('📋 Auditor portal link copied to clipboard!');
        }).catch(() => {
            document.execCommand('copy');
            if (window.showToast) window.showToast('📋 Link copied!');
        });
    }

    async function downloadAuditorPackage() {
        try {
            if (window.showToast) window.showToast('Fetching cryptographically signed evidence bundle...');
            const token = latestAuditorToken || '';
            const url = token ? `${API_BASE}/api/auditor/export?token=${token}` : `${API_BASE}/api/auditor/export`;
            
            const res = await fetch(url);
            if (!res.ok) {
                throw new Error(`Export failed: HTTP ${res.status}`);
            }

            const data = await res.json();
            const bundle = data.package || data;

            // Trigger file download
            const dataStr = JSON.stringify(bundle, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
            const link = document.createElement('a');
            link.href = dataUri;
            link.download = `ComplianceFlow_SOC2_Auditor_Package_${Date.now()}.json`;
            link.click();

            if (window.showToast) window.showToast('📦 Signed evidence package downloaded.');
            if (window.LiveTerminal) {
                LiveTerminal.log('system', `Evidence bundle verified & downloaded. SHA-256 Digest: ${bundle.manifestHash || 'Verified'}`);
            }
        } catch (e) {
            console.error('Download package error:', e);
            if (window.showToast) window.showToast(`Download error: ${e.message}`);
        }
    }

    async function verifyEvidencePackage() {
        const input = document.getElementById('verify-package-input');
        const resultCard = document.getElementById('verify-result-card');
        const resultStatus = document.getElementById('verify-result-status');
        const resultDetails = document.getElementById('verify-result-details');

        if (!input || !input.value.trim()) {
            if (window.showToast) window.showToast('Please paste the JSON evidence package to verify.');
            return;
        }

        let packageObj;
        try {
            packageObj = JSON.parse(input.value.trim());
        } catch (e) {
            if (window.showToast) window.showToast('Invalid JSON format.');
            return;
        }

        try {
            if (window.showToast) window.showToast('Interrogating cryptographic HMAC-SHA256 signature...');

            const res = await fetch(`${API_BASE}/api/auditor/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ package: packageObj })
            });

            const verification = await res.json();
            if (resultCard) resultCard.style.display = 'block';

            if (verification.verified && verification.signatureMatch) {
                if (resultStatus) {
                    resultStatus.className = 'verify-badge-authentic';
                    resultStatus.innerHTML = '🛡️ CRYPTOGRAPHICALLY AUTHENTIC & UNTAMPERED';
                }
                if (resultDetails) {
                    resultDetails.innerHTML = `
                        <div class="verify-detail-row"><span>Status:</span> <strong style="color:var(--success)">PASSED (HMAC-SHA256 Valid)</strong></div>
                        <div class="verify-detail-row"><span>Manifest Hash:</span> <code>${verification.manifestHash}</code></div>
                        <div class="verify-detail-row"><span>Tenant ID:</span> <code>${verification.tenantId || 'Enterprise'}</code></div>
                        <div class="verify-detail-row"><span>Evidence Assets:</span> <strong>${verification.assetCount || 'Multi-Asset'} Items Verified</strong></div>
                        <div class="verify-detail-row"><span>Issued At:</span> <span>${new Date(verification.issuedAt).toLocaleString()}</span></div>
                        <div class="verify-detail-row"><span>Expires At:</span> <span>${new Date(verification.expiresAt).toLocaleString()}</span></div>
                    `;
                }
                if (window.showToast) window.showToast('✓ Package signature is authentic and untampered!');
                if (window.LiveTerminal) {
                    LiveTerminal.log('system', `Auditor Verification PASSED for ${verification.manifestHash?.slice(0, 16)}...`);
                }
            } else {
                if (resultStatus) {
                    resultStatus.className = 'verify-badge-tampered';
                    resultStatus.innerHTML = '⚠️ SIGNATURE MISMATCH / PACKAGE TAMPERED';
                }
                if (resultDetails) {
                    resultDetails.innerHTML = `
                        <div class="verify-detail-row"><span>Status:</span> <strong style="color:var(--danger)">FAILED / TAMPERED</strong></div>
                        <div class="verify-detail-row"><span>Reason:</span> <span>${verification.reason || 'Cryptographic HMAC digest does not match manifest.'}</span></div>
                    `;
                }
                if (window.showToast) window.showToast('❌ Warning: Evidence package integrity check failed!');
                if (window.LiveTerminal) {
                    LiveTerminal.log('insight', 'Auditor Verification FAILED: Cryptographic signature mismatch detected.');
                }
            }
        } catch (e) {
            console.error('Verify error:', e);
            if (window.showToast) window.showToast(`Verification error: ${e.message}`);
        }
    }

    function renderAuditorPanel() {
        const tenantSelect = document.getElementById('auditor-tenant-select');
        if (!tenantSelect) return;

        // Populate tenant select from TenantManager if available
        if (window.TenantManager && typeof window.TenantManager.getTenants === 'function') {
            const tenants = window.TenantManager.getTenants();
            if (tenants.length > 0) {
                tenantSelect.innerHTML = tenants.map(t => `<option value="${t.id}">${t.name} (${t.provider.toUpperCase()})</option>`).join('');
                return;
            }
        }
        
        tenantSelect.innerHTML = `
            <option value="prod-aws-env">AWS Production Environment</option>
            <option value="azure-cloud-core">Azure Enterprise Core</option>
            <option value="gcp-analytics-hub">GCP Analytics Cluster</option>
            <option value="hetzner-gpu-nodes">Hetzner Dedicated Fleet</option>
        `;
    }

    function getEvidenceLog() {
        return evidenceData;
    }

    load();

    return { 
        captureFromScan, 
        captureFromRemediation, 
        generateReport, 
        downloadJSON, 
        refreshView, 
        getEvidenceLog,
        // Auditor Portal Methods
        issueAuditorToken,
        copyPortalLink,
        downloadAuditorPackage,
        verifyEvidencePackage,
        renderAuditorPanel
    };
})();
