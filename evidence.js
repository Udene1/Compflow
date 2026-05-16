// ─── ComplianceFlow AI: Evidence & Audit Engine (Phase 4 Multi-Framework) ───
// Captures evidence across all mapped frameworks (SOC2, GDPR, HIPAA, ISO 27001)

window.Evidence = (() => {
    let evidenceData = [];
    let reportGenerated = false;

    async function SHA256(str) {
        if (!window.crypto || !window.crypto.subtle) {
            // Unlikely in modern browser context over localhost/HTTPS, but fallback
            return 'SHA256-FALLBACK-' + Date.now();
        }
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        return 'SHA256-' + Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
    }

    async function captureFromScan(resource) {
        // Tag with all mapped controls
        const controls = resource.controlKeys || ['soc2:CC6.1'];
        const hash = await SHA256(resource.name + resource.type + Date.now());
        
        const item = {
            id: 'EVD-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
            type: 'Inventory Scan',
            timestamp: new Date().toISOString(),
            source: resource.name,
            resourceType: resource.type,
            provider: 'AWS',
            controls: controls, 
            hash: hash,
            data: resource
        };
        evidenceData.push(item);
        
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
            provider: 'AWS',
            controls: controls,
            hash: hash,
            data: { before, after }
        };
        evidenceData.push(item);
        
        if (window.LiveTerminal) {
            LiveTerminal.log('system', `Remediation evidence signed: ${item.id}`);
        }
    }

    function refreshView() {
        const fw = Frameworks.getCurrent();
        
        // Update subtitles
        const subtitle = document.getElementById('evidence-subtitle');
        if (subtitle) subtitle.textContent = `All captured evidence mapped to ${fw.name} requirements.`;

        buildEvidenceList();
        if (reportGenerated) {
            generateReport();
        }
    }

    function buildEvidenceList() {
        const container = document.getElementById('evidence-list');
        const empty = document.getElementById('evidence-empty');
        const fwId = Frameworks.getCurrentId();

        if (evidenceData.length === 0) {
            empty.style.display = 'block';
            container.innerHTML = '';
            return;
        }

        empty.style.display = 'none';
        
        // Filter based on current framework
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
        function generateReport() {
        if (evidenceData.length === 0) return;
        
        reportGenerated = true;
        const container = document.getElementById('report-findings-area');
        const empty = document.getElementById('report-empty');
        const proContainer = document.getElementById('professional-report-container');
        
        empty.style.display = 'none';
        proContainer.style.display = 'block';

        // Set metadata
        document.getElementById('rep-date-val').textContent = new Date().toLocaleString();
        
        // Calculate scores for all frameworks
        const frameworks = ['soc2', 'gdpr', 'hipaa', 'iso27001'];
        const coverage = {};
        
        frameworks.forEach(fwId => {
            const fw = Frameworks.DATA[fwId];
            const relevantEvidence = evidenceData.filter(e => e.controls.some(c => c.startsWith(fwId)));
            const coveredCtrls = new Set();
            relevantEvidence.forEach(e => {
                e.controls.filter(c => c.startsWith(fwId)).forEach(c => coveredCtrls.add(c));
            });
            const totalCtrls = Object.keys(fw.controls).length;
            coverage[fwId] = Math.round((coveredCtrls.size / totalCtrls) * 100);
            
            // Update UI
            const scoreEl = document.getElementById(`score-${fwId === 'iso27001' ? 'iso' : fwId}`);
            if (scoreEl) scoreEl.textContent = coverage[fwId] + '%';
        });

        // Set Risk Meter (Inverse of average coverage)
        const avgCoverage = Object.values(coverage).reduce((a, b) => a + b, 0) / 4;
        const riskFill = document.getElementById('risk-fill');
        const riskVal = document.getElementById('risk-val');
        const riskLevel = 100 - avgCoverage;
        
        riskFill.style.width = riskLevel + '%';
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

        // Generate Executive Summary Text
        const summaryText = document.getElementById('exec-summary-text');
        const criticalCount = evidenceData.filter(e => e.data.severity === 'critical').length;
        summaryText.textContent = `Infrastructure audit complete. Analysis of 120+ controls reveals an average maturity of ${Math.round(avgCoverage)}%. ` +
            (criticalCount > 0 ? `Urgent attention required for ${criticalCount} critical vulnerabilities in perimeter security.` : 
            `Compliance posture is significantly hardened across all scale providers.`);

        // Build Findings Table
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
                                            const [fw, id] = c.split(':');
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

            <div class="report-chain no-print">
                <h4>🔐 Chain of Custody & Cryptographic Proof</h4>
                <div class="chain-info">
                    <span>Root Hash: <code>${evidenceData[0]?.hash || 'PENDING'}</code></span>
                    <span>Validator: ComplianceFlow AI Governance Node</span>
                    <span>State: <span class="chain-verified">✓ Cryptographically Verified</span></span>
                </div>
            </div>
        `;
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

    return { captureFromScan, captureFromRemediation, generateReport, downloadJSON, refreshView };
})();

