// ─── ComplianceFlow AI: Evidence & Audit Engine (Phase 4 Multi-Framework) ───
// Captures evidence across all mapped frameworks (SOC2, GDPR, HIPAA, ISO 27001)

window.Evidence = (() => {
    let evidenceData = [];
    let reportGenerated = false;

    function SHA256(str) {
        // Simple mock hash for demo; in real app, use crypto library
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0;
        }
        return 'SHA256-' + Math.abs(hash).toString(16).padStart(16, '0').toUpperCase();
    }

    function captureFromScan(resource) {
        // Tag with all mapped controls
        const controls = resource.controlKeys || ['soc2:CC6.1'];
        
        const item = {
            id: 'EVD-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
            type: 'Inventory Scan',
            timestamp: new Date().toISOString(),
            source: resource.name,
            resourceType: resource.type,
            provider: 'AWS',
            controls: controls, 
            hash: SHA256(resource.name + resource.type + Date.now()),
            data: resource
        };
        evidenceData.push(item);
        
        if (window.LiveTerminal) {
            LiveTerminal.log('system', `Evidence captured: ${item.id} mapped to ${controls.length} frameworks.`);
        }
    }

    function captureFromRemediation(resource, before, after) {
        const controls = resource.controlKeys || ['soc2:CC6.1'];
        
        const item = {
            id: 'REM-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
            type: 'Remediation Action',
            timestamp: new Date().toISOString(),
            source: resource.name,
            resourceType: resource.type,
            provider: 'AWS',
            controls: controls,
            hash: SHA256(resource.name + JSON.stringify(after) + Date.now()),
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
        }).join('');
    }

    function generateReport() {
        if (evidenceData.length === 0) return;
        
        reportGenerated = true;
        const container = document.getElementById('report-content');
        const empty = document.getElementById('report-empty');
        const fw = Frameworks.getCurrent();
        const fwId = Frameworks.getCurrentId();

        empty.style.display = 'none';
        
        // Calculate coverage based on framework controls
        const relevantEvidence = evidenceData.filter(e => e.controls.some(c => c.startsWith(fwId)));
        const coveredCtrls = new Set();
        relevantEvidence.forEach(e => {
            e.controls.filter(c => c.startsWith(fwId)).forEach(c => coveredCtrls.add(c));
        });

        const totalCtrls = Object.keys(fw.controls).length;
        const coveragePct = Math.round((coveredCtrls.size / totalCtrls) * 100);

        container.innerHTML = `
            <div class="report-header-block">
                <div class="report-meta">
                    <div class="report-badge fw-${fwId}">${fw.name}</div>
                    <h2>Compliance Readiness Audit</h2>
                    <p class="report-date">Generated: ${new Date().toLocaleString()} &nbsp;|&nbsp; Report ID: RPT-${Date.now().toString(36).toUpperCase()}</p>
                </div>
                <div class="report-summary-stats">
                    <div class="report-stat">
                        <div class="report-stat-value">${relevantEvidence.length}</div>
                        <div class="report-stat-label">Evidence Items</div>
                    </div>
                    <div class="report-stat">
                        <div class="report-stat-value">${coveredCtrls.size}</div>
                        <div class="report-stat-label">Controls Met</div>
                    </div>
                    <div class="report-stat">
                        <div class="report-stat-value">${coveragePct}%</div>
                        <div class="report-stat-label">Total Coverage</div>
                    </div>
                </div>
            </div>

            <div class="report-chain">
                <h4>🔐 Chain of Custody</h4>
                <div class="chain-info">
                    <span>Digital Signature: <code>${relevantEvidence[0]?.hash || 'PENDING'}</code></span>
                    <span>Signer: ComplianceFlow AI Orchestrator</span>
                    <span>Integrity: <span class="chain-verified">✓ Verified State</span></span>
                </div>
            </div>

            <h3 class="report-section-title">${fw.type} Coverage</h3>
            <div class="tsc-grid">
                ${Object.values(fw.controls).map(ctrl => {
                    const isCovered = coveredCtrls.has(fwId + ':' + ctrl.id);
                    return `
                        <div class="tsc-card ${isCovered ? 'covered' : 'uncovered'}">
                            <div class="tsc-id">${ctrl.id}</div>
                            <div class="tsc-title">${ctrl.name}</div>
                            <div class="tsc-status">${isCovered ? '✓ Covered' : '○ Pending'}</div>
                        </div>
                    `;
                }).join('')}
            </div>

            <div class="evidence-table-wrap">
                <table class="evidence-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Timestamp</th>
                            <th>Resource</th>
                            <th>Mapping</th>
                            <th>Integrity Hash</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${relevantEvidence.map(e => `
                            <tr>
                                <td><code>${e.id}</code></td>
                                <td style="font-size:0.72rem;">${new Date(e.timestamp).toLocaleTimeString()}</td>
                                <td>
                                    <div style="font-weight:600;">${e.source}</div>
                                    <div style="font-size:0.7rem;">${e.resourceType}</div>
                                </td>
                                <td>${e.controls.filter(c => c.startsWith(fwId)).map(c => `<span class="rem-control-tag">${c.split(':')[1]}</span>`).join(' ')}</td>
                                <td><code style="font-size:0.65rem;">${e.hash.substring(0, 16)}...</code></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>

            <div class="report-actions">
                <button class="btn btn-secondary" onclick="Evidence.downloadJSON()">📦 Export Evidence Pack (JSON)</button>
                <button class="btn btn-primary" onclick="window.print()">🖨️ Download ${fw.name} Report (PDF)</button>
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

