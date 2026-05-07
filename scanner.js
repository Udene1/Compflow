// ─── ComplianceFlow AI: Resource Scanner ───
// Generates a realistic cloud resource inventory and scans for compliance issues

window.Scanner = (() => {
    const RESOURCE_TEMPLATES = [
        { name: 'finance-records', type: 'S3 Bucket', icon: '🪣', region: 'us-east-1', severity: 'critical', control: 'CC6.1', issue: 'Public access enabled' },
        { name: 'user-uploads', type: 'S3 Bucket', icon: '🪣', region: 'us-east-1', severity: 'warning', control: 'CC6.6', issue: 'No versioning' },
        { name: 'static-assets', type: 'S3 Bucket', icon: '🪣', region: 'us-west-2', severity: 'pass', control: 'CC6.1' },
        { name: 'admin-root', type: 'IAM Role', icon: '🔑', region: 'global', severity: 'critical', control: 'CC6.3', issue: 'No MFA enforced' },
        { name: 'deploy-bot', type: 'IAM Role', icon: '🔑', region: 'global', severity: 'critical', control: 'CC6.1', issue: 'Wildcard permissions (*)' },
        { name: 'readonly-audit', type: 'IAM Role', icon: '🔑', region: 'global', severity: 'pass', control: 'CC6.3' },
        { name: 'ci-runner', type: 'IAM Role', icon: '🔑', region: 'global', severity: 'warning', control: 'CC6.2', issue: 'Unused for 90 days' },
        { name: 'prod-api-01', type: 'EC2 Instance', icon: '🖥️', region: 'us-east-1', severity: 'warning', control: 'CC7.1', issue: 'Unpatched (14d overdue)' },
        { name: 'prod-api-02', type: 'EC2 Instance', icon: '🖥️', region: 'us-east-1', severity: 'pass', control: 'CC7.1' },
        { name: 'staging-web', type: 'EC2 Instance', icon: '🖥️', region: 'eu-west-1', severity: 'pass', control: 'CC7.1' },
        { name: 'prod-db-primary', type: 'RDS Database', icon: '💾', region: 'us-east-1', severity: 'critical', control: 'CC6.7', issue: 'Encryption at rest disabled' },
        { name: 'prod-db-replica', type: 'RDS Database', icon: '💾', region: 'us-east-1', severity: 'pass', control: 'CC6.7' },
        { name: 'analytics-db', type: 'RDS Database', icon: '💾', region: 'us-west-2', severity: 'warning', control: 'CC6.7', issue: 'Backup retention < 7 days' },
        { name: 'process-invoices', type: 'Lambda', icon: '⚡', region: 'us-east-1', severity: 'pass', control: 'CC8.1' },
        { name: 'email-sender', type: 'Lambda', icon: '⚡', region: 'us-east-1', severity: 'warning', control: 'CC8.1', issue: 'Deprecated runtime (Node 14)' },
        { name: 'auth-handler', type: 'Lambda', icon: '⚡', region: 'us-east-1', severity: 'pass', control: 'CC8.1' },
        { name: 'vpc-production', type: 'VPC', icon: '🌐', region: 'us-east-1', severity: 'pass', control: 'CC6.6' },
        { name: 'sg-default', type: 'Security Group', icon: '🛡️', region: 'us-east-1', severity: 'critical', control: 'CC6.6', issue: 'Allows 0.0.0.0/0 on port 22' },
        { name: 'sg-api', type: 'Security Group', icon: '🛡️', region: 'us-east-1', severity: 'pass', control: 'CC6.6' },
        { name: 'sg-database', type: 'Security Group', icon: '🛡️', region: 'us-east-1', severity: 'warning', control: 'CC6.6', issue: 'Overly permissive egress rules' },
        { name: 'cloudtrail-main', type: 'CloudTrail', icon: '📋', region: 'us-east-1', severity: 'pass', control: 'CC7.2' },
        { name: 'kms-master', type: 'KMS Key', icon: '🔐', region: 'us-east-1', severity: 'pass', control: 'CC6.1' },
        { name: 'secrets-prod', type: 'Secrets Manager', icon: '🗝️', region: 'us-east-1', severity: 'warning', control: 'CC6.1', issue: 'Rotation disabled (last: 120d ago)' },
        { name: 'ecr-api-image', type: 'ECR Repository', icon: '📦', region: 'us-east-1', severity: 'pass', control: 'CC8.1' },
    ];

    let scannedResources = [];

    function init() {
        document.getElementById('btn-start-scan').addEventListener('click', startScan);
    }

    function startScan() {
        if (!CloudConnect.isConnected()) {
            LiveTerminal.log('insight', 'ERROR: No cloud provider connected. Go to Cloud Connect first.');
            return;
        }

        const providers = CloudConnect.getProviders();
        const provider = providers[0]; // Start with first connected
        const credentials = CloudConnect.getCredentials(provider);

        if (!credentials) {
            LiveTerminal.log('insight', 'ERROR: Missing credentials for ' + provider);
            CloudConnect.openSettings(provider);
            return;
        }

        const btn = document.getElementById('btn-start-scan');
        btn.disabled = true;
        btn.textContent = 'Scanning...';

        scannedResources = [];
        document.getElementById('resource-tbody').innerHTML = '';
        document.getElementById('scan-empty').style.display = 'none';
        document.getElementById('resource-table').style.display = 'table';
        document.getElementById('scan-stats').style.display = 'grid';
        document.getElementById('scan-progress-wrap').style.display = 'block';
        document.getElementById('scan-progress-fill').style.width = '10%';

        LiveTerminal.log('system', `Contacting real cloud APIs for ${provider.toUpperCase()}...`);
        LiveTerminal.log('agent', `Requesting enumeration of S3 and IAM resources...`);

        fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider, credentials })
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) throw new Error(data.error);

            scannedResources = data.resources || [];
            document.getElementById('scan-progress-fill').style.width = '100%';

            scannedResources.forEach((res, i) => {
                addResourceRow({ ...res, id: i }, i);
                
                // Log findings
                if (res.severity === 'critical') {
                    LiveTerminal.log('insight', `CRITICAL: ${res.type} "${res.name}" — ${res.issue}`);
                } else if (res.severity === 'warning') {
                    LiveTerminal.log('agent', `Warning: ${res.type} "${res.name}" — ${res.issue}`);
                }
            });

            const issues = scannedResources.filter(r => r.severity !== 'pass');
            LiveTerminal.log('output', `Scan complete: ${scannedResources.length} resources discovered. ${issues.length} issues found.`);

            // Stats
            const counts = getCounts();
            document.getElementById('stat-total').textContent = counts.total;
            document.getElementById('stat-pass').textContent = counts.pass;
            document.getElementById('stat-warn').textContent = counts.warn;
            document.getElementById('stat-crit').textContent = counts.crit;

            // Badges
            const badge = document.getElementById('issues-badge');
            if (issues.length > 0) {
                badge.style.display = 'inline';
                badge.textContent = issues.length;
            }

            updateScore();

            // Evidence
            scannedResources.forEach(r => {
                if (window.Evidence) Evidence.captureFromScan(r);
            });
            updateEvidenceBadge();

            // Remediation
            Remediation.buildFromScan(scannedResources);
            
            btn.disabled = false;
            btn.textContent = 'Re-scan';
        })
        .catch(err => {
            console.error(err);
            LiveTerminal.log('insight', `SCAN FAILED: ${err.message}`);
            btn.disabled = false;
            btn.textContent = 'Retry Scan';
        });
    }

    function addResourceRow(res, delay) {
        const tbody = document.getElementById('resource-tbody');
        const tr = document.createElement('tr');
        tr.className = 'resource-row';
        tr.style.animationDelay = '0s';
        tr.id = 'resource-row-' + res.id;

        const sevClass = res.severity === 'pass' ? 'pass' : res.severity === 'warning' ? 'warning' : 'critical';
        const sevLabel = res.severity === 'pass' ? '✓ Pass' : res.severity === 'warning' ? '⚠ Warning' : '✕ Critical';
        const issueText = res.issue || 'No issues';

        tr.innerHTML = `
            <td><div class="resource-name">${res.icon} ${res.name}</div>
                <div style="font-size:0.72rem; color:var(--text-dim); margin-top:2px;">${issueText}</div></td>
            <td><span class="resource-type">${res.type}</span></td>
            <td style="color:var(--text-muted); font-size:0.82rem;">${res.region}</td>
            <td><span class="severity-badge ${sevClass}">${sevLabel}</span></td>
            <td><span class="rem-control-tag">${res.control}</span></td>
        `;
        tbody.appendChild(tr);
    }

    function getCounts() {
        const total = scannedResources.length;
        const pass = scannedResources.filter(r => r.severity === 'pass').length;
        const warn = scannedResources.filter(r => r.severity === 'warning').length;
        const crit = scannedResources.filter(r => r.severity === 'critical').length;
        return { total, pass, warn, crit };
    }

    function updateScore() {
        const counts = getCounts();
        const score = counts.total > 0 ? Math.round((counts.pass / counts.total) * 100) : 0;
        document.getElementById('sidebar-score').textContent = score + '%';
    }

    function markFixed(resourceId) {
        const res = scannedResources.find(r => r.id === resourceId);
        if (res) {
            res.severity = 'pass';
            res.issue = null;
            const row = document.getElementById('resource-row-' + resourceId);
            if (row) {
                const badge = row.querySelector('.severity-badge');
                badge.className = 'severity-badge pass';
                badge.textContent = '✓ Pass';
                const issueDiv = row.querySelector('.resource-name').parentElement.querySelector('div:nth-child(2)');
                if (issueDiv) issueDiv.textContent = 'Remediated';
            }
            // Update stats
            const counts = getCounts();
            document.getElementById('stat-pass').textContent = counts.pass;
            document.getElementById('stat-warn').textContent = counts.warn;
            document.getElementById('stat-crit').textContent = counts.crit;

            const issues = scannedResources.filter(r => r.severity !== 'pass');
            const badge = document.getElementById('issues-badge');
            badge.textContent = issues.length;
            if (issues.length === 0) badge.style.display = 'none';

            updateScore();
        }
    }

    function updateEvidenceBadge() {
        if (!window.Evidence) return;
        const log = Evidence.getEvidenceLog();
        const badge = document.getElementById('evidence-badge');
        if (badge && log.length > 0) {
            badge.style.display = 'inline';
            badge.textContent = log.length;
        }
        // Update evidence list panel
        const listEl = document.getElementById('evidence-list');
        const emptyEl = document.getElementById('evidence-empty');
        if (listEl && log.length > 0) {
            emptyEl.style.display = 'none';
            document.getElementById('evidence-subtitle').textContent = 
                `${log.length} evidence items captured with SHA-256 integrity hashes.`;
            listEl.innerHTML = log.map(e => `
                <div class="evidence-entry">
                    <div class="evidence-entry-header">
                        <code>${e.id}</code>
                        <span class="rem-control-tag">${e.control}</span>
                        <span class="severity-badge ${e.afterState === 'Compliant' ? 'pass' : 'critical'}">
                            ${e.afterState === 'Compliant' ? '✓ Compliant' : '✕ Finding'}
                        </span>
                    </div>
                    <div class="evidence-entry-body">
                        <span>${e.resource} (${e.resourceType})</span>
                        <span style="color:var(--text-dim); font-size:0.72rem;">${e.action}</span>
                    </div>
                    <div class="evidence-entry-hash">
                        <code style="font-size:0.65rem; color:var(--text-dim);">SHA-256: ${e.hash.substring(0, 24)}...</code>
                        <span style="font-size:0.7rem; color:var(--text-dim);">${new Date(e.timestamp).toLocaleTimeString()}</span>
                    </div>
                </div>
            `).join('');
        }
    }

    function getResources() { return scannedResources; }

    return { init, getResources, markFixed, updateEvidenceBadge };
})();

document.addEventListener('DOMContentLoaded', Scanner.init);
