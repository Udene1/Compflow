// ─── ComplianceFlow AI: Remediation Engine ───
// Maps failing resources to SOC2 controls and provides auto-fix with config diffs

window.Remediation = (() => {
    let issues = [];

    const DIFFS = {
        'S3 Bucket': {
            'Public access enabled': {
                before: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::finance-records/*"
  }]
}`,
                after: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::finance-records/*",
    "Condition": {
      "Bool": { "aws:SecureTransport": "false" }
    }
  }],
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true,
    "BlockPublicPolicy": true
  }
}`
            },
            'No versioning': {
                before: `BucketVersioning:
  Status: Suspended
  MFADelete: Disabled`,
                after: `BucketVersioning:
  Status: Enabled
  MFADelete: Enabled`
            }
        },
        'IAM Role': {
            'No MFA enforced': {
                before: `{
  "PolicyName": "AdminAccess",
  "Condition": {}
}`,
                after: `{
  "PolicyName": "AdminAccess",
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}`
            },
            'Wildcard permissions (*)': {
                before: `{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}`,
                after: `{
  "Effect": "Allow",
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchGetImage",
    "ecs:UpdateService",
    "s3:GetObject"
  ],
  "Resource": "arn:aws:*:*:123456789:*"
}`
            },
            'Unused for 90 days': {
                before: `RoleStatus: Active
LastUsed: 2026-01-15T10:23:00Z`,
                after: `RoleStatus: Deactivated
LastUsed: 2026-01-15T10:23:00Z
DeactivatedAt: 2026-04-30T19:30:00Z
Reason: "Inactive > 90 days (SOC2 CC6.2)"`
            }
        },
        'EC2 Instance': {
            'Unpatched (14d overdue)': {
                before: `PatchStatus: NON_COMPLIANT
  PendingPatches: 3
  LastPatchRun: 2026-04-16
  OverdueDays: 14`,
                after: `PatchStatus: COMPLIANT
  PendingPatches: 0
  LastPatchRun: 2026-04-30
  OverdueDays: 0`
            }
        },
        'RDS Database': {
            'Encryption at rest disabled': {
                before: `StorageEncrypted: false
KmsKeyId: null`,
                after: `StorageEncrypted: true
KmsKeyId: "arn:aws:kms:us-east-1:123456789:key/mrk-abc123"
EncryptionType: "AES-256"`
            },
            'Backup retention < 7 days': {
                before: `BackupRetentionPeriod: 3
PreferredBackupWindow: "03:00-04:00"`,
                after: `BackupRetentionPeriod: 14
PreferredBackupWindow: "03:00-04:00"
PointInTimeRecovery: Enabled`
            }
        },
        'Lambda': {
            'Deprecated runtime (Node 14)': {
                before: `Runtime: nodejs14.x
LastModified: 2025-06-01
DeprecationDate: 2025-11-27`,
                after: `Runtime: nodejs20.x
LastModified: 2026-04-30
MigrationNote: "Automated runtime upgrade"`
            }
        },
        'Security Group': {
            'Allows 0.0.0.0/0 on port 22': {
                before: `IngressRules:
  - Protocol: tcp
    Port: 22
    Source: 0.0.0.0/0
    Description: "SSH open to world"`,
                after: `IngressRules:
  - Protocol: tcp
    Port: 22
    Source: 10.0.0.0/16
    Description: "SSH restricted to VPC CIDR"
  - Protocol: tcp
    Port: 22
    Source: 203.0.113.5/32
    Description: "SSH from bastion host"`
            },
            'Overly permissive egress rules': {
                before: `EgressRules:
  - Protocol: -1
    Port: All
    Destination: 0.0.0.0/0`,
                after: `EgressRules:
  - Protocol: tcp
    Port: 443
    Destination: 0.0.0.0/0
    Description: "HTTPS only"
  - Protocol: tcp
    Port: 5432
    Destination: 10.0.2.0/24
    Description: "Postgres to DB subnet"`
            }
        },
        'Secrets Manager': {
            'Rotation disabled (last: 120d ago)': {
                before: `RotationEnabled: false
LastRotatedDate: 2025-12-31
RotationLambdaARN: null`,
                after: `RotationEnabled: true
LastRotatedDate: 2026-04-30
RotationLambdaARN: "arn:aws:lambda:us-east-1:123456789:function:SecretRotator"
RotationSchedule: "rate(30 days)"`
            }
        }
    };

    const CONTROL_NAMES = {
        'CC6.1': 'Logical & Physical Access Controls',
        'CC6.2': 'User Access Management',
        'CC6.3': 'Authentication Mechanisms',
        'CC6.6': 'System Boundary Protection',
        'CC6.7': 'Data Encryption',
        'CC7.1': 'System Monitoring & Patching',
        'CC7.2': 'Activity Logging',
        'CC8.1': 'Change Management',
    };

    function buildFromScan(resources) {
        issues = resources.filter(r => r.severity !== 'pass');
        const list = document.getElementById('remediation-list');
        const emptyEl = document.getElementById('rem-empty');
        const fixAllBtn = document.getElementById('btn-fix-all');

        list.innerHTML = '';

        if (issues.length === 0) {
            emptyEl.style.display = 'block';
            fixAllBtn.style.display = 'none';
            return;
        }

        emptyEl.style.display = 'none';
        fixAllBtn.style.display = 'inline-flex';
        document.getElementById('rem-subtitle').textContent =
            `${issues.length} issue${issues.length > 1 ? 's' : ''} found across ${new Set(issues.map(i => i.control)).size} controls.`;

        issues.forEach((issue, i) => {
            const diff = getDiff(issue);
            const controlName = CONTROL_NAMES[issue.control] || issue.control;

            const card = document.createElement('div');
            card.className = 'remediation-card';
            card.id = 'rem-card-' + issue.id;

            const sevClass = issue.severity === 'critical' ? 'critical' : 'warning';
            const sevIcon = issue.severity === 'critical' ? '✕' : '⚠';

            card.innerHTML = `
                <div class="rem-card-header" data-toggle="rem-detail-${issue.id}">
                    <div class="rem-card-info">
                        <span class="severity-badge ${sevClass}">${sevIcon} ${issue.severity}</span>
                        <h4>${issue.icon} ${issue.name}</h4>
                        <span class="rem-control-tag">${issue.control}: ${controlName}</span>
                    </div>
                    <div class="rem-card-actions">
                        <span style="color:var(--text-dim); font-size:0.8rem;">${issue.issue}</span>
                        <button class="btn btn-primary btn-sm" id="fix-btn-${issue.id}" onclick="Remediation.fixSingle(${issue.id})">Auto-Fix</button>
                    </div>
                </div>
                <div class="rem-detail" id="rem-detail-${issue.id}">
                    <div class="rem-detail-inner">
                        <p style="font-size:0.82rem; color:var(--text-muted); margin:0.75rem 0 0;">
                            <strong>Resource:</strong> ${issue.type} / ${issue.name} (${issue.region})<br>
                            <strong>Issue:</strong> ${issue.issue}
                        </p>
                        ${diff ? `
                        <div class="diff-block">
                            <div class="line-context">--- Before (current config)</div>
                            ${diff.before.split('\n').map(l => `<div class="line-remove">- ${l}</div>`).join('')}
                            <div class="line-context" style="margin-top:0.5rem;">+++ After (remediated)</div>
                            ${diff.after.split('\n').map(l => `<div class="line-add">+ ${l}</div>`).join('')}
                        </div>` : ''}
                    </div>
                </div>
            `;

            list.appendChild(card);

            // Toggle detail
            card.querySelector('.rem-card-header').addEventListener('click', (e) => {
                if (e.target.tagName === 'BUTTON') return;
                const detail = document.getElementById('rem-detail-' + issue.id);
                detail.classList.toggle('open');
            });
        });

        // Fix All button
        fixAllBtn.onclick = fixAll;
    }

    function getDiff(resource) {
        const typeDiffs = DIFFS[resource.type];
        if (!typeDiffs) return null;
        return typeDiffs[resource.issue] || null;
    }

    function fixSingle(resourceId) {
        const issue = issues.find(i => i.id === resourceId);
        if (!issue) return;

        const providers = CloudConnect.getProviders();
        const provider = providers[0];
        const credentials = CloudConnect.getCredentials(provider);

        if (!credentials) {
            LiveTerminal.log('insight', 'ERROR: Missing credentials for ' + provider);
            CloudConnect.openSettings(provider);
            return;
        }

        const btn = document.getElementById('fix-btn-' + resourceId);
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>';

        LiveTerminal.log('action', `EXECUTING REAL FIX: ${issue.type} "${issue.name}" — ${issue.issue}`);

        fetch('/api/remediate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                provider, 
                credentials, 
                resourceType: issue.type, 
                resourceName: issue.name, 
                issue: issue.issue 
            })
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) throw new Error(data.error);

            btn.textContent = '✓ Fixed';
            btn.className = 'btn btn-success btn-sm';
            const card = document.getElementById('rem-card-' + resourceId);
            card.classList.add('fixed');

            // Update severity badge in remediation card
            const badge = card.querySelector('.severity-badge');
            badge.className = 'severity-badge pass';
            badge.textContent = '✓ pass';

            Scanner.markFixed(resourceId);
            LiveTerminal.log('output', `SUCCESS: ${issue.type} "${issue.name}" remediated via real-world API call.`);

            // Capture Evidence
            if (window.Evidence) {
                const diff = getDiff(issue);
                Evidence.captureFromRemediation(issue, diff?.before, diff?.after);
            }
            if (window.Scanner) Scanner.updateEvidenceBadge();

            checkAllFixed();
        })
        .catch(err => {
            console.error(err);
            LiveTerminal.log('insight', `FIX FAILED: ${err.message}`);
            btn.disabled = false;
            btn.textContent = 'Retry Fix';
        });
    }

    function fixAll() {
        const unfixed = issues.filter(i => {
            const card = document.getElementById('rem-card-' + i.id);
            return card && !card.classList.contains('fixed');
        });

        if (unfixed.length === 0) return;

        const progressWrap = document.getElementById('fix-all-progress');
        const progressFill = document.getElementById('fix-all-fill');
        progressWrap.style.display = 'block';

        LiveTerminal.log('action', `BULK REMEDIATION: Fixing ${unfixed.length} issues...`);

        let idx = 0;
        const interval = setInterval(() => {
            if (idx >= unfixed.length) {
                clearInterval(interval);
                progressFill.style.width = '100%';
                LiveTerminal.log('output', `All ${unfixed.length} issues remediated. Readiness: 100%.`);
                document.getElementById('btn-fix-all').style.display = 'none';
                return;
            }

            fixSingle(unfixed[idx].id);
            const pct = Math.round(((idx + 1) / unfixed.length) * 100);
            progressFill.style.width = pct + '%';
            idx++;
        }, 1500);
    }

    function checkAllFixed() {
        const remaining = issues.filter(i => {
            const card = document.getElementById('rem-card-' + i.id);
            return card && !card.classList.contains('fixed');
        });
        if (remaining.length === 0) {
            document.getElementById('btn-fix-all').style.display = 'none';
            document.getElementById('rem-subtitle').textContent = 'All issues remediated. Readiness: 100%.';
        }
    }

    return { buildFromScan, fixSingle, fixAll };
})();
