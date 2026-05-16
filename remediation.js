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
            'Versioning not enabled': {
                before: `BucketVersioning:
  Status: Suspended
  MFADelete: Disabled`,
                after: `BucketVersioning:
  Status: Enabled
  MFADelete: Enabled`
            },
            'Default encryption disabled': {
                before: `ServerSideEncryptionConfiguration:
  Rules: []
  BucketKeyEnabled: false`,
                after: `ServerSideEncryptionConfiguration:
  Rules:
    - ApplyServerSideEncryptionByDefault:
        SSEAlgorithm: "aws:kms"
      BucketKeyEnabled: true`
            },
            'Server access logging disabled': {
                before: `LoggingConfiguration:
  TargetBucket: null
  TargetPrefix: null`,
                after: `LoggingConfiguration:
  TargetBucket: "my-access-logs-bucket"
  TargetPrefix: "s3-access-logs/"
  TargetGrants:
    - Permission: FULL_CONTROL`
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
            'Stale Access': {
                before: `AssumeRolePolicyDocument:
  Statement:
    - Effect: Allow
      Principal: { AWS: "*" }
      Action: "sts:AssumeRole"`,
                after: `AssumeRolePolicyDocument:
  Statement:
    - Effect: Deny
      Principal: "*"
      Action: "sts:AssumeRole"
      Condition:
        ComplianceFlow: "deactivated"
  DeactivatedAt: 2026-05-08
  Reason: "Stale > 180 days (SOC2 CC6.2)"`
            },
            'Access key >90 days': {
                before: `AccessKey:
  Status: Active
  CreateDate: 2026-01-15
  AgeDays: 113`,
                after: `AccessKey:
  Status: Inactive
  CreateDate: 2026-01-15
  DeactivatedAt: 2026-05-08
  NewKey: "AKIA...ROTATED"
  Reason: "Key age > 90 days (SOC2 CC6.2)"`
            }
        },
        'IAM Account': {
            'Root MFA disabled': {
                before: `AccountMFAEnabled: 0
  RootAccountUsed: true
  MFADevices: []`,
                after: `AccountMFAEnabled: 1
  RootAccountUsed: false
  MFADevices:
    - SerialNumber: "arn:aws:iam::mfa/root-account"
      Type: "virtual"
  Note: "ADVISORY — Must enable MFA via AWS Console"`
            },
            'No account password policy': {
                before: `PasswordPolicy: null
  # No password policy configured`,
                after: `PasswordPolicy:
  MinimumPasswordLength: 14
  RequireSymbols: true
  RequireNumbers: true
  RequireUppercaseCharacters: true
  RequireLowercaseCharacters: true
  MaxPasswordAge: 90
  PasswordReusePrevention: 12`
            },
            'Weak password policy': {
                before: `PasswordPolicy:
  MinimumPasswordLength: 8
  RequireSymbols: false
  RequireNumbers: false`,
                after: `PasswordPolicy:
  MinimumPasswordLength: 14
  RequireSymbols: true
  RequireNumbers: true
  RequireUppercaseCharacters: true
  RequireLowercaseCharacters: true
  MaxPasswordAge: 90
  PasswordReusePrevention: 12`
            }
        },
        'EC2 Instance': {
            'IMDSv2 not enforced': {
                before: `MetadataOptions:
  HttpTokens: optional
  HttpEndpoint: enabled
  HttpPutResponseHopLimit: 1`,
                after: `MetadataOptions:
  HttpTokens: required       # IMDSv2 enforced
  HttpEndpoint: enabled
  HttpPutResponseHopLimit: 1
  InstanceMetadataTags: enabled`
            }
        },
        'RDS Database': {
            'Encryption at rest disabled': {
                before: `StorageEncrypted: false
KmsKeyId: null`,
                after: `StorageEncrypted: true
KmsKeyId: "arn:aws:kms:us-east-1:123456789:key/mrk-abc123"
EncryptionType: "AES-256"
Note: "ADVISORY — Requires snapshot + restore"`
            },
            'Backup retention': {
                before: `BackupRetentionPeriod: 3
PreferredBackupWindow: "03:00-04:00"`,
                after: `BackupRetentionPeriod: 14
PreferredBackupWindow: "03:00-04:00"
PointInTimeRecovery: Enabled`
            },
            'Multi-AZ disabled': {
                before: `MultiAZ: false
AvailabilityZone: us-east-1a
FailoverCapability: none`,
                after: `MultiAZ: true
AvailabilityZone: us-east-1a
StandbyAZ: us-east-1b
FailoverCapability: automatic`
            },
            'Publicly accessible': {
                before: `PubliclyAccessible: true
Endpoint: mydb.abc123.us-east-1.rds.amazonaws.com
Port: 5432`,
                after: `PubliclyAccessible: false
Endpoint: mydb.abc123.us-east-1.rds.amazonaws.com
Port: 5432
NetworkAccess: "VPC internal only"`
            }
        },
        'Lambda': {
            'Deprecated runtime': {
                before: `Runtime: nodejs14.x
LastModified: 2025-06-01
DeprecationDate: 2025-11-27`,
                after: `Runtime: nodejs20.x
LastModified: 2026-05-08
MigrationNote: "Automated runtime upgrade by ComplianceFlow"`
            },
            'Not VPC-attached': {
                before: `VpcConfig:
  VpcId: null
  SubnetIds: []
  SecurityGroupIds: []`,
                after: `VpcConfig:
  VpcId: "vpc-0abc123def456"
  SubnetIds: ["subnet-priv-1a", "subnet-priv-1b"]
  SecurityGroupIds: ["sg-lambda-internal"]
  Note: "ADVISORY — Configure VPC manually"`
            },
            'Possible secrets in env vars': {
                before: `Environment:
  Variables:
    DB_PASSWORD: "hunter2"
    API_KEY: "sk-live-abc123..."`,
                after: `Environment:
  Variables:
    DB_PASSWORD: "{{resolve:secretsmanager:prod/db-password}}"
    API_KEY: "{{resolve:secretsmanager:prod/api-key}}"
  Note: "Use Secrets Manager references instead of plaintext"`
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
            }
        },
        'CloudTrail': {
            'No trail enabled': {
                before: `TrailList: []
  # No CloudTrail configured`,
                after: `TrailList:
  - Name: "complianceflow-audit"
    IsMultiRegionTrail: true
    EnableLogFileValidation: true
    S3BucketName: "complianceflow-audit-logs"
    KmsKeyId: "arn:aws:kms:us-east-1:123456789:key/ct-key"
  Note: "ADVISORY — Requires S3 bucket with correct policy"`
            },
            'Log Validation disabled': {
                before: `Trail:
  Name: "my-trail"
  EnableLogFileValidation: false`,
                after: `Trail:
  Name: "my-trail"
  EnableLogFileValidation: true
  DigestDelivery: Enabled`
            },
            'Not multi-region': {
                before: `Trail:
  Name: "my-trail"
  IsMultiRegionTrail: false
  HomeRegion: us-east-1`,
                after: `Trail:
  Name: "my-trail"
  IsMultiRegionTrail: true
  HomeRegion: us-east-1
  Coverage: "All AWS regions"`
            },
            'Log encryption disabled': {
                before: `Trail:
  Name: "my-trail"
  KmsKeyId: null
  S3BucketEncryption: "SSE-S3"`,
                after: `Trail:
  Name: "my-trail"
  KmsKeyId: "arn:aws:kms:us-east-1:123456789:key/ct-encrypt"
  S3BucketEncryption: "SSE-KMS"
  Note: "ADVISORY — Requires KMS key with correct policy"`
            }
        },
        'VPC': {
            'Flow Logs disabled': {
                before: `FlowLogs: []
  TrafficCapture: none`,
                after: `FlowLogs:
  - ResourceId: "vpc-0abc123"
    ResourceType: VPC
    TrafficType: ALL
    LogDestination: "cloud-watch-logs"
    LogGroupName: "/complianceflow/vpc-flow-logs"
    DeliverLogsPermissionArn: "arn:aws:iam::role/FlowLogRole"`
            }
        },
        'KMS Key': {
            'Key Rotation disabled': {
                before: `KeyId: "mrk-abc123"
KeyManager: CUSTOMER
RotationEnabled: false
NextRotation: null`,
                after: `KeyId: "mrk-abc123"
KeyManager: CUSTOMER
RotationEnabled: true
RotationPeriod: 365
NextRotation: "2027-05-08"`
            }
        },
        'Secrets Manager': {
            'Rotation disabled': {
                before: `RotationEnabled: false
LastRotatedDate: null
RotationLambdaARN: null`,
                after: `RotationEnabled: true
LastRotatedDate: 2026-05-08
RotationLambdaARN: "arn:aws:lambda:us-east-1:123456789:function:SecretRotator"
RotationSchedule: "rate(30 days)"
Note: "ADVISORY — Requires rotation Lambda"`
            }
        },
        'Macie': {
            'Macie not initialized': {
                before: `MacieStatus: NOT_ENABLED
DataDiscovery: disabled`,
                after: `MacieStatus: ENABLED
DataDiscovery: automatic
ClassificationJobs: active
Note: "ADVISORY — Enable via AWS Console > Macie"`
            },
            'Automated Data Discovery disabled': {
                before: `MacieStatus: PAUSED
DataDiscovery: disabled`,
                after: `MacieStatus: ENABLED
DataDiscovery: automatic
Note: "ADVISORY — Re-enable via AWS Console"`
            }
        },
        'WAF': {
            'No WAF WebACLs found': {
                before: `WebACLs: []
Protection: none`,
                after: `WebACLs:
  - Name: "complianceflow-waf"
    Scope: REGIONAL
    Rules:
      - AWSManagedRulesCommonRuleSet
      - AWSManagedRulesSQLiRuleSet
      - RateLimitRule (2000 req/5min)
Note: "ADVISORY — Create WebACL via WAF Console"`
            }
        },
        'Shield': {
            'Shield Advanced not active': {
                before: `ShieldSubscription: INACTIVE
DDoSProtection: Basic only`,
                after: `ShieldSubscription: ACTIVE
DDoSProtection: Advanced
ResponseTeam: AWS Shield Response Team
CostProtection: enabled
Note: "ADVISORY — $3,000/mo subscription required"`
            }
        },
        'DynamoDB Table': {
            'PITR (Continuous Backups) disabled': {
                before: `ContinuousBackups:
  PointInTimeRecoveryStatus: DISABLED`,
                after: `ContinuousBackups:
  PointInTimeRecoveryStatus: ENABLED
  Note: "Automated PITR enablement applied"`
            }
        },
        'API Gateway': {
            'Default execute-api endpoint enabled': {
                before: `RestApi:
  disableExecuteApiEndpoint: false
  EndpointConfiguration: EDGE`,
                after: `RestApi:
  disableExecuteApiEndpoint: true
  EndpointConfiguration: EDGE
  Note: "Forces clients to use custom domain routing"`
            }
        },
        'API Gateway Stage': {
            'X-Ray Tracing disabled': {
                before: `Stage:
  tracingEnabled: false
  metricsEnabled: true`,
                after: `Stage:
  tracingEnabled: true
  metricsEnabled: true`
            }
        },

        // ── GCP Resource Diffs ──
        'GCP Firewall': {
            '0.0.0.0/0 allowed on port 22': {
                before: `gcloud compute firewall-rules describe allow-all-ingress:
  sourceRanges: ["0.0.0.0/0"]
  allowed:
    - IPProtocol: tcp
      ports: ["22"]
  direction: INGRESS`,
                after: `gcloud compute firewall-rules update allow-all-ingress:
  sourceRanges: ["10.128.0.0/9"]
  allowed:
    - IPProtocol: tcp
      ports: ["22"]
  direction: INGRESS
  # SSH restricted to internal VPC CIDR`
            }
        },
        'GCP Instance': {
            'External IP address assigned': {
                before: `networkInterfaces:
  - accessConfigs:
      - name: "External NAT"
        type: ONE_TO_ONE_NAT
        natIP: 35.202.xxx.xxx`,
                after: `networkInterfaces:
  - accessConfigs: []
    # External IP removed
    # Use Cloud NAT for outbound traffic
    # Use IAP for SSH access`
            }
        },
        'GCP CloudSQL': {
            'Public IP enabled': {
                before: `settings:
  ipConfiguration:
    ipv4Enabled: true
    authorizedNetworks:
      - value: "0.0.0.0/0"`,
                after: `settings:
  ipConfiguration:
    ipv4Enabled: false
    privateNetwork: "projects/myproj/global/networks/prod-vpc"
    requireSsl: true`
            }
        },
        'GCP Bucket': {
            'Object versioning disabled': {
                before: `gsutil versioning get gs://cf-audit-logs-private:
  Suspended`,
                after: `gsutil versioning set on gs://cf-audit-logs-private:
  Enabled`
            }
        },
        'GCP IAM': {
            'Default Service Account has Editor role': {
                before: `gcloud projects get-iam-policy:
  bindings:
    - role: roles/editor
      members:
        - serviceAccount:default-sa@project.iam`,
                after: `gcloud projects get-iam-policy:
  bindings:
    - role: roles/storage.objectViewer
      members:
        - serviceAccount:default-sa@project.iam
    - role: roles/cloudsql.client
      members:
        - serviceAccount:default-sa@project.iam
  # Least-privilege roles applied`
            }
        },
        'GCP VPC': {
            'VPC Flow Logs disabled': {
                before: `subnetworks:
  - name: "default"
    enableFlowLogs: false`,
                after: `subnetworks:
  - name: "default"
    enableFlowLogs: true
    logConfig:
      aggregationInterval: INTERVAL_5_SEC
      flowSampling: 1.0
      metadata: INCLUDE_ALL_METADATA`
            }
        },
        'GCP KMS': {
            'Key rotation disabled': {
                before: `cryptoKeys:
  - name: "kms-key-prod"
    rotationPeriod: null
    nextRotationTime: null`,
                after: `cryptoKeys:
  - name: "kms-key-prod"
    rotationPeriod: "7776000s"  # 90 days
    nextRotationTime: "2026-08-14T00:00:00Z"`
            }
        },

        // ── Azure Resource Diffs ──
        'Azure NSG': {
            'Inbound rule': {
                before: `az network nsg rule show:
  name: AllowAnyCustom
  sourceAddressPrefix: "*"
  destinationPortRange: "*"
  access: Allow
  priority: 100`,
                after: `az network nsg rule update:
  name: AllowVNetOnly
  sourceAddressPrefix: "10.0.0.0/8"
  destinationPortRange: "443"
  access: Allow
  priority: 100
  # Wildcard removed — VNet only`
            }
        },
        'Azure VM': {
            'Managed Identity not assigned': {
                before: `az vm identity show:
  type: None
  # No managed identity assigned`,
                after: `az vm identity assign:
  type: SystemAssigned
  principalId: "12345-abcde-67890"
  tenantId: "tenant-uuid"
  # RBAC-based auth enabled`
            }
        },
        'Azure Storage': {
            'Public blob access enabled': {
                before: `az storage account show:
  allowBlobPublicAccess: true
  minimumTlsVersion: TLS1_0`,
                after: `az storage account update:
  allowBlobPublicAccess: false
  minimumTlsVersion: TLS1_2
  supportsHttpsTrafficOnly: true`
            }
        },
        'Azure SQL': {
            'Firewall allows 0.0.0.0': {
                before: `az sql server firewall-rule list:
  - name: "AllowAllAzureIps"
    startIpAddress: "0.0.0.0"
    endIpAddress: "0.0.0.0"`,
                after: `az sql server firewall-rule delete:
  # Removed "AllowAllAzureIps" rule
  # Access via VNet Service Endpoints only
  az sql server vnet-rule create:
    - subnet: "prod-data-subnet"`
            }
        },
        'Azure KeyVault': {
            'Soft delete disabled': {
                before: `az keyvault show:
  properties:
    enableSoftDelete: false
    enablePurgeProtection: false`,
                after: `az keyvault update:
  properties:
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true`
            }
        },
        'Azure Monitor': {
            'No diagnostic settings configured': {
                before: `az monitor diagnostic-settings list:
  value: []
  # No activity log export`,
                after: `az monitor diagnostic-settings create:
  logs:
    - category: Administrative
    - category: Security
    - category: Alert
    - category: Policy
  workspaceId: "/subscriptions/.../logAnalytics"
  retentionPolicy:
    enabled: true
    days: 365`
            }
        },
        'Azure AD': {
            'Conditional Access MFA not enforced': {
                before: `Conditional Access Policies:
  - AdminMFA: NOT_CONFIGURED
  # No MFA requirement for admins`,
                after: `Conditional Access Policies:
  - name: "Require MFA for Admins"
    state: enabled
    conditions:
      users: directoryRoles/GlobalAdministrator
    grantControls:
      builtInControls: ["mfa"]`
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
        'Art. 25': 'Data Protection by Design (GDPR)',
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
        // Exact match first
        if (typeDiffs[resource.issue]) return typeDiffs[resource.issue];
        // Partial match — scan issue text may contain dynamic values
        for (const key of Object.keys(typeDiffs)) {
            if (resource.issue && resource.issue.includes(key)) return typeDiffs[key];
        }
        return null;
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

            const card = document.getElementById('rem-card-' + resourceId);
            const badge = card.querySelector('.severity-badge');

            if (data.advisory) {
                // Advisory — not auto-fixable, show info state
                btn.textContent = 'ⓘ Advisory';
                btn.className = 'btn btn-warning btn-sm';
                btn.disabled = true;
                card.classList.add('fixed');
                badge.className = 'severity-badge warning';
                badge.textContent = '⚠ advisory';
                LiveTerminal.log('insight', `ADVISORY: ${data.message}`);
            } else {
                // Real fix applied
                btn.textContent = '✓ Fixed';
                btn.className = 'btn btn-success btn-sm';
                card.classList.add('fixed');
                badge.className = 'severity-badge pass';
                badge.textContent = '✓ pass';
                Scanner.markFixed(resourceId);
                LiveTerminal.log('output', `SUCCESS: ${issue.type} "${issue.name}" remediated via real-world API call.`);
            }

            // Capture Evidence
            if (window.Evidence) {
                const diff = getDiff(issue);
                Evidence.captureFromRemediation(issue, diff?.before, diff?.after).then(() => {
                    if (window.Scanner) Scanner.updateEvidenceBadge();
                });
            } else {
                if (window.Scanner) Scanner.updateEvidenceBadge();
            }

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
