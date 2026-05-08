import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand, GetBucketVersioningCommand, GetBucketEncryptionCommand, GetBucketLoggingCommand } from "@aws-sdk/client-s3";
import { IAMClient, ListRolesCommand, GetAccountSummaryCommand, GetAccountPasswordPolicyCommand, ListUsersCommand, ListAccessKeysCommand } from "@aws-sdk/client-iam";
import { EC2Client, DescribeSecurityGroupsCommand, DescribeVpcsCommand, DescribeInstancesCommand, DescribeFlowLogsCommand } from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { KMSClient, ListKeysCommand, DescribeKeyCommand, GetKeyRotationStatusCommand } from "@aws-sdk/client-kms";
import { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } from "@aws-sdk/client-cloudtrail";
import { Macie2Client, GetMacieSessionCommand } from "@aws-sdk/client-macie2";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { WAFV2Client, ListWebACLsCommand } from "@aws-sdk/client-wafv2";
import { ShieldClient, GetSubscriptionStatusCommand } from "@aws-sdk/client-shield";
import { SecretsManagerClient, ListSecretsCommand } from "@aws-sdk/client-secrets-manager";

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { credentials, provider } = req.body;

    const XOR_KEY = 'CompFlow_Guard_2026';
    function deobfuscate(encoded) {
        if (!encoded) return '';
        const decoded = atob(encoded);
        let out = "";
        for (let i = 0; i < decoded.length; i++) {
            out += String.fromCharCode(decoded.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
        }
        return out;
    }

    if (!credentials || !credentials.accessKeyId || !credentials.secretAccessKey) {
        return res.status(400).json({ error: 'Missing cloud credentials' });
    }

    try {
        const config = {
            region: credentials.region || 'us-east-1',
            credentials: {
                accessKeyId: credentials.isObfuscated ? deobfuscate(credentials.accessKeyId) : credentials.accessKeyId,
                secretAccessKey: credentials.isObfuscated ? deobfuscate(credentials.secretAccessKey) : credentials.secretAccessKey
            }
        };

        const resources = [];
        
        if (provider === 'aws') {
            const s3 = new S3Client(config);
            const iam = new IAMClient(config);
            const ec2 = new EC2Client(config);
            const rds = new RDSClient(config);
            const kms = new KMSClient(config);
            const cloudtrail = new CloudTrailClient(config);
            const macie = new Macie2Client(config);
            const lambda = new LambdaClient(config);
            const waf = new WAFV2Client(config);
            const shield = new ShieldClient(config);
            const sm = new SecretsManagerClient(config);

            // ═══════════════════════════════════════════
            // 1. S3 BUCKETS — Deep Scan
            // ═══════════════════════════════════════════
            try {
                const { Buckets } = await s3.send(new ListBucketsCommand({}));
                for (const bucket of Buckets || []) {
                    // Check: Public Access Block
                    let severity = 'pass';
                    let issue = null;
                    try {
                        await s3.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name }));
                    } catch (e) {
                        severity = 'critical';
                        issue = 'Public access enabled';
                    }
                    resources.push({
                        name: bucket.Name, type: 'S3 Bucket', icon: '🪣',
                        region: config.region, severity, control: 'CC6.1', issue
                    });

                    // Check: Versioning
                    try {
                        const vRes = await s3.send(new GetBucketVersioningCommand({ Bucket: bucket.Name }));
                        if (vRes.Status !== 'Enabled') {
                            resources.push({
                                name: bucket.Name, type: 'S3 Bucket', icon: '🪣',
                                region: config.region, severity: 'warning', control: 'CC7.2',
                                issue: 'Versioning not enabled'
                            });
                        }
                    } catch (e) { /* skip */ }

                    // Check: Default Encryption
                    try {
                        await s3.send(new GetBucketEncryptionCommand({ Bucket: bucket.Name }));
                    } catch (e) {
                        resources.push({
                            name: bucket.Name, type: 'S3 Bucket', icon: '🪣',
                            region: config.region, severity: 'warning', control: 'CC6.7',
                            issue: 'Default encryption disabled'
                        });
                    }

                    // Check: Server Access Logging
                    try {
                        const logRes = await s3.send(new GetBucketLoggingCommand({ Bucket: bucket.Name }));
                        if (!logRes.LoggingEnabled) {
                            resources.push({
                                name: bucket.Name, type: 'S3 Bucket', icon: '🪣',
                                region: config.region, severity: 'warning', control: 'CC7.2',
                                issue: 'Server access logging disabled'
                            });
                        }
                    } catch (e) { /* skip */ }
                }
            } catch (e) { console.warn("S3 fail", e); }

            // ═══════════════════════════════════════════
            // 2. EC2 — Security Groups, VPCs, Instances
            // ═══════════════════════════════════════════
            try {
                const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({}));
                for (const sg of SecurityGroups || []) {
                    const isOpen = sg.IpPermissions.some(p => 
                        (p.FromPort <= 22 && p.ToPort >= 22 || p.IpProtocol === '-1') && 
                        p.IpRanges.some(r => r.CidrIp === '0.0.0.0/0')
                    );
                    resources.push({
                        name: sg.GroupName, type: 'Security Group', icon: '🛡️',
                        region: config.region, 
                        severity: isOpen ? 'critical' : 'pass',
                        control: 'CC6.6',
                        issue: isOpen ? 'Allows 0.0.0.0/0 on port 22' : null
                    });
                }

                // VPCs + Flow Logs check
                const { Vpcs } = await ec2.send(new DescribeVpcsCommand({}));
                for (const vpc of Vpcs || []) {
                    let flowLogsEnabled = false;
                    try {
                        const { FlowLogs } = await ec2.send(new DescribeFlowLogsCommand({
                            Filter: [{ Name: 'resource-id', Values: [vpc.VpcId] }]
                        }));
                        flowLogsEnabled = FlowLogs && FlowLogs.length > 0;
                    } catch (e) { /* skip */ }

                    resources.push({
                        name: vpc.VpcId, type: 'VPC', icon: '🌐',
                        region: config.region,
                        severity: flowLogsEnabled ? 'pass' : 'warning',
                        control: 'CC7.2',
                        issue: flowLogsEnabled ? null : 'Flow Logs disabled'
                    });
                }

                // EC2 Instances — IMDSv2 check
                try {
                    const { Reservations } = await ec2.send(new DescribeInstancesCommand({
                        Filters: [{ Name: 'instance-state-name', Values: ['running'] }]
                    }));
                    for (const res of Reservations || []) {
                        for (const inst of res.Instances || []) {
                            const imdsV2 = inst.MetadataOptions?.HttpTokens === 'required';
                            const nameTag = inst.Tags?.find(t => t.Key === 'Name')?.Value || inst.InstanceId;
                            if (!imdsV2) {
                                resources.push({
                                    name: nameTag, type: 'EC2 Instance', icon: '💻',
                                    region: config.region, severity: 'warning', control: 'CC6.3',
                                    issue: 'IMDSv2 not enforced'
                                });
                            }
                        }
                    }
                } catch (e) { console.warn("EC2 instances fail", e); }
            } catch (e) { console.warn("EC2/VPC fail", e); }

            // ═══════════════════════════════════════════
            // 3. RDS — Deep Scan
            // ═══════════════════════════════════════════
            try {
                const { DBInstances } = await rds.send(new DescribeDBInstancesCommand({}));
                for (const db of DBInstances || []) {
                    // Encryption at rest
                    if (!db.StorageEncrypted) {
                        resources.push({
                            name: db.DBInstanceIdentifier, type: 'RDS Database', icon: '💾',
                            region: config.region, severity: 'critical', control: 'CC6.7',
                            issue: 'Encryption at rest disabled'
                        });
                    }
                    // Backup retention
                    if ((db.BackupRetentionPeriod || 0) < 7) {
                        resources.push({
                            name: db.DBInstanceIdentifier, type: 'RDS Database', icon: '💾',
                            region: config.region, severity: 'warning', control: 'CC7.2',
                            issue: `Backup retention < 7 days (currently ${db.BackupRetentionPeriod || 0}d)`
                        });
                    }
                    // Multi-AZ
                    if (!db.MultiAZ) {
                        resources.push({
                            name: db.DBInstanceIdentifier, type: 'RDS Database', icon: '💾',
                            region: config.region, severity: 'warning', control: 'CC7.1',
                            issue: 'Multi-AZ disabled (no failover)'
                        });
                    }
                    // Publicly accessible
                    if (db.PubliclyAccessible) {
                        resources.push({
                            name: db.DBInstanceIdentifier, type: 'RDS Database', icon: '💾',
                            region: config.region, severity: 'critical', control: 'CC6.6',
                            issue: 'Publicly accessible'
                        });
                    }
                    // If all pass, add a clean entry
                    if (db.StorageEncrypted && (db.BackupRetentionPeriod || 0) >= 7 && db.MultiAZ && !db.PubliclyAccessible) {
                        resources.push({
                            name: db.DBInstanceIdentifier, type: 'RDS Database', icon: '💾',
                            region: config.region, severity: 'pass', control: 'CC6.7', issue: null
                        });
                    }
                }
            } catch (e) { console.warn("RDS fail", e); }

            // ═══════════════════════════════════════════
            // 4. CloudTrail — Deep Scan
            // ═══════════════════════════════════════════
            try {
                const { TrailList } = await cloudtrail.send(new DescribeTrailsCommand({}));
                if (!TrailList || TrailList.length === 0) {
                    resources.push({
                        name: 'Global', type: 'CloudTrail', icon: '📋',
                        region: 'Global', severity: 'critical', control: 'CC7.2', issue: 'No trail enabled'
                    });
                } else {
                    for (const t of TrailList) {
                        // Log validation
                        if (!t.LogFileValidationEnabled) {
                            resources.push({
                                name: t.Name, type: 'CloudTrail', icon: '📋',
                                region: t.HomeRegion, severity: 'warning', control: 'CC7.2',
                                issue: 'Log Validation disabled'
                            });
                        }
                        // Multi-region
                        if (!t.IsMultiRegionTrail) {
                            resources.push({
                                name: t.Name, type: 'CloudTrail', icon: '📋',
                                region: t.HomeRegion, severity: 'warning', control: 'CC7.2',
                                issue: 'Not multi-region (blind spots in other regions)'
                            });
                        }
                        // Log encryption
                        if (!t.KmsKeyId) {
                            resources.push({
                                name: t.Name, type: 'CloudTrail', icon: '📋',
                                region: t.HomeRegion, severity: 'warning', control: 'CC6.7',
                                issue: 'Log encryption disabled (no KMS key)'
                            });
                        }
                        // All pass
                        if (t.LogFileValidationEnabled && t.IsMultiRegionTrail && t.KmsKeyId) {
                            resources.push({
                                name: t.Name, type: 'CloudTrail', icon: '📋',
                                region: t.HomeRegion, severity: 'pass', control: 'CC7.2', issue: null
                            });
                        }
                    }
                }
            } catch (e) { console.warn("CloudTrail fail", e); }

            // ═══════════════════════════════════════════
            // 5. Macie
            // ═══════════════════════════════════════════
            try {
                const { status } = await macie.send(new GetMacieSessionCommand({}));
                resources.push({
                    name: 'Macie Service', type: 'Macie', icon: '🔍',
                    region: 'Global', severity: status === 'ENABLED' ? 'pass' : 'warning',
                    control: 'Art. 25', issue: status === 'ENABLED' ? null : 'Automated Data Discovery disabled'
                });
            } catch (e) { 
                resources.push({
                    name: 'Macie Service', type: 'Macie', icon: '🔍',
                    region: 'Global', severity: 'warning', control: 'Art. 25',
                    issue: 'Macie not initialized'
                });
            }

            // ═══════════════════════════════════════════
            // 6. KMS Keys — Deep Scan
            // ═══════════════════════════════════════════
            try {
                const { Keys } = await kms.send(new ListKeysCommand({}));
                for (const k of (Keys || []).slice(0, 5)) {
                    const { KeyMetadata } = await kms.send(new DescribeKeyCommand({ KeyId: k.KeyId }));
                    if (KeyMetadata.KeyManager === 'CUSTOMER') {
                        const { RotationEnabled } = await kms.send(new GetKeyRotationStatusCommand({ KeyId: k.KeyId }));
                        resources.push({
                            name: k.KeyId.substring(0, 8), type: 'KMS Key', icon: '🔐',
                            region: config.region, severity: RotationEnabled ? 'pass' : 'warning',
                            control: 'CC6.7', issue: RotationEnabled ? null : 'Key Rotation disabled'
                        });
                    }
                }
            } catch (e) { console.warn("KMS fail", e); }

            // ═══════════════════════════════════════════
            // 7. Lambda — Deep Scan
            // ═══════════════════════════════════════════
            try {
                const { Functions } = await lambda.send(new ListFunctionsCommand({}));
                for (const fn of (Functions || []).slice(0, 15)) {
                    const issues = [];
                    // Deprecated runtime check
                    const deprecated = ['nodejs12.x','nodejs14.x','nodejs16.x','python3.7','python3.8','dotnetcore3.1','ruby2.7'];
                    const isOld = fn.Runtime && deprecated.some(d => fn.Runtime.includes(d));
                    if (isOld) {
                        resources.push({
                            name: fn.FunctionName, type: 'Lambda', icon: '⚡',
                            region: config.region, severity: 'critical', control: 'CC7.1',
                            issue: `Deprecated runtime (${fn.Runtime})`
                        });
                    }
                    // VPC attachment check
                    if (!fn.VpcConfig || !fn.VpcConfig.VpcId) {
                        resources.push({
                            name: fn.FunctionName, type: 'Lambda', icon: '⚡',
                            region: config.region, severity: 'warning', control: 'CC6.6',
                            issue: 'Not VPC-attached (public network exposure)'
                        });
                    }
                    // Environment variable secrets exposure
                    if (fn.Environment?.Variables) {
                        const suspectKeys = Object.keys(fn.Environment.Variables).filter(k =>
                            /secret|password|key|token|api_key/i.test(k)
                        );
                        if (suspectKeys.length > 0) {
                            resources.push({
                                name: fn.FunctionName, type: 'Lambda', icon: '⚡',
                                region: config.region, severity: 'warning', control: 'CC6.1',
                                issue: `Possible secrets in env vars: ${suspectKeys.join(', ')}`
                            });
                        }
                    }
                    // If all pass
                    if (!isOld && fn.VpcConfig?.VpcId && !(fn.Environment?.Variables && Object.keys(fn.Environment.Variables).some(k => /secret|password|key|token|api_key/i.test(k)))) {
                        resources.push({
                            name: fn.FunctionName, type: 'Lambda', icon: '⚡',
                            region: config.region, severity: 'pass', control: 'CC7.1', issue: null
                        });
                    }
                }
            } catch (e) { console.warn("Lambda fail", e); }

            // ═══════════════════════════════════════════
            // 8. WAF & Shield
            // ═══════════════════════════════════════════
            try {
                const { WebACLs } = await waf.send(new ListWebACLsCommand({ Scope: 'REGIONAL' }));
                if (!WebACLs || WebACLs.length === 0) {
                    resources.push({
                        name: 'Web Perimeter', type: 'WAF', icon: '🧱',
                        region: config.region, severity: 'warning', control: 'CC6.7', issue: 'No WAF WebACLs found'
                    });
                } else {
                    resources.push({
                        name: `${WebACLs.length} WebACL(s)`, type: 'WAF', icon: '🧱',
                        region: config.region, severity: 'pass', control: 'CC6.7', issue: null
                    });
                }
            } catch (e) { console.warn("WAF fail", e); }

            try {
                const { Status } = await shield.send(new GetSubscriptionStatusCommand({}));
                resources.push({
                    name: 'Shield Protection', type: 'Shield', icon: '🛡️',
                    region: 'Global',
                    severity: Status === 'SUBSCRIBED' ? 'pass' : 'warning',
                    control: 'CC6.7',
                    issue: Status === 'SUBSCRIBED' ? null : 'Shield Advanced not active'
                });
            } catch (e) { console.warn("Shield fail", e); }

            // ═══════════════════════════════════════════
            // 9. IAM — Deep Scan
            // ═══════════════════════════════════════════
            try {
                const { SummaryMap } = await iam.send(new GetAccountSummaryCommand({}));
                if (SummaryMap.AccountMFAEnabled === 0) {
                    resources.push({
                        name: 'Root Account', type: 'IAM Account', icon: '👤',
                        region: 'Global', severity: 'critical', control: 'CC6.3', issue: 'Root MFA disabled'
                    });
                }
                // Password policy
                try {
                    const policy = await iam.send(new GetAccountPasswordPolicyCommand({}));
                    const pp = policy.PasswordPolicy;
                    if (pp.MinimumPasswordLength < 14 || !pp.RequireSymbols || !pp.RequireNumbers) {
                        resources.push({
                            name: 'Password Policy', type: 'IAM Account', icon: '👤',
                            region: 'Global', severity: 'warning', control: 'CC6.3',
                            issue: `Weak password policy (min length: ${pp.MinimumPasswordLength}, symbols: ${pp.RequireSymbols ? 'yes':'no'})`
                        });
                    }
                } catch (e) {
                    // No password policy set at all
                    resources.push({
                        name: 'Password Policy', type: 'IAM Account', icon: '👤',
                        region: 'Global', severity: 'critical', control: 'CC6.3',
                        issue: 'No account password policy configured'
                    });
                }

                // Stale IAM Roles
                const { Roles } = await iam.send(new ListRolesCommand({}));
                for (const role of (Roles || []).slice(0, 10)) {
                    const ageDays = (new Date() - new Date(role.CreateDate)) / (1000 * 60 * 60 * 24);
                    if (ageDays > 180) {
                        resources.push({
                            name: role.RoleName, type: 'IAM Role', icon: '🔑',
                            region: 'global', severity: 'warning',
                            control: 'CC6.2', issue: `Stale Access (${Math.round(ageDays)} days old)`
                        });
                    }
                }

                // Access Key Age
                try {
                    const { Users } = await iam.send(new ListUsersCommand({}));
                    for (const user of (Users || []).slice(0, 10)) {
                        const { AccessKeyMetadata } = await iam.send(new ListAccessKeysCommand({ UserName: user.UserName }));
                        for (const key of AccessKeyMetadata || []) {
                            if (key.Status === 'Active') {
                                const keyAgeDays = (new Date() - new Date(key.CreateDate)) / (1000 * 60 * 60 * 24);
                                if (keyAgeDays > 90) {
                                    resources.push({
                                        name: `${user.UserName} / ${key.AccessKeyId.substring(0, 8)}...`, type: 'IAM Role', icon: '🔑',
                                        region: 'Global', severity: 'warning', control: 'CC6.2',
                                        issue: `Access key >90 days old (${Math.round(keyAgeDays)}d)`
                                    });
                                }
                            }
                        }
                    }
                } catch (e) { console.warn("IAM access keys fail", e); }
            } catch (e) { console.warn("IAM fail", e); }

            // ═══════════════════════════════════════════
            // 10. Secrets Manager
            // ═══════════════════════════════════════════
            try {
                const { SecretList } = await sm.send(new ListSecretsCommand({}));
                for (const secret of SecretList || []) {
                    if (!secret.RotationEnabled) {
                        const lastRotated = secret.LastRotatedDate 
                            ? Math.round((new Date() - new Date(secret.LastRotatedDate)) / (1000 * 60 * 60 * 24))
                            : 'never';
                        resources.push({
                            name: secret.Name, type: 'Secrets Manager', icon: '🔒',
                            region: config.region, severity: 'warning', control: 'CC6.2',
                            issue: `Rotation disabled (last: ${lastRotated === 'never' ? 'never' : lastRotated + 'd ago'})`
                        });
                    } else {
                        resources.push({
                            name: secret.Name, type: 'Secrets Manager', icon: '🔒',
                            region: config.region, severity: 'pass', control: 'CC6.2', issue: null
                        });
                    }
                }
            } catch (e) { console.warn("Secrets Manager fail", e); }
        }

        res.status(200).json({ resources });
    } catch (error) {
        console.error('Scan Error:', error);
        res.status(500).json({ error: error.message });
    }
}
