import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand, GetBucketVersioningCommand, GetBucketEncryptionCommand, GetBucketLoggingCommand, GetBucketLifecycleConfigurationCommand } from "@aws-sdk/client-s3";
import { IAMClient, ListRolesCommand, GetAccountSummaryCommand, GetAccountPasswordPolicyCommand, ListUsersCommand, ListAccessKeysCommand, ListMFADevicesCommand, ListUserPoliciesCommand, ListAttachedUserPoliciesCommand, ListRolePoliciesCommand } from "@aws-sdk/client-iam";
import { EC2Client, DescribeSecurityGroupsCommand, DescribeVpcsCommand, DescribeInstancesCommand, DescribeFlowLogsCommand, DescribeNetworkInterfacesCommand, DescribeAddressesCommand, DescribeVolumesCommand, DescribeSnapshotsCommand, DescribeSnapshotAttributeCommand } from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { KMSClient, ListKeysCommand, DescribeKeyCommand, GetKeyRotationStatusCommand } from "@aws-sdk/client-kms";
import { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } from "@aws-sdk/client-cloudtrail";
import { Macie2Client, GetMacieSessionCommand } from "@aws-sdk/client-macie2";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { WAFV2Client, ListWebACLsCommand } from "@aws-sdk/client-wafv2";
import { ShieldClient, GetSubscriptionStateCommand } from "@aws-sdk/client-shield";
import { SecretsManagerClient, ListSecretsCommand } from "@aws-sdk/client-secrets-manager";
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { GuardDutyClient, ListDetectorsCommand } from "@aws-sdk/client-guardduty";
import { ConfigServiceClient, DescribeConfigurationRecordersCommand } from "@aws-sdk/client-config-service";
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand, DescribeContinuousBackupsCommand } from "@aws-sdk/client-dynamodb";
import { EKSClient, ListClustersCommand, DescribeClusterCommand } from "@aws-sdk/client-eks";
import { RedshiftClient, DescribeClustersCommand } from "@aws-sdk/client-redshift";
import { APIGatewayClient, GetRestApisCommand, GetStagesCommand } from "@aws-sdk/client-api-gateway";
import { CloudFrontClient, ListDistributionsCommand, GetDistributionConfigCommand } from "@aws-sdk/client-cloudfront";
import { SQSClient, ListQueuesCommand, GetQueueAttributesCommand } from "@aws-sdk/client-sqs";
import { SNSClient, ListTopicsCommand, GetTopicAttributesCommand } from "@aws-sdk/client-sns";
import { log } from './logger.js';

export async function runScan(provider, credentials) {

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
        throw new Error('Missing cloud credentials');
    }

    try {
        const config = {
            region: credentials.region || 'us-east-1',
            credentials: {
                accessKeyId: credentials.isObfuscated ? deobfuscate(credentials.accessKeyId) : credentials.accessKeyId,
                secretAccessKey: credentials.isObfuscated ? deobfuscate(credentials.secretAccessKey) : credentials.secretAccessKey,
                sessionToken: credentials.sessionToken
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
            const cloudwatch = new CloudWatchClient(config);
            const cwLogs = new CloudWatchLogsClient(config);
            const guardduty = new GuardDutyClient(config);
            const configService = new ConfigServiceClient(config);
            const dynamodb = new DynamoDBClient(config);
            const eks = new EKSClient(config);
            const redshift = new RedshiftClient(config);
            const apigw = new APIGatewayClient(config);
            const cloudfront = new CloudFrontClient(config);
            const sqs = new SQSClient(config);
            const sns = new SNSClient(config);

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
                        region: config.region, severity, 
                        technicalId: severity === 'pass' ? null : 'S3_PUBLIC', issue
                    });

                    // Check: Versioning & MFA Delete
                    try {
                        const vRes = await s3.send(new GetBucketVersioningCommand({ Bucket: bucket.Name }));
                        if (vRes.Status !== 'Enabled') {
                            resources.push({
                                name: bucket.Name, type: 'S3 Bucket', icon: '🪣',
                                region: config.region, severity: 'warning',
                                technicalId: 'S3_VERSIONING',
                                issue: 'Versioning not enabled'
                            });
                        }
                        if (vRes.MFADelete !== 'Enabled') {
                            resources.push({
                                name: bucket.Name, type: 'S3 Bucket', icon: '🪣',
                                region: config.region, severity: 'warning', control: 'CC6.3',
                                issue: 'MFA Delete disabled'
                            });
                        }
                    } catch (e) { /* skip */ }

                    // Check: Default Encryption
                    try {
                        await s3.send(new GetBucketEncryptionCommand({ Bucket: bucket.Name }));
                    } catch (e) {
                        resources.push({
                            name: bucket.Name, type: 'S3 Bucket', icon: '🪣',
                            region: config.region, severity: 'warning',
                            technicalId: 'S3_ENCRYPTION',
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

                    // Check: Lifecycle Policy
                    try {
                        await s3.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket.Name }));
                    } catch (e) {
                        resources.push({
                            name: bucket.Name, type: 'S3 Bucket', icon: '🪣',
                            region: config.region, severity: 'warning', control: 'CC7.2',
                            issue: 'Lifecycle policy not configured'
                        });
                    }
                }
            } catch (e) { log.warn("S3 fail", e); }

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
                        technicalId: isOpen ? 'SG_OPEN_SSH' : null,
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
                        technicalId: flowLogsEnabled ? null : 'VPC_FLOW_LOGS',
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
                } catch (e) { log.warn("EC2 instances fail", e); }

                // EBS Volumes Check
                try {
                    const { Volumes } = await ec2.send(new DescribeVolumesCommand({}));
                    for (const vol of Volumes || []) {
                        if (!vol.Encrypted) {
                            resources.push({
                                name: vol.VolumeId, type: 'EBS Volume', icon: '💾',
                                region: config.region, severity: 'critical', control: 'CC6.7',
                                issue: 'Volume encryption disabled'
                            });
                        }
                    }
                } catch(e) { log.warn("EBS fail", e); }

                // EBS Snapshots Check
                try {
                    const { Snapshots } = await ec2.send(new DescribeSnapshotsCommand({ OwnerIds: ['self'] }));
                    for (const snap of (Snapshots || []).slice(0, 10)) {
                        const { CreateVolumePermissions } = await ec2.send(new DescribeSnapshotAttributeCommand({
                            Attribute: 'createVolumePermission', SnapshotId: snap.SnapshotId
                        }));
                        if (CreateVolumePermissions && CreateVolumePermissions.some(p => p.Group === 'all')) {
                            resources.push({
                                name: snap.SnapshotId, type: 'EBS Snapshot', icon: '📸',
                                region: config.region, severity: 'critical', control: 'CC6.6',
                                issue: 'Publicly Restorable'
                            });
                        }
                    }
                } catch(e) { log.warn("EBS snapshots fail", e); }
            } catch (e) { log.warn("EC2/VPC fail", e); }

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
            } catch (e) { log.warn("RDS fail", e); }

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
            } catch (e) { log.warn("CloudTrail fail", e); }

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
            } catch (e) { log.warn("KMS fail", e); }

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
            } catch (e) { log.warn("Lambda fail", e); }

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
            } catch (e) { log.warn("WAF fail", e); }

            try {
                const { SubscriptionState } = await shield.send(new GetSubscriptionStateCommand({}));
                const isSubscribed = SubscriptionState === 'SUBSCRIBED' || SubscriptionState === 'ACTIVE';
                resources.push({
                    name: 'Shield Protection', type: 'Shield', icon: '🛡️',
                    region: 'Global',
                    severity: isSubscribed ? 'pass' : 'warning',
                    control: 'CC6.7',
                    issue: isSubscribed ? null : 'Shield Advanced not active'
                });
            } catch (e) { log.warn("Shield fail", e); }

            // ═══════════════════════════════════════════
            // 9. IAM — Deep Scan
            // ═══════════════════════════════════════════
            try {
                const { SummaryMap } = await iam.send(new GetAccountSummaryCommand({}));
                
                // Root Account Security
                if (SummaryMap.AccountMFAEnabled === 0) {
                    resources.push({
                        name: 'Root Account', type: 'IAM Account', icon: '👤',
                        region: 'Global', severity: 'critical', control: 'CC6.3', issue: 'Root MFA disabled'
                    });
                }
                if (SummaryMap.AccountAccessKeysPresent > 0) {
                    resources.push({
                        name: 'Root Account', type: 'IAM Account', icon: '👤',
                        region: 'Global', severity: 'critical', control: 'CC6.1', issue: 'Root access keys present'
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
                            issue: `Weak password policy (length: ${pp.MinimumPasswordLength})`
                        });
                    }
                } catch (e) {
                    resources.push({
                        name: 'Password Policy', type: 'IAM Account', icon: '👤',
                        region: 'Global', severity: 'critical', control: 'CC6.3',
                        issue: 'No account password policy configured'
                    });
                }

                const { Users } = await iam.send(new ListUsersCommand({}));
                let adminCount = 0;

                for (const user of Users || []) {
                    // Check individual MFA
                    const { MFADevices } = await iam.send(new ListMFADevicesCommand({ UserName: user.UserName }));
                    if (MFADevices.length === 0) {
                        resources.push({
                            name: user.UserName, type: 'IAM User', icon: '👤',
                            region: 'Global', severity: 'critical', control: 'CC6.3', issue: 'MFA not enabled for user'
                        });
                    }

                    // Check Unused User (>90 days)
                    const lastUsed = user.PasswordLastUsed ? new Date(user.PasswordLastUsed) : null;
                    const daysUnused = lastUsed ? (new Date() - lastUsed) / (1000 * 60 * 60 * 24) : 999;
                    if (daysUnused > 90) {
                        resources.push({
                            name: user.UserName, type: 'IAM User', icon: '👤',
                            region: 'Global', severity: 'warning', control: 'CC6.2', issue: `Inactive user (>90 days: ${Math.round(daysUnused)}d)`
                        });
                    }

                    // Check Access Key Age & Root-like power
                    const { AccessKeyMetadata } = await iam.send(new ListAccessKeysCommand({ UserName: user.UserName }));
                    for (const key of AccessKeyMetadata || []) {
                        const keyAge = (new Date() - new Date(key.CreateDate)) / (1000 * 60 * 60 * 24);
                        if (keyAge > 90 && key.Status === 'Active') {
                            resources.push({
                                name: `${user.UserName}/${key.AccessKeyId.substring(0, 8)}`, type: 'IAM User', icon: '🔑',
                                region: 'Global', severity: 'warning', control: 'CC6.1', issue: `Access key >90 days old (${Math.round(keyAge)}d)`
                            });
                        }
                    }

                    // Check for Inline Policies (Anti-pattern)
                    const { PolicyNames } = await iam.send(new ListUserPoliciesCommand({ UserName: user.UserName }));
                    if (PolicyNames.length > 0) {
                        resources.push({
                            name: user.UserName, type: 'IAM User', icon: '👤',
                            region: 'Global', severity: 'warning', control: 'CC8.1', issue: 'Direct inline policies attached'
                        });
                    }

                    // Count Admin Sprawl
                    const { AttachedPolicies } = await iam.send(new ListAttachedUserPoliciesCommand({ UserName: user.UserName }));
                    if (AttachedPolicies.some(p => p.PolicyName === 'AdministratorAccess')) adminCount++;
                }

                if (adminCount > 3) {
                    resources.push({
                        name: 'Admin Group', type: 'IAM Group', icon: '👥',
                        region: 'Global', severity: 'warning', control: 'CC6.2', issue: `Admin Sprawl: ${adminCount} users have AdministratorAccess`
                    });
                }

                // Stale IAM Roles
                const { Roles } = await iam.send(new ListRolesCommand({}));
                for (const role of (Roles || []).slice(0, 15)) {
                    const ageDays = (new Date() - new Date(role.CreateDate)) / (1000 * 60 * 60 * 24);
                    if (ageDays > 180) {
                        resources.push({
                            name: role.RoleName, type: 'IAM Role', icon: '🔑',
                            region: 'global', severity: 'warning',
                            control: 'CC6.2', issue: `Stale access role (>180 days: ${Math.round(ageDays)}d)`
                        });
                    }
                    // Check for Inline Policies on Roles
                    const { PolicyNames } = await iam.send(new ListRolePoliciesCommand({ RoleName: role.RoleName }));
                    if (PolicyNames.length > 0) {
                        resources.push({
                            name: role.RoleName, type: 'IAM Role', icon: '🔑',
                            region: 'global', severity: 'warning', control: 'CC8.1', issue: 'Inline policy attached to role'
                        });
                    }
                }
            } catch (e) { log.warn("IAM fail", e); }

            // ═══════════════════════════════════════════
            // 10. Secrets Manager & Networking Cleanup
            // ═══════════════════════════════════════════
            try {
                const { SecretList } = await sm.send(new ListSecretsCommand({}));
                for (const secret of SecretList || []) {
                    if (!secret.RotationEnabled) {
                        resources.push({
                            name: secret.Name, type: 'Secrets Manager', icon: '🔒',
                            region: config.region, severity: 'warning', control: 'CC6.2',
                            issue: 'Rotation disabled'
                        });
                    }
                }
            } catch (e) { log.warn("Secrets Manager fail", e); }

            try {
                // Check for Broad Ports (RDP, HTTP) in Security Groups
                const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({}));
                for (const sg of SecurityGroups || []) {
                    const isRDP = sg.IpPermissions.some(p => 
                        (p.FromPort <= 3389 && p.ToPort >= 3389) && p.IpRanges.some(r => r.CidrIp === '0.0.0.0/0')
                    );
                    const isHTTP = sg.IpPermissions.some(p => 
                        (p.FromPort <= 80 && p.ToPort >= 80) && p.IpRanges.some(r => r.CidrIp === '0.0.0.0/0')
                    );
                    if (isRDP) {
                        resources.push({
                            name: sg.GroupName, type: 'Security Group', icon: '🛡️',
                            region: config.region, severity: 'critical', control: 'CC6.6', issue: 'RDP port (3389) open to world'
                        });
                    }
                    if (isHTTP) {
                        resources.push({
                            name: sg.GroupName, type: 'Security Group', icon: '🛡️',
                            region: config.region, severity: 'warning', control: 'CC6.6', issue: 'Unencrypted HTTP (80) open to world'
                        });
                    }

                    // Check for Unused Security Groups
                    try {
                        const { NetworkInterfaces } = await ec2.send(new DescribeNetworkInterfacesCommand({
                            Filters: [{ Name: 'group-id', Values: [sg.GroupId] }]
                        }));
                        if (NetworkInterfaces.length === 0 && sg.GroupName !== 'default') {
                            resources.push({
                                name: sg.GroupName, type: 'Security Group', icon: '🛡️',
                                region: config.region, severity: 'warning', control: 'CC8.1', issue: 'Unused Security Group'
                            });
                        }
                    } catch (e) { /* skip */ }
                }

                // Check for Unassociated Elastic IPs
                const { Addresses } = await ec2.send(new DescribeAddressesCommand({}));
                const unassociated = (Addresses || []).filter(a => !a.AssociationId);
                for (const addr of unassociated) {
                    resources.push({
                        name: addr.PublicIp, type: 'Elastic IP', icon: '📍',
                        region: config.region, severity: 'warning', control: 'CC8.1', issue: 'Unassociated Elastic IP'
                    });
                }

                // Check for Default VPC usage
                const { Vpcs } = await ec2.send(new DescribeVpcsCommand({}));
                const defaultVpc = Vpcs.find(v => v.IsDefault);
                if (defaultVpc) {
                    resources.push({
                        name: defaultVpc.VpcId, type: 'VPC', icon: '🌐',
                        region: config.region, severity: 'warning', control: 'CC6.6', issue: 'Default VPC in use (Compliance Risk)'
                    });
                }
            } catch (e) { log.warn("Net cleanup fail", e); }

            // ═══════════════════════════════════════════
            // 11. Monitoring & Threat Detection
            // ═══════════════════════════════════════════
            try {
                // GuardDuty Focus
                const { DetectorIds } = await guardduty.send(new ListDetectorsCommand({}));
                if (!DetectorIds || DetectorIds.length === 0) {
                    resources.push({
                        name: 'GuardDuty', type: 'Threat Detection', icon: '🚨',
                        region: config.region, severity: 'critical', control: 'CC6.6', issue: 'GuardDuty disabled'
                    });
                } else {
                    resources.push({
                        name: 'GuardDuty', type: 'Threat Detection', icon: '🚨',
                        region: config.region, severity: 'pass', control: 'CC6.6', issue: null
                    });
                }
            } catch(e) { log.warn("GuardDuty fail", e); }

            try {
                // AWS Config Focus
                const { ConfigurationRecorders } = await configService.send(new DescribeConfigurationRecordersCommand({}));
                if (!ConfigurationRecorders || ConfigurationRecorders.length === 0) {
                    resources.push({
                        name: 'AWS Config', type: 'Configuration', icon: '⚙️',
                        region: config.region, severity: 'warning', control: 'CC7.1', issue: 'AWS Config disabled'
                    });
                } else {
                    resources.push({
                        name: 'AWS Config', type: 'Configuration', icon: '⚙️',
                        region: config.region, severity: 'pass', control: 'CC7.1', issue: null
                    });
                }
            } catch(e) { log.warn("AWS Config fail", e); }

            try {
                // CloudWatch Logs Retention Check
                const { logGroups } = await cwLogs.send(new DescribeLogGroupsCommand({ limit: 20 }));
                for (const lg of logGroups || []) {
                    if (lg.retentionInDays && lg.retentionInDays < 365) {
                        resources.push({
                            name: lg.logGroupName, type: 'Log Group', icon: '📜',
                            region: config.region, severity: 'warning', control: 'CC7.2', issue: `Log retention < 365 days (currently ${lg.retentionInDays}d)`
                        });
                    }
                }
            } catch(e) { log.warn("CW Logs fail", e); }

            try {
                // CloudWatch Alarms for Root/IAM/CloudTrail
                const { MetricAlarms } = await cloudwatch.send(new DescribeAlarmsCommand({}));
                const alarmNames = (MetricAlarms || []).map(a => a.AlarmName.toLowerCase());
                
                const hasRootAlarm = alarmNames.some(n => n.includes('root'));
                const hasIAMAlarm = alarmNames.some(n => n.includes('iam') || n.includes('policy'));
                const hasTrailAlarm = alarmNames.some(n => n.includes('cloudtrail') || n.includes('trail'));

                if (!hasRootAlarm) {
                    resources.push({ name: 'Root Login Alarm', type: 'CloudWatch Alarms', icon: '🔔', region: 'Global', severity: 'critical', control: 'CC6.1', issue: 'No CloudWatch alarm for root user login' });
                }
                if (!hasIAMAlarm) {
                    resources.push({ name: 'IAM Change Alarm', type: 'CloudWatch Alarms', icon: '🔔', region: 'Global', severity: 'warning', control: 'CC6.1', issue: 'No CloudWatch alarm for IAM policy changes' });
                }
                if (!hasTrailAlarm) {
                    resources.push({ name: 'CloudTrail Change Alarm', type: 'CloudWatch Alarms', icon: '🔔', region: 'Global', severity: 'warning', control: 'CC7.2', issue: 'No CloudWatch alarm for CloudTrail configuration changes' });
                }
            } catch(e) { log.warn("CW Alarms fail", e); }

            // ═══════════════════════════════════════════
            // 12. Database & Compute Advanced (DynamoDB, Redshift, EKS)
            // ═══════════════════════════════════════════
            const checkDataCompute = async () => {
                // DynamoDB
                try {
                    const { TableNames } = await dynamodb.send(new ListTablesCommand({}));
                    for (const table of TableNames || []) {
                        const { Table } = await dynamodb.send(new DescribeTableCommand({ TableName: table }));
                        const pDesc = await dynamodb.send(new DescribeContinuousBackupsCommand({ TableName: table })).catch(()=>({}));
                        const pitr = pDesc?.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus === 'ENABLED';

                        if (!pitr) {
                            resources.push({ name: table, type: 'DynamoDB Table', icon: '🗄️', region: config.region, severity: 'critical', control: 'CC7.2', issue: 'PITR (Continuous Backups) disabled' });
                        }
                        if (Table.SSEDescription?.Status !== 'ENABLED') {
                            resources.push({ name: table, type: 'DynamoDB Table', icon: '🗄️', region: config.region, severity: 'warning', control: 'CC6.7', issue: 'KMS Encryption disabled (using AWS owned)' });
                        }
                    }
                } catch(e) { log.warn("DDB fail", e); }

                // Redshift
                try {
                    const { Clusters } = await redshift.send(new DescribeClustersCommand({}));
                    for (const cluster of Clusters || []) {
                        if (!cluster.Encrypted) {
                            resources.push({ name: cluster.ClusterIdentifier, type: 'Redshift Cluster', icon: '📊', region: config.region, severity: 'critical', control: 'CC6.7', issue: 'Cluster encryption disabled' });
                        }
                        if (cluster.AutomatedSnapshotRetentionPeriod < 7) {
                            resources.push({ name: cluster.ClusterIdentifier, type: 'Redshift Cluster', icon: '📊', region: config.region, severity: 'warning', control: 'CC7.2', issue: `Automated snapshots < 7 days (${cluster.AutomatedSnapshotRetentionPeriod}d)` });
                        }
                        if (cluster.PubliclyAccessible) {
                            resources.push({ name: cluster.ClusterIdentifier, type: 'Redshift Cluster', icon: '📊', region: config.region, severity: 'critical', control: 'CC6.6', issue: 'Publicly Accessible' });
                        }
                    }
                } catch(e) { log.warn("Redshift fail", e); }

                // EKS
                try {
                    const { clusters } = await eks.send(new ListClustersCommand({}));
                    for (const c of clusters || []) {
                        const { cluster } = await eks.send(new DescribeClusterCommand({ name: c }));
                        
                        const logTypes = cluster.logging?.clusterLogging?.[0]?.types || [];
                        const hasAuditLog = logTypes.includes('audit') && logTypes.includes('api');
                        if (!hasAuditLog) {
                            resources.push({ name: c, type: 'EKS Cluster', icon: '☸️', region: config.region, severity: 'warning', control: 'CC7.2', issue: 'Control Plane Logging (Audit/API) incomplete or disabled' });
                        }

                        if (cluster.resourcesVpcConfig?.endpointPublicAccess) {
                            resources.push({ name: c, type: 'EKS Cluster', icon: '☸️', region: config.region, severity: 'critical', control: 'CC6.6', issue: 'Cluster Endpoint publicly accessible' });
                        }

                        if (!cluster.encryptionConfig || cluster.encryptionConfig.length === 0) {
                            resources.push({ name: c, type: 'EKS Cluster', icon: '☸️', region: config.region, severity: 'critical', control: 'CC6.7', issue: 'Secrets encryption disabled' });
                        }
                    }
                } catch(e) { log.warn("EKS fail", e); }
            };

            // ═══════════════════════════════════════════
            // 13. Application & Edge Advanced (API GW, CloudFront, SQS, SNS)
            // ═══════════════════════════════════════════
            const checkAppEdge = async () => {
                // API Gateway
                try {
                    const { items } = await apigw.send(new GetRestApisCommand({}));
                    for (const api of items || []) {
                        if (!api.disableExecuteApiEndpoint) {
                            resources.push({ name: api.name, type: 'API Gateway', icon: '🚪', region: config.region, severity: 'warning', control: 'CC6.6', issue: 'Default execute-api endpoint enabled' });
                        }
                        try {
                            const { item: stages } = await apigw.send(new GetStagesCommand({ restApiId: api.id }));
                            for (const stage of stages || []) {
                                if (!stage.webAclArn) {
                                    resources.push({ name: `${api.name}/${stage.stageName}`, type: 'API Gateway Stage', icon: '🚪', region: config.region, severity: 'warning', control: 'CC6.6', issue: 'No WAF WebACL associated' });
                                }
                                if (!stage.tracingEnabled) {
                                    resources.push({ name: `${api.name}/${stage.stageName}`, type: 'API Gateway Stage', icon: '🚪', region: config.region, severity: 'warning', control: 'CC7.2', issue: 'X-Ray Tracing disabled' });
                                }
                            }
                        } catch(e) {}
                    }
                } catch(e) { log.warn("APIGW fail", e); }

                // CloudFront
                try {
                    const { DistributionList } = await cloudfront.send(new ListDistributionsCommand({}));
                    for (const dist of DistributionList?.Items || []) {
                        if (!dist.WebACLId) {
                            resources.push({ name: dist.Id, type: 'CloudFront Distribution', icon: '🌍', region: 'Global', severity: 'warning', control: 'CC6.6', issue: 'No WAF Integration' });
                        }
                        if (!dist.DefaultRootObject) {
                            resources.push({ name: dist.Id, type: 'CloudFront Distribution', icon: '🌍', region: 'Global', severity: 'warning', control: 'CC6.1', issue: 'No Default Root Object configured' });
                        }
                        if (dist.DefaultCacheBehavior?.ViewerProtocolPolicy === 'allow-all') {
                            resources.push({ name: dist.Id, type: 'CloudFront Distribution', icon: '🌍', region: 'Global', severity: 'critical', control: 'CC6.7', issue: 'HTTP traffic allowed (Viewer Protocol Policy)' });
                        }
                    }
                } catch(e) { log.warn("CloudFront fail", e); }

                // SQS
                try {
                    const { QueueUrls } = await sqs.send(new ListQueuesCommand({}));
                    for (const url of QueueUrls || []) {
                        const qName = url.split('/').pop();
                        const { Attributes } = await sqs.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ['All'] }));
                        if (!Attributes.KmsMasterKeyId && Attributes.SqsManagedSseEnabled !== 'true') {
                            resources.push({ name: qName, type: 'SQS Queue', icon: '📨', region: config.region, severity: 'warning', control: 'CC6.7', issue: 'Server-Side Encryption disabled' });
                        }
                        if (!Attributes.RedrivePolicy) {
                            resources.push({ name: qName, type: 'SQS Queue', icon: '📨', region: config.region, severity: 'warning', control: 'CC7.2', issue: 'No Dead Letter Queue (DLQ) configured' });
                        }
                    }
                } catch(e) { log.warn("SQS fail", e); }

                // SNS
                try {
                    const { Topics } = await sns.send(new ListTopicsCommand({}));
                    for (const t of Topics || []) {
                        const tName = t.TopicArn.split(':').pop();
                        const { Attributes } = await sns.send(new GetTopicAttributesCommand({ TopicArn: t.TopicArn }));
                        if (!Attributes.KmsMasterKeyId) {
                            resources.push({ name: tName, type: 'SNS Topic', icon: '📟', region: config.region, severity: 'warning', control: 'CC6.7', issue: 'Server-Side Encryption disabled' });
                        }
                    }
                } catch(e) { log.warn("SNS fail", e); }
            };

            await Promise.allSettled([checkDataCompute(), checkAppEdge()]);
        }

        return { resources };
    } catch (error) {
        log.error('Scan Error:', error);
        throw error;
    }
}
