import { S3Client, PutPublicAccessBlockCommand, PutBucketVersioningCommand, PutBucketEncryptionCommand } from "@aws-sdk/client-s3";
import { EC2Client, RevokeSecurityGroupIngressCommand, AuthorizeSecurityGroupIngressCommand, DescribeSecurityGroupsCommand, CreateFlowLogsCommand, ReleaseAddressCommand, DeleteSecurityGroupCommand, ModifyInstanceMetadataOptionsCommand } from "@aws-sdk/client-ec2";
import { IAMClient, UpdateAssumeRolePolicyCommand, GetRoleCommand, UpdateAccessKeyCommand } from "@aws-sdk/client-iam";
import { RDSClient, ModifyDBInstanceCommand } from "@aws-sdk/client-rds";
import { KMSClient, EnableKeyRotationCommand } from "@aws-sdk/client-kms";
import { LambdaClient, UpdateFunctionConfigurationCommand } from "@aws-sdk/client-lambda";
import { CloudTrailClient, UpdateTrailCommand, CreateTrailCommand, StartLoggingCommand } from "@aws-sdk/client-cloudtrail";
import { SecretsManagerClient, RotateSecretCommand } from "@aws-sdk/client-secrets-manager";
import { ConfigServiceClient } from "@aws-sdk/client-config-service";
import { GuardDutyClient, CreateDetectorCommand } from "@aws-sdk/client-guardduty";
import { CloudWatchLogsClient, PutRetentionPolicyCommand } from "@aws-sdk/client-cloudwatch-logs";
import { CloudWatchClient } from "@aws-sdk/client-cloudwatch";

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { credentials, provider, resourceType, resourceName, issue } = req.body;

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

        let result = { success: true, message: `Successfully remediated ${resourceName}` };

        if (provider === 'aws') {


            // ── S3 Bucket Remediations ──
            if (resourceType === 'S3 Bucket') {
                const s3 = new S3Client(config);

                if (issue.includes('Public access')) {
                    await s3.send(new PutPublicAccessBlockCommand({
                        Bucket: resourceName,
                        PublicAccessBlockConfiguration: {
                            BlockPublicAcls: true,
                            IgnorePublicAcls: true,
                            BlockPublicPolicy: true,
                            RestrictPublicBuckets: true
                        }
                    }));
                } else if (issue.includes('Versioning')) {
                    await s3.send(new PutBucketVersioningCommand({
                        Bucket: resourceName,
                        VersioningConfiguration: { Status: 'Enabled' }
                    }));
                } else if (issue.includes('Default encryption disabled')) {
                    await s3.send(new PutBucketEncryptionCommand({
                        Bucket: resourceName,
                        ServerSideEncryptionConfiguration: {
                            Rules: [{
                                ApplyServerSideEncryptionByDefault: {
                                    SSEAlgorithm: 'aws:kms'
                                },
                                BucketKeyEnabled: true
                            }]
                        }
                    }));
                }
            }

            // ── Security Group Remediations ──
            else if (resourceType === 'Security Group') {
                const ec2 = new EC2Client(config);

                if (issue.includes('port 22')) {
                    const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({ GroupNames: [resourceName] }));
                    const sg = SecurityGroups?.[0];
                    if (sg) {
                        const openRules = sg.IpPermissions.filter(p => (p.FromPort <= 22 && p.ToPort >= 22) && p.IpRanges.some(r => r.CidrIp === '0.0.0.0/0'));
                        for (const rule of openRules) {
                            await ec2.send(new RevokeSecurityGroupIngressCommand({
                                GroupId: sg.GroupId,
                                IpPermissions: [{ IpProtocol: rule.IpProtocol, FromPort: rule.FromPort, ToPort: rule.ToPort, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }]
                            }));
                        }
                        await ec2.send(new AuthorizeSecurityGroupIngressCommand({
                            GroupId: sg.GroupId,
                            IpPermissions: [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '10.0.0.0/16', Description: 'SSH restricted to VPC CIDR (ComplianceFlow)' }] }]
                        }));
                    }
                } else if (issue.includes('RDP') || issue.includes('3389')) {
                    const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({ GroupNames: [resourceName] }));
                    const sg = SecurityGroups?.[0];
                    if (sg) {
                        const rdpRules = sg.IpPermissions.filter(p => (p.FromPort <= 3389 && p.ToPort >= 3389) && p.IpRanges.some(r => r.CidrIp === '0.0.0.0/0'));
                        for (const rule of rdpRules) {
                            await ec2.send(new RevokeSecurityGroupIngressCommand({
                                GroupId: sg.GroupId,
                                IpPermissions: [{ IpProtocol: rule.IpProtocol, FromPort: rule.FromPort, ToPort: rule.ToPort, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }]
                            }));
                        }
                    }
                } else if (issue.includes('HTTP') || issue.includes('port 80')) {
                    const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({ GroupNames: [resourceName] }));
                    const sg = SecurityGroups?.[0];
                    if (sg) {
                        const httpRules = sg.IpPermissions.filter(p => (p.FromPort <= 80 && p.ToPort >= 80) && p.IpRanges.some(r => r.CidrIp === '0.0.0.0/0'));
                        for (const rule of httpRules) {
                            await ec2.send(new RevokeSecurityGroupIngressCommand({
                                GroupId: sg.GroupId,
                                IpPermissions: [{ IpProtocol: rule.IpProtocol, FromPort: rule.FromPort, ToPort: rule.ToPort, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }]
                            }));
                        }
                    }
                } else if (issue.includes('Unused Security Group')) {
                    const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({ GroupNames: [resourceName] }));
                    if (SecurityGroups?.[0]) {
                        await ec2.send(new DeleteSecurityGroupCommand({ GroupId: SecurityGroups[0].GroupId }));
                        result.message = `Deleted unused Security Group: ${resourceName}`;
                    }
                }
            }

            // ── IAM Remediations ──
            else if (resourceType === 'IAM Account') {
                if (issue.includes('Root access keys')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: Root access keys detected. PLEASE DELETE MANUALLY via IAM > Security credentials.`
                    };
                } else {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: Root MFA must be enabled manually via the AWS Console.`
                    };
                }
            }
            else if (resourceType === 'IAM User') {
                if (issue.includes('MFA not enabled')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: User "${resourceName}" must enable MFA.`
                    };
                } else if (issue.includes('Inactive user')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: User "${resourceName}" is inactive (>90 days). Consider deactivating or deleting.`
                    };
                } else if (issue.includes('inline policies')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: User "${resourceName}" has direct inline policies. Refactor into Managed Policies.`
                    };
                } else if (issue.includes('Access key') && issue.includes('90 days')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: Access key for "${resourceName}" is >90 days old. Rotate manually.`
                    };
                }
            }
            else if (resourceType === 'IAM Group') {
                if (issue.includes('Admin Sprawl')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: Multiple users have AdministratorAccess. Review and apply Principle of Least Privilege.`
                    };
                }
            }
            else if (resourceType === 'IAM Role') {
                const iam = new IAMClient(config);
                if (issue.includes('Stale Access') || issue.includes('180 days')) {
                    const denyPolicy = {
                        Version: "2012-10-17",
                        Statement: [{
                            Effect: "Deny", Principal: "*", Action: "sts:AssumeRole",
                            Condition: { StringEquals: { "aws:PrincipalTag/ComplianceFlow": "deactivated" } }
                        }]
                    };
                    await iam.send(new UpdateAssumeRolePolicyCommand({
                        RoleName: resourceName,
                        PolicyDocument: JSON.stringify(denyPolicy)
                    }));
                }
            }

            // ── RDS Database Remediations ──
            else if (resourceType === 'RDS Database') {
                const rds = new RDSClient(config);
                if (issue.includes('Encryption at rest')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: RDS encryption cannot be enabled in-place. Create an encrypted snapshot, then restore.`
                    };
                } else if (issue.includes('Backup retention')) {
                    await rds.send(new ModifyDBInstanceCommand({
                        DBInstanceIdentifier: resourceName,
                        BackupRetentionPeriod: 14,
                        ApplyImmediately: true
                    }));
                } else if (issue.includes('Multi-AZ')) {
                    await rds.send(new ModifyDBInstanceCommand({
                        DBInstanceIdentifier: resourceName,
                        MultiAZ: true,
                        ApplyImmediately: false
                    }));
                    result.message = `Multi-AZ enabled for "${resourceName}". applies next maintenance window.`;
                } else if (issue.includes('Publicly accessible')) {
                    await rds.send(new ModifyDBInstanceCommand({
                        DBInstanceIdentifier: resourceName,
                        PubliclyAccessible: false,
                        ApplyImmediately: true
                    }));
                }
            }

            // ── KMS Key Remediations ──
            else if (resourceType === 'KMS Key') {
                const kms = new KMSClient(config);
                if (issue.includes('Rotation disabled')) {
                    await kms.send(new EnableKeyRotationCommand({ KeyId: resourceName }));
                }
            }

            // ── Lambda Remediations ──
            else if (resourceType === 'Lambda') {
                const lambda = new LambdaClient(config);
                if (issue.includes('runtime')) {
                    await lambda.send(new UpdateFunctionConfigurationCommand({
                        FunctionName: resourceName,
                        Runtime: 'nodejs20.x'
                    }));
                }
            }

            // ── CloudTrail Remediations ──
            else if (resourceType === 'CloudTrail') {
                const cloudtrail = new CloudTrailClient(config);
                if (issue.includes('Log Validation disabled')) {
                    await cloudtrail.send(new UpdateTrailCommand({
                        Name: resourceName,
                        EnableLogFileValidation: true
                    }));
                } else if (issue.includes('Not multi-region')) {
                    await cloudtrail.send(new UpdateTrailCommand({
                        Name: resourceName,
                        IsMultiRegionTrail: true
                    }));
                }
            }

            // ── VPC & Networking Remediations ──
            else if (resourceType === 'VPC') {
                const ec2 = new EC2Client(config);
                if (issue.includes('Flow Logs disabled')) {
                    try {
                        await ec2.send(new CreateFlowLogsCommand({
                            ResourceIds: [resourceName],
                            ResourceType: 'VPC',
                            TrafficType: 'ALL',
                            LogDestinationType: 'cloud-watch-logs',
                            LogGroupName: `/complianceflow/vpc-flow-logs/${resourceName}`,
                            DeliverLogsPermissionArn: `arn:aws:iam::role/ComplianceFlowVPCFlowLogRole`
                        }));
                    } catch (e) {
                        result = {
                            success: true,
                            advisory: true,
                            message: `ADVISORY: VPC Flow Logs require an IAM role "ComplianceFlowVPCFlowLogRole".`
                        };
                    }
                }
            }
            else if (resourceType === 'Elastic IP') {
                const ec2 = new EC2Client(config);
                if (issue.includes('Unassociated')) {
                    await ec2.send(new ReleaseAddressCommand({ PublicIp: resourceName }));
                    result.message = `Released unassociated Elastic IP: ${resourceName}`;
                }
            }

            // ── Secrets Manager Remediations ──
            else if (resourceType === 'Secrets Manager') {
                result = {
                    success: true,
                    advisory: true,
                    message: `ADVISORY: Secret "${resourceName}" rotation requires Lambda configuration.`
                };
            }

            // ── EC2 Instance Remediations ──
            else if (resourceType === 'EC2 Instance') {
                if (issue.includes('IMDSv2')) {
                    const ec2 = new EC2Client(config);
                    await ec2.send(new ModifyInstanceMetadataOptionsCommand({
                        InstanceId: resourceName,
                        HttpTokens: 'required',
                        HttpEndpoint: 'enabled'
                    }));
                }
            }

            // ── Monitoring & Threat Detection Remediations ──
            else if (resourceType === 'Threat Detection') {
                const guardduty = new GuardDutyClient(config);
                if (issue.includes('disabled')) {
                    await guardduty.send(new CreateDetectorCommand({ Enable: true }));
                    result.message = `Enabled GuardDuty threat detection.`;
                }
            }
            else if (resourceType === 'Configuration') {
                if (issue.includes('disabled')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: AWS Config requires an IAM Role and an S3 bucket for configuration history. Configure via AWS Console > AWS Config.`
                    };
                }
            }
            else if (resourceType === 'Log Group') {
                const cwLogs = new CloudWatchLogsClient(config);
                if (issue.includes('retention') || issue.includes('< 365')) {
                    await cwLogs.send(new PutRetentionPolicyCommand({
                        logGroupName: resourceName,
                        retentionInDays: 365
                    }));
                    result.message = `Set log retention to 365 days for ${resourceName}.`;
                }
            }
            else if (resourceType === 'CloudWatch Alarms') {
                result = {
                    success: true,
                    advisory: true,
                    message: `ADVISORY: CloudWatch Alarms for SOC2 require metric filters on CloudTrail log groups. Set this manually via AWS Console.`
                };
            }

            // ── Macie / WAF / Shield — Advisory only ──
            else if (resourceType === 'Macie') {
                result = { success: true, advisory: true, message: `ADVISORY: Enable Amazon Macie via the AWS Console.` };
            }
            else if (resourceType === 'WAF') {
                result = { success: true, advisory: true, message: `ADVISORY: Create a WebACL via AWS Console > WAF & Shield.` };
            }
            else if (resourceType === 'Shield') {
                result = { success: true, advisory: true, message: `ADVISORY: AWS Shield Advanced requires a subscription.` };
            }

            // ── Fallback ──
            else {
                result = { success: true, advisory: true, message: `No automated remediation available for ${resourceType}. Manual intervention required.` };
            }
        }

        res.status(200).json(result);
    } catch (error) {
        console.error('Remediation Error:', error);
        res.status(500).json({ error: error.message });
    }
}
