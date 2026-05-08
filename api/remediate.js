import { S3Client, PutPublicAccessBlockCommand, PutBucketVersioningCommand, PutBucketEncryptionCommand } from "@aws-sdk/client-s3";
import { EC2Client, RevokeSecurityGroupIngressCommand, AuthorizeSecurityGroupIngressCommand, DescribeSecurityGroupsCommand, CreateFlowLogsCommand } from "@aws-sdk/client-ec2";
import { IAMClient, UpdateAssumeRolePolicyCommand, GetRoleCommand } from "@aws-sdk/client-iam";
import { RDSClient, ModifyDBInstanceCommand } from "@aws-sdk/client-rds";
import { KMSClient, EnableKeyRotationCommand } from "@aws-sdk/client-kms";
import { LambdaClient, UpdateFunctionConfigurationCommand } from "@aws-sdk/client-lambda";
import { CloudTrailClient, UpdateTrailCommand, CreateTrailCommand, StartLoggingCommand } from "@aws-sdk/client-cloudtrail";
import { SecretsManagerClient, RotateSecretCommand } from "@aws-sdk/client-secrets-manager";

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

                if (issue.includes('0.0.0.0/0')) {
                    // First, find the offending ingress rule
                    const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({
                        GroupNames: [resourceName]
                    }));
                    const sg = SecurityGroups?.[0];
                    if (sg) {
                        // Revoke the open SSH rule
                        const openRules = sg.IpPermissions.filter(p =>
                            (p.FromPort <= 22 && p.ToPort >= 22) &&
                            p.IpRanges.some(r => r.CidrIp === '0.0.0.0/0')
                        );
                        for (const rule of openRules) {
                            await ec2.send(new RevokeSecurityGroupIngressCommand({
                                GroupId: sg.GroupId,
                                IpPermissions: [{
                                    IpProtocol: rule.IpProtocol,
                                    FromPort: rule.FromPort,
                                    ToPort: rule.ToPort,
                                    IpRanges: [{ CidrIp: '0.0.0.0/0' }]
                                }]
                            }));
                        }
                        // Re-authorize restricted to VPC default CIDR
                        await ec2.send(new AuthorizeSecurityGroupIngressCommand({
                            GroupId: sg.GroupId,
                            IpPermissions: [{
                                IpProtocol: 'tcp',
                                FromPort: 22,
                                ToPort: 22,
                                IpRanges: [{ CidrIp: '10.0.0.0/16', Description: 'SSH restricted to VPC CIDR (ComplianceFlow)' }]
                            }]
                        }));
                    }
                }
            }

            // ── IAM Remediations ──
            else if (resourceType === 'IAM Account') {
                // Root MFA cannot be enabled programmatically
                result = {
                    success: true,
                    advisory: true,
                    message: `ADVISORY: Root MFA must be enabled manually via the AWS Console. Navigate to IAM > Security credentials > Assign MFA device.`
                };
            }
            else if (resourceType === 'IAM Role') {
                const iam = new IAMClient(config);

                if (issue.includes('Stale Access') || issue.includes('180 days')) {
                    // Deny all assume-role by updating the trust policy
                    const { Role } = await iam.send(new GetRoleCommand({ RoleName: resourceName }));
                    const denyPolicy = {
                        Version: "2012-10-17",
                        Statement: [{
                            Effect: "Deny",
                            Principal: "*",
                            Action: "sts:AssumeRole",
                            Condition: {
                                StringEquals: {
                                    "aws:PrincipalTag/ComplianceFlow": "deactivated"
                                }
                            }
                        }]
                    };
                    await iam.send(new UpdateAssumeRolePolicyCommand({
                        RoleName: resourceName,
                        PolicyDocument: JSON.stringify(denyPolicy)
                    }));
                } else if (issue.includes('Access key') && issue.includes('90 days')) {
                    // Access key rotation is advisory — can't auto-rotate without breaking apps
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: Access key for "${resourceName}" is >90 days old. Rotate manually via IAM > Users > Security credentials to avoid service disruption.`
                    };
                }
            }

            // ── RDS Database Remediations ──
            else if (resourceType === 'RDS Database') {
                const rds = new RDSClient(config);

                if (issue.includes('Encryption at rest')) {
                    // RDS encryption cannot be enabled in-place
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: RDS encryption cannot be enabled in-place. Create an encrypted snapshot of "${resourceName}", then restore from it. See: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html`
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
                        ApplyImmediately: false // Requires maintenance window
                    }));
                    result.message = `Multi-AZ enabled for "${resourceName}". Change will apply during the next maintenance window.`;
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

                if (issue.includes('Deprecated runtime') || issue.includes('runtime')) {
                    // Map deprecated runtimes to current equivalents
                    const runtimeUpgrades = {
                        'nodejs12.x': 'nodejs20.x',
                        'nodejs14.x': 'nodejs20.x',
                        'nodejs16.x': 'nodejs20.x',
                        'python3.7': 'python3.12',
                        'python3.8': 'python3.12',
                    };
                    // Extract current runtime from issue text
                    const runtimeMatch = issue.match(/\(([^)]+)\)/);
                    const currentRuntime = runtimeMatch ? runtimeMatch[1] : null;
                    const newRuntime = currentRuntime ? (runtimeUpgrades[currentRuntime] || 'nodejs20.x') : 'nodejs20.x';

                    await lambda.send(new UpdateFunctionConfigurationCommand({
                        FunctionName: resourceName,
                        Runtime: newRuntime
                    }));
                    result.message = `Lambda "${resourceName}" runtime upgraded to ${newRuntime}.`;
                } else if (issue.includes('Not VPC-attached')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: Lambda "${resourceName}" is not VPC-attached. Configure VPC settings manually with appropriate subnets and security groups.`
                    };
                }
            }

            // ── CloudTrail Remediations ──
            else if (resourceType === 'CloudTrail') {
                const cloudtrail = new CloudTrailClient(config);

                if (issue.includes('No trail enabled')) {
                    // Create a new multi-region trail
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: Creating a CloudTrail requires an S3 bucket with the correct bucket policy. Create a trail named "complianceflow-audit" via the AWS Console or CLI with an existing log bucket.`
                    };
                } else if (issue.includes('Log Validation disabled')) {
                    await cloudtrail.send(new UpdateTrailCommand({
                        Name: resourceName,
                        EnableLogFileValidation: true
                    }));
                } else if (issue.includes('Not multi-region')) {
                    await cloudtrail.send(new UpdateTrailCommand({
                        Name: resourceName,
                        IsMultiRegionTrail: true
                    }));
                } else if (issue.includes('Log encryption disabled')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: CloudTrail log encryption requires a KMS key with the correct key policy. Configure via: aws cloudtrail update-trail --name ${resourceName} --kms-key-id <KMS_KEY_ARN>`
                    };
                }
            }

            // ── VPC Remediations ──
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
                    } catch (flowErr) {
                        // Flow logs require an IAM role — fallback to advisory
                        result = {
                            success: true,
                            advisory: true,
                            message: `ADVISORY: VPC Flow Logs require an IAM role with logs:CreateLogGroup and logs:PutLogEvents permissions. Create the role "ComplianceFlowVPCFlowLogRole" first, then re-run remediation.`
                        };
                    }
                }
            }

            // ── Secrets Manager Remediations ──
            else if (resourceType === 'Secrets Manager') {
                const sm = new SecretsManagerClient(config);

                if (issue.includes('Rotation disabled') || issue.includes('rotation')) {
                    result = {
                        success: true,
                        advisory: true,
                        message: `ADVISORY: Secret "${resourceName}" requires a Lambda rotation function. Configure rotation via: aws secretsmanager rotate-secret --secret-id ${resourceName} --rotation-lambda-arn <LAMBDA_ARN>`
                    };
                }
            }

            // ── Macie / WAF / Shield — Advisory only ──
            else if (resourceType === 'Macie') {
                result = {
                    success: true,
                    advisory: true,
                    message: `ADVISORY: Enable Amazon Macie via the AWS Console > Macie > Get Started. Macie requires explicit activation per account.`
                };
            }
            else if (resourceType === 'WAF') {
                result = {
                    success: true,
                    advisory: true,
                    message: `ADVISORY: No WAF WebACLs found. Create a WebACL via AWS Console > WAF & Shield > Web ACLs to protect your endpoints.`
                };
            }
            else if (resourceType === 'Shield') {
                result = {
                    success: true,
                    advisory: true,
                    message: `ADVISORY: AWS Shield Advanced requires a subscription ($3,000/mo). Enable via AWS Console > Shield > Subscribe to Advanced.`
                };
            }

            // ── EC2 Instance Remediations ──
            else if (resourceType === 'EC2 Instance') {
                if (issue.includes('IMDSv2')) {
                    const ec2 = new EC2Client(config);
                    const { ModifyInstanceMetadataOptionsCommand } = await import("@aws-sdk/client-ec2");
                    await ec2.send(new ModifyInstanceMetadataOptionsCommand({
                        InstanceId: resourceName,
                        HttpTokens: 'required',
                        HttpEndpoint: 'enabled'
                    }));
                }
            }

            // ── Fallback for unknown types ──
            else {
                result = {
                    success: true,
                    advisory: true,
                    message: `No automated remediation available for ${resourceType}. Manual intervention required.`
                };
            }
        }

        res.status(200).json(result);
    } catch (error) {
        console.error('Remediation Error:', error);
        res.status(500).json({ error: error.message });
    }
}
