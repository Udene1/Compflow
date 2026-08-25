import { 
    S3Client, 
    PutPublicAccessBlockCommand, 
    PutBucketVersioningCommand, 
    PutBucketEncryptionCommand, 
    PutBucketLifecycleConfigurationCommand 
} from "@aws-sdk/client-s3";
import { 
    EC2Client, 
    RevokeSecurityGroupIngressCommand, 
    AuthorizeSecurityGroupIngressCommand, 
    DescribeSecurityGroupsCommand, 
    CreateFlowLogsCommand, 
    ReleaseAddressCommand, 
    DeleteSecurityGroupCommand, 
    ModifyInstanceMetadataOptionsCommand, 
    ModifySnapshotAttributeCommand 
} from "@aws-sdk/client-ec2";
import { 
    IAMClient, 
    UpdateAssumeRolePolicyCommand, 
    GetRoleCommand, 
    UpdateAccessKeyCommand 
} from "@aws-sdk/client-iam";
import { 
    RDSClient, 
    ModifyDBInstanceCommand, 
    DescribeDBInstancesCommand 
} from "@aws-sdk/client-rds";
import { 
    KMSClient, 
    EnableKeyRotationCommand, 
    GetKeyRotationStatusCommand 
} from "@aws-sdk/client-kms";
import { 
    ConfigServiceClient 
} from "@aws-sdk/client-config-service";
import { 
    GuardDutyClient, 
    CreateDetectorCommand 
} from "@aws-sdk/client-guardduty";
import { 
    CloudWatchLogsClient, 
    PutRetentionPolicyCommand 
} from "@aws-sdk/client-cloudwatch-logs";
import { 
    CloudWatchClient 
} from "@aws-sdk/client-cloudwatch";
import { 
    DynamoDBClient, 
    UpdateContinuousBackupsCommand 
} from "@aws-sdk/client-dynamodb";
import { 
    APIGatewayClient, 
    UpdateRestApiCommand, 
    UpdateStageCommand 
} from "@aws-sdk/client-api-gateway";
import { 
    CloudFrontClient, 
    UpdateDistributionCommand, 
    GetDistributionConfigCommand 
} from "@aws-sdk/client-cloudfront";
import { 
    SQSClient, 
    SetQueueAttributesCommand 
} from "@aws-sdk/client-sqs";
import { 
    SNSClient, 
    SetTopicAttributesCommand 
} from "@aws-sdk/client-sns";
import { 
    LambdaClient, 
    UpdateFunctionConfigurationCommand 
} from "@aws-sdk/client-lambda";
import { 
    CloudTrailClient, 
    UpdateTrailCommand 
} from "@aws-sdk/client-cloudtrail";
import { log } from '../logger.js';
import { FINDING_CODES, resolveFindingCode } from '../finding_codes.js';

/**
 * AWS Comprehensive Auto-Remediation & Governance Engine
 * 
 * Supports 20+ AWS resource types with deterministic finding codes,
 * blast-radius protection, parameterized network CIDRs, and pre-flight state checks.
 */
export async function runRemediation(provider, credentials, resourceType, resourceName, issue, dryRun = false, options = {}) {

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
        return { success: false, error: 'Missing AWS credentials for remediation.' };
    }

    // Resolve canonical finding code
    const findingCode = options.findingCode || resolveFindingCode(resourceType, issue);
    const safeCidr = options.allowedCidr || options.safeCidr || null;

    try {
        // ── BLAST RADIUS CONTROL: Auto-Fix Whitelist vs Advisory Escalation ──
        const SAFE_AUTO_FIX_CODES = new Set([
            FINDING_CODES.S3_PUBLIC_ACCESS,
            FINDING_CODES.S3_VERSIONING_DISABLED,
            FINDING_CODES.S3_ENCRYPTION_DISABLED,
            FINDING_CODES.S3_LIFECYCLE_MISSING,
            FINDING_CODES.SG_OPEN_SSH_WORLD,
            FINDING_CODES.SG_OPEN_RDP_WORLD,
            FINDING_CODES.SG_OPEN_HTTP_WORLD,
            FINDING_CODES.SG_UNUSED,
            FINDING_CODES.RDS_BACKUP_DISABLED,
            FINDING_CODES.RDS_PUBLICLY_ACCESSIBLE,
            FINDING_CODES.DYNAMODB_PITR_DISABLED,
            FINDING_CODES.KMS_KEY_ROTATION_DISABLED,
            FINDING_CODES.CLOUDTRAIL_LOG_VALIDATION_DISABLED,
            FINDING_CODES.CLOUDTRAIL_NOT_MULTI_REGION,
            FINDING_CODES.EC2_IMDSV1_ENABLED,
            FINDING_CODES.EIP_UNASSOCIATED,
            FINDING_CODES.CLOUDWATCH_LOG_RETENTION_SHORT,
            FINDING_CODES.GUARDDUTY_DISABLED,
            FINDING_CODES.APIGATEWAY_XRAY_DISABLED
        ]);

        // Fallback text check for legacy compatibility
        const LEGACY_SAFE_WORDS = [
            'Public access', 'Versioning', 'Default encryption', 'Lifecycle',
            'Log Validation', 'Not multi-region', 'Rotation', 'PITR', 'retention',
            '< 365', 'X-Ray', 'IMDSv2', 'disabled', 'port 22', 'RDP', '3389',
            'HTTP', 'port 80', 'Unused Security Group', 'Unassociated',
            'Backup retention', 'Multi-AZ', 'Publicly accessible', 'execute-api'
        ];

        const isSafeToAutoFix = SAFE_AUTO_FIX_CODES.has(findingCode) || 
                                LEGACY_SAFE_WORDS.some(w => issue.toLowerCase().includes(w.toLowerCase()));

        // ── Dry Run Simulation Mode ──
        if (dryRun) {
            log.info(`[DRY-RUN] Would fix AWS ${resourceType} "${resourceName}" (Code: ${findingCode}): ${issue}`);
            return {
                success: true,
                dryRun: true,
                findingCode,
                targetResource: resourceName,
                resourceType,
                action: isSafeToAutoFix ? 'AUTO_REMEDIATE' : 'ADVISORY_ESCALATE',
                message: `[DRY-RUN] Safety validated for ${findingCode} on "${resourceName}". Would execute targeted fix.`
            };
        }

        if (!isSafeToAutoFix) {
            log.info(`[BLAST RADIUS] Auto-fix blocked and escalated for ${resourceType} "${resourceName}" (Code: ${findingCode}): ${issue}`);
            return {
                success: true,
                advisory: true,
                findingCode,
                message: `ADVISORY: Finding [${findingCode}] on ${resourceType} "${resourceName}" requires manual approval. Escalated for human review.`
            };
        }

        const config = {
            region: credentials.region || 'us-east-1',
            credentials: {
                accessKeyId: credentials.isObfuscated ? deobfuscate(credentials.accessKeyId) : credentials.accessKeyId,
                secretAccessKey: credentials.isObfuscated ? deobfuscate(credentials.secretAccessKey) : credentials.secretAccessKey
            }
        };

        let result = { success: true, findingCode, message: `Successfully remediated ${resourceName}` };

        // ─────────────────────────────────────────────────────────────────────
        // 1. S3 BUCKETS
        // ─────────────────────────────────────────────────────────────────────
        if (resourceType === 'S3 Bucket' || findingCode.startsWith('S3_')) {
            const s3 = new S3Client(config);

            if (findingCode === FINDING_CODES.S3_PUBLIC_ACCESS || issue.includes('Public access')) {
                await s3.send(new PutPublicAccessBlockCommand({
                    Bucket: resourceName,
                    PublicAccessBlockConfiguration: {
                        BlockPublicAcls: true,
                        IgnorePublicAcls: true,
                        BlockPublicPolicy: true,
                        RestrictPublicBuckets: true
                    }
                }));
                result.message = `Enabled S3 Block Public Access (all 4 settings) on "${resourceName}".`;
            } 
            else if (findingCode === FINDING_CODES.S3_VERSIONING_DISABLED || issue.includes('Versioning')) {
                await s3.send(new PutBucketVersioningCommand({
                    Bucket: resourceName,
                    VersioningConfiguration: { Status: 'Enabled' }
                }));
                result.message = `Enabled S3 Bucket Versioning on "${resourceName}".`;
            } 
            else if (findingCode === FINDING_CODES.S3_ENCRYPTION_DISABLED || issue.includes('encryption')) {
                await s3.send(new PutBucketEncryptionCommand({
                    Bucket: resourceName,
                    ServerSideEncryptionConfiguration: {
                        Rules: [{
                            ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms' },
                            BucketKeyEnabled: true
                        }]
                    }
                }));
                result.message = `Enabled KMS default encryption on S3 bucket "${resourceName}".`;
            } 
            else if (findingCode === FINDING_CODES.S3_LIFECYCLE_MISSING || issue.includes('Lifecycle')) {
                await s3.send(new PutBucketLifecycleConfigurationCommand({
                    Bucket: resourceName,
                    LifecycleConfiguration: {
                        Rules: [{
                            Status: "Enabled",
                            Filter: { Prefix: "" },
                            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
                            ID: "ComplianceFlow-Auto-Abort-Incomplete-Multipart"
                        }]
                    }
                }));
                result.message = `Applied base lifecycle policy to S3 bucket "${resourceName}".`;
            }
            else if (issue.includes('MFA Delete')) {
                result = {
                    success: true,
                    advisory: true,
                    findingCode,
                    message: `ADVISORY: MFA Delete can only be enabled by the root account user via AWS CLI or SDK.`
                };
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 2. SECURITY GROUPS (Parameterized CIDR & Pre-Flight Check)
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'Security Group' || findingCode.startsWith('SG_')) {
            const ec2 = new EC2Client(config);

            const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({ GroupNames: [resourceName] })).catch(() => ({ SecurityGroups: [] }));
            const sg = SecurityGroups?.[0];

            if (!sg) {
                return { success: false, error: `Pre-flight check failed: Security Group "${resourceName}" not found.` };
            }

            if (findingCode === FINDING_CODES.SG_OPEN_SSH_WORLD || issue.includes('port 22') || issue.includes('SSH')) {
                const openRules = (sg.IpPermissions || []).filter(p => (p.FromPort <= 22 && p.ToPort >= 22) && (p.IpRanges || []).some(r => r.CidrIp === '0.0.0.0/0'));
                
                if (openRules.length === 0) {
                    return { success: true, message: `Pre-flight check: SSH port 22 is already closed to 0.0.0.0/0 on "${resourceName}".` };
                }

                for (const rule of openRules) {
                    await ec2.send(new RevokeSecurityGroupIngressCommand({
                        GroupId: sg.GroupId,
                        IpPermissions: [{ IpProtocol: rule.IpProtocol, FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }]
                    }));
                }

                if (safeCidr) {
                    await ec2.send(new AuthorizeSecurityGroupIngressCommand({
                        GroupId: sg.GroupId,
                        IpPermissions: [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: safeCidr, Description: 'Restricted SSH (ComplianceFlow Policy)' }] }]
                    }));
                    result.message = `Revoked 0.0.0.0/0 and restricted SSH to authorized CIDR (${safeCidr}) on "${resourceName}".`;
                } else {
                    result.message = `Revoked public 0.0.0.0/0 SSH rule on "${resourceName}" (Revoke-Only safe mode).`;
                }
            }
            else if (findingCode === FINDING_CODES.SG_OPEN_RDP_WORLD || issue.includes('RDP') || issue.includes('3389')) {
                const rdpRules = (sg.IpPermissions || []).filter(p => (p.FromPort <= 3389 && p.ToPort >= 3389) && (p.IpRanges || []).some(r => r.CidrIp === '0.0.0.0/0'));
                for (const rule of rdpRules) {
                    await ec2.send(new RevokeSecurityGroupIngressCommand({
                        GroupId: sg.GroupId,
                        IpPermissions: [{ IpProtocol: rule.IpProtocol, FromPort: rule.FromPort, ToPort: rule.ToPort, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }]
                    }));
                }
                result.message = `Revoked public RDP (port 3389) rule on "${resourceName}".`;
            }
            else if (findingCode === FINDING_CODES.SG_OPEN_HTTP_WORLD || issue.includes('HTTP') || issue.includes('port 80')) {
                const httpRules = (sg.IpPermissions || []).filter(p => (p.FromPort <= 80 && p.ToPort >= 80) && (p.IpRanges || []).some(r => r.CidrIp === '0.0.0.0/0'));
                for (const rule of httpRules) {
                    await ec2.send(new RevokeSecurityGroupIngressCommand({
                        GroupId: sg.GroupId,
                        IpPermissions: [{ IpProtocol: rule.IpProtocol, FromPort: rule.FromPort, ToPort: rule.ToPort, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }]
                    }));
                }
                result.message = `Revoked public HTTP (port 80) rule on "${resourceName}".`;
            }
            else if (findingCode === FINDING_CODES.SG_UNUSED || issue.includes('Unused')) {
                await ec2.send(new DeleteSecurityGroupCommand({ GroupId: sg.GroupId }));
                result.message = `Deleted unused Security Group: "${resourceName}".`;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 3. EC2 & EBS VOLUMES / SNAPSHOTS
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'EC2 Instance' || findingCode === FINDING_CODES.EC2_IMDSV1_ENABLED) {
            const ec2 = new EC2Client(config);
            await ec2.send(new ModifyInstanceMetadataOptionsCommand({
                InstanceId: resourceName,
                HttpTokens: 'required',
                HttpEndpoint: 'enabled'
            }));
            result.message = `Enforced IMDSv2 (HttpTokens: required) on EC2 instance "${resourceName}".`;
        }
        else if (resourceType === 'Elastic IP' || findingCode === FINDING_CODES.EIP_UNASSOCIATED) {
            const ec2 = new EC2Client(config);
            await ec2.send(new ReleaseAddressCommand({ AllocationId: resourceName }));
            result.message = `Released unassociated Elastic IP ${resourceName}.`;
        }
        else if (resourceType === 'EBS Snapshot') {
            if (issue.includes('Publicly Restorable')) {
                const ec2 = new EC2Client(config);
                await ec2.send(new ModifySnapshotAttributeCommand({
                    SnapshotId: resourceName,
                    Attribute: "createVolumePermission",
                    OperationType: "remove",
                    GroupNames: ["all"]
                }));
                result.message = `Removed public restore permissions from EBS Snapshot ${resourceName}.`;
            }
        }
        else if (resourceType === 'EBS Volume') {
            result = {
                success: true,
                advisory: true,
                findingCode,
                message: `ADVISORY: EBS volume encryption cannot be enabled in-place. Create an encrypted snapshot copy and restore.`
            };
        }

        // ─────────────────────────────────────────────────────────────────────
        // 4. RDS DATABASES
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'RDS Database' || findingCode.startsWith('RDS_')) {
            const rds = new RDSClient(config);

            if (findingCode === FINDING_CODES.RDS_BACKUP_DISABLED || issue.includes('Backup retention')) {
                await rds.send(new ModifyDBInstanceCommand({
                    DBInstanceIdentifier: resourceName,
                    BackupRetentionPeriod: 14,
                    ApplyImmediately: true
                }));
                result.message = `Configured 14-day automated backup retention on RDS "${resourceName}".`;
            }
            else if (findingCode === FINDING_CODES.RDS_PUBLICLY_ACCESSIBLE || issue.includes('Publicly accessible')) {
                await rds.send(new ModifyDBInstanceCommand({
                    DBInstanceIdentifier: resourceName,
                    PubliclyAccessible: false,
                    ApplyImmediately: true
                }));
                result.message = `Revoked public accessibility on RDS instance "${resourceName}".`;
            }
            else if (issue.includes('Multi-AZ')) {
                await rds.send(new ModifyDBInstanceCommand({
                    DBInstanceIdentifier: resourceName,
                    MultiAZ: true,
                    ApplyImmediately: false
                }));
                result.message = `Multi-AZ enabled for "${resourceName}" (applies next maintenance window).`;
            }
            else if (findingCode === FINDING_CODES.RDS_UNENCRYPTED || issue.includes('Encryption at rest')) {
                result = {
                    success: true,
                    advisory: true,
                    findingCode,
                    message: `ADVISORY: RDS encryption at rest cannot be enabled in-place. Create an encrypted snapshot and restore.`
                };
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 5. KMS KEY ROTATION
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'KMS Key' || findingCode === FINDING_CODES.KMS_KEY_ROTATION_DISABLED) {
            const kms = new KMSClient(config);
            await kms.send(new EnableKeyRotationCommand({ KeyId: resourceName }));
            result.message = `Enabled automatic annual key rotation on KMS Key "${resourceName}".`;
        }

        // ─────────────────────────────────────────────────────────────────────
        // 6. DYNAMODB TABLES
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'DynamoDB Table' || findingCode === FINDING_CODES.DYNAMODB_PITR_DISABLED) {
            if (issue.includes('PITR') || findingCode === FINDING_CODES.DYNAMODB_PITR_DISABLED) {
                const ddb = new DynamoDBClient(config);
                await ddb.send(new UpdateContinuousBackupsCommand({
                    TableName: resourceName,
                    PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true }
                }));
                result.message = `Enabled Point-in-Time Recovery (PITR) on DynamoDB table "${resourceName}".`;
            } else {
                result = {
                    success: true,
                    advisory: true,
                    findingCode,
                    message: `ADVISORY: KMS encryption configuration for DynamoDB cannot be modified in-place.`
                };
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 7. CLOUDTRAIL LOGGING
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'CloudTrail' || findingCode.startsWith('CLOUDTRAIL_')) {
            const cloudtrail = new CloudTrailClient(config);
            if (findingCode === FINDING_CODES.CLOUDTRAIL_LOG_VALIDATION_DISABLED || issue.includes('Validation')) {
                await cloudtrail.send(new UpdateTrailCommand({
                    Name: resourceName,
                    EnableLogFileValidation: true
                }));
                result.message = `Enabled digest log file validation on CloudTrail "${resourceName}".`;
            } else if (findingCode === FINDING_CODES.CLOUDTRAIL_NOT_MULTI_REGION || issue.includes('multi-region')) {
                await cloudtrail.send(new UpdateTrailCommand({
                    Name: resourceName,
                    IsMultiRegionTrail: true
                }));
                result.message = `Configured CloudTrail "${resourceName}" as multi-region trail.`;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 8. GUARDDUTY THREAT DETECTION
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'Threat Detection' || findingCode === FINDING_CODES.GUARDDUTY_DISABLED) {
            const guardduty = new GuardDutyClient(config);
            await guardduty.send(new CreateDetectorCommand({ Enable: true }));
            result.message = `Enabled Amazon GuardDuty threat detection.`;
        }

        // ─────────────────────────────────────────────────────────────────────
        // 9. CLOUDWATCH LOG GROUPS
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'Log Group' || findingCode === FINDING_CODES.CLOUDWATCH_LOG_RETENTION_SHORT) {
            const logs = new CloudWatchLogsClient(config);
            await logs.send(new PutRetentionPolicyCommand({
                logGroupName: resourceName,
                retentionInDays: 365
            }));
            result.message = `Set 365-day compliance retention policy on Log Group "${resourceName}".`;
        }

        // ─────────────────────────────────────────────────────────────────────
        // 10. API GATEWAY
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'API Gateway') {
            if (issue.includes('execute-api')) {
                const apigw = new APIGatewayClient(config);
                await apigw.send(new UpdateRestApiCommand({
                    restApiId: resourceName,
                    patchOperations: [{ op: 'replace', path: '/disableExecuteApiEndpoint', value: 'true' }]
                }));
                result.message = `Disabled default execute-api endpoint for API ${resourceName}.`;
            }
        }
        else if (resourceType === 'API Gateway Stage' || findingCode === FINDING_CODES.APIGATEWAY_XRAY_DISABLED) {
            if (issue.includes('X-Ray') || findingCode === FINDING_CODES.APIGATEWAY_XRAY_DISABLED) {
                const apigw = new APIGatewayClient(config);
                const [apiId, stageName] = resourceName.split('/');
                if (apiId && stageName) {
                    await apigw.send(new UpdateStageCommand({
                        restApiId: apiId,
                        stageName: stageName,
                        patchOperations: [{ op: 'replace', path: '/*/*/tracingEnabled', value: 'true' }]
                    }));
                    result.message = `Enabled X-Ray tracing for API Stage ${resourceName}.`;
                }
            } else if (issue.includes('WAF')) {
                result = { success: true, advisory: true, findingCode, message: `ADVISORY: Attach a WebACL via APIGW Console > Stages.` };
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 11. LAMBDA RUNTIMES
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'Lambda') {
            if (issue.includes('runtime')) {
                const lambda = new LambdaClient(config);
                await lambda.send(new UpdateFunctionConfigurationCommand({
                    FunctionName: resourceName,
                    Runtime: 'nodejs20.x'
                }));
                result.message = `Updated Lambda "${resourceName}" runtime to Node.js 20.x.`;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 12. IAM ACCOUNTS, USERS, ROLES (Advisories & Session Invalidation)
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'IAM Account') {
            result = {
                success: true,
                advisory: true,
                findingCode,
                message: issue.includes('Root') ? `ADVISORY: Root MFA / Keys must be managed manually in the AWS Console.` : `ADVISORY: Configure password policy via IAM Console.`
            };
        }
        else if (resourceType === 'IAM User') {
            result = {
                success: true,
                advisory: true,
                findingCode,
                message: `ADVISORY: User "${resourceName}" access requires manual review (rotate access keys / enforce MFA).`
            };
        }
        else if (resourceType === 'IAM Role') {
            const iam = new IAMClient(config);
            if (issue.includes('Stale Access') || issue.includes('180 days') || findingCode === FINDING_CODES.IAM_STALE_ACCESS) {
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
                result.message = `Deactivated stale IAM Role "${resourceName}" with explicit Deny assume-role policy.`;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 13. SQS, SNS, REDSHIFT, EKS, MACIE, WAF, SHIELD (Advisories)
        // ─────────────────────────────────────────────────────────────────────
        else if (resourceType === 'Redshift Cluster') {
            result = { success: true, advisory: true, findingCode, message: `ADVISORY: Redshift cluster changes (encryption, public access) require planned maintenance.` };
        }
        else if (resourceType === 'EKS Cluster') {
            result = { success: true, advisory: true, findingCode, message: `ADVISORY: EKS cluster modifications (secrets encryption, logging) must be applied via cluster configuration.` };
        }
        else if (resourceType === 'SQS Queue') {
            result = { success: true, advisory: true, findingCode, message: `ADVISORY: Enable SQS server-side encryption via SQS Console > Edit Queue.` };
        }
        else if (resourceType === 'SNS Topic') {
            result = { success: true, advisory: true, findingCode, message: `ADVISORY: Enable SNS server-side encryption via SNS Console > Edit Topic.` };
        }
        else if (resourceType === 'Macie') {
            result = { success: true, advisory: true, findingCode, message: `ADVISORY: Enable Amazon Macie sensitive data discovery in the AWS Console.` };
        }
        else if (resourceType === 'WAF') {
            result = { success: true, advisory: true, findingCode, message: `ADVISORY: Create and associate a WebACL via AWS WAF & Shield Console.` };
        }
        else if (resourceType === 'Shield') {
            result = { success: true, advisory: true, findingCode, message: `ADVISORY: AWS Shield Advanced requires an active subscription.` };
        }

        // Fallback for any other resource
        else {
            result = {
                success: true,
                advisory: true,
                findingCode,
                message: `ADVISORY: Automated fix for ${resourceType} "${resourceName}" requires manual operator review.`
            };
        }

        return result;

    } catch (err) {
        log.error(`[AWS REMEDIATION ERROR] Failed on ${resourceType} "${resourceName}":`, err.message);
        throw err;
    }
}
