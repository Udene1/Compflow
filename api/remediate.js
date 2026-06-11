import { S3Client, PutPublicAccessBlockCommand, PutBucketVersioningCommand, PutBucketEncryptionCommand, PutBucketLifecycleConfigurationCommand } from "@aws-sdk/client-s3";
import { EC2Client, RevokeSecurityGroupIngressCommand, AuthorizeSecurityGroupIngressCommand, DescribeSecurityGroupsCommand, CreateFlowLogsCommand, ReleaseAddressCommand, DeleteSecurityGroupCommand, ModifyInstanceMetadataOptionsCommand, ModifySnapshotAttributeCommand } from "@aws-sdk/client-ec2";
import { IAMClient, UpdateAssumeRolePolicyCommand, GetRoleCommand, UpdateAccessKeyCommand } from "@aws-sdk/client-iam";
import { RDSClient, ModifyDBInstanceCommand } from "@aws-sdk/client-rds";
import { KMSClient, EnableKeyRotationCommand } from "@aws-sdk/client-kms";
import { ConfigServiceClient } from "@aws-sdk/client-config-service";
import { GuardDutyClient, CreateDetectorCommand } from "@aws-sdk/client-guardduty";
import { CloudWatchLogsClient, PutRetentionPolicyCommand } from "@aws-sdk/client-cloudwatch-logs";
import { CloudWatchClient } from "@aws-sdk/client-cloudwatch";
import { DynamoDBClient, UpdateContinuousBackupsCommand } from "@aws-sdk/client-dynamodb";
import { APIGatewayClient, UpdateRestApiCommand, UpdateStageCommand } from "@aws-sdk/client-api-gateway";
import { CloudFrontClient, UpdateDistributionCommand, GetDistributionConfigCommand } from "@aws-sdk/client-cloudfront";
import { SQSClient, SetQueueAttributesCommand } from "@aws-sdk/client-sqs";
import { SNSClient, SetTopicAttributesCommand } from "@aws-sdk/client-sns";
import { Monitoring } from '../core/monitoring.js';
import { v4 as uuidv4 } from 'uuid';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { credentials, provider, resourceType, resourceName, issue, dryRun, clientId } = req.body;
    const jobId = uuidv4();

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

    // Flexible credential check
    const hasKeys = credentials?.accessKeyId && credentials?.secretAccessKey;
    const hasToken = credentials?.apiToken;
    const hasRole = credentials?.authMethod === 'role';

    if (!hasKeys && !hasToken && !hasRole) {
        return res.status(400).json({ error: 'Missing or incomplete cloud credentials' });
    }

    try {
        // ── PHASE 1: Blast Radius Control (Auto-Fix Whitelist) ──
        // Only low-risk, non-destructive actions are permitted for autonomous remediation.
        // Dangerous actions (Networking, IAM, Elastic IPs) MUST escalate, even if the LLM hallucinated safety.
        const SAFE_WHITELIST = {
            'S3 Bucket': ['Public access', 'Versioning', 'Default encryption', 'Lifecycle'],
            'CloudTrail': ['Log Validation', 'Not multi-region', 'Log encryption'],
            'KMS Key': ['Rotation'],
            'DynamoDB Table': ['PITR'],
            'Log Group': ['retention', '< 365'],
            'API Gateway Stage': ['X-Ray'],
            'EC2 Instance': ['IMDSv2'],
            'Threat Detection': ['disabled'],
            'Hetzner Server': ['firewall', 'login'],
            'DigitalOcean Droplet': ['VPC'],
            'DigitalOcean Firewall': ['port 22']
        };

        const isSafeParams = SAFE_WHITELIST[resourceType] && 
                             SAFE_WHITELIST[resourceType].some(safeWord => issue.includes(safeWord));

        if (!isSafeParams) {
            return res.status(200).json({
                success: true,
                advisory: true,
                message: `ADVISORY [BLAST RADIUS]: Auto-fixing "${issue}" on ${resourceType} is outside the safe whitelist. Escalated for human review.`
            });
        }

        // ── PHASE 1: Dry-Run Mode ──
        if (dryRun) {
            console.log(`[DRY-RUN] ${provider.toUpperCase()} Remediation prevented for ${resourceType} "${resourceName}": ${issue}`);
            return res.status(200).json({
                success: true,
                message: `[DRY-RUN] Validated safety. Would execute fix for ${resourceName}.`
            });
        }

        // ── PHASE 1: Job Logging ──
        await Monitoring.logJobStart(jobId, clientId || 'default', provider, issue);

        let result = { success: true, message: `Successfully remediated ${resourceName}` };

        try {
            if (provider === 'aws') {
                const { runRemediation } = await import('../core/providers/aws_remediator.js');
                result = await runRemediation(provider, credentials, resourceType, resourceName, issue, dryRun);
            } else if (provider === 'gcp') {
                const { runRemediation } = await import('../core/providers/gcp_remediator.js');
                result = await runRemediation(provider, credentials, resourceType, resourceName, issue);
            } else if (provider === 'azure') {
                const { runRemediation } = await import('../core/providers/azure_remediator.js');
                result = await runRemediation(provider, credentials, resourceType, resourceName, issue);
            } else if (provider === 'hetzner') {
                const { runRemediation } = await import('../core/providers/hetzner_remediator.js');
                result = await runRemediation(provider, credentials, resourceType, resourceName, issue);
            } else if (provider === 'digitalocean') {
                const { runRemediation } = await import('../core/providers/digitalocean_remediator.js');
                result = await runRemediation(provider, credentials, resourceType, resourceName, issue);
            } else {
                result = {
                    success: false,
                    message: `ADVISORY: Provider "${provider}" is not recognized. No automated remediation available.`
                };
            }

            await Monitoring.logJobComplete(jobId, result.success, result.message, result);
            res.status(200).json(result);

        } catch (innerError) {
            const userFriendly = Monitoring.standardizeError(innerError, provider);
            await Monitoring.logJobComplete(jobId, false, userFriendly, { raw: innerError.message });
            res.status(500).json({ success: false, error: userFriendly });
        }

    } catch (error) {
        console.error('Fatal Remediation Error:', error);
        res.status(500).json({ success: false, error: 'Internal system fault during remediation orchestration.' });
    }
}
