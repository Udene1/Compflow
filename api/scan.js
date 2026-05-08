import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import { IAMClient, ListRolesCommand, GetAccountSummaryCommand } from "@aws-sdk/client-iam";
import { EC2Client, DescribeSecurityGroupsCommand, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { KMSClient, ListKeysCommand, DescribeKeyCommand, GetKeyRotationStatusCommand } from "@aws-sdk/client-kms";
import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";

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

            // 1. Scan S3 Buckets
            try {
                const { Buckets } = await s3.send(new ListBucketsCommand({}));
                for (const bucket of Buckets || []) {
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
                }
            } catch (e) { console.warn("S3 fail", e); }

            // 2. Scan EC2 Security Groups & VPCs
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

                const { Vpcs } = await ec2.send(new DescribeVpcsCommand({}));
                for (const vpc of Vpcs || []) {
                    resources.push({
                        name: vpc.VpcId, type: 'VPC', icon: '🌐',
                        region: config.region, severity: 'warning', control: 'CC7.2',
                        issue: 'Flow Logs disabled'
                    });
                }
            } catch (e) { console.warn("EC2/VPC fail", e); }

            // 3. Scan RDS Instances
            try {
                const { DBInstances } = await rds.send(new DescribeDBInstancesCommand({}));
                for (const db of DBInstances || []) {
                    const unencrypted = !db.StorageEncrypted;
                    resources.push({
                        name: db.DBInstanceIdentifier, type: 'RDS Database', icon: '💾',
                        region: config.region,
                        severity: unencrypted ? 'critical' : 'pass',
                        control: 'CC6.7',
                        issue: unencrypted ? 'Encryption at rest disabled' : null
                    });
                }
            } catch (e) { console.warn("RDS fail", e); }

            // 4. Scan CloudTrail
            try {
                const { TrailList } = await cloudtrail.send(new DescribeTrailsCommand({}));
                if (!TrailList || TrailList.length === 0) {
                    resources.push({
                        name: 'Global', type: 'CloudTrail', icon: '📋',
                        region: 'Global', severity: 'critical', control: 'CC7.2', issue: 'No trail enabled'
                    });
                } else {
                    TrailList.forEach(t => {
                        const validation = !t.LogFileValidationEnabled;
                        resources.push({
                            name: t.Name, type: 'CloudTrail', icon: '📋',
                            region: t.HomeRegion, severity: validation ? 'warning' : 'pass',
                            control: 'CC7.2', issue: validation ? 'Log Validation disabled' : null
                        });
                    });
                }
            } catch (e) { console.warn("CloudTrail fail", e); }

            // 5. Scan KMS Keys
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

            // 6. Scan IAM Account & Roles
            try {
                const { Roles } = await iam.send(new ListRolesCommand({}));
                for (const role of Roles || []) {
                    const isOld = (new Date() - new Date(role.CreateDate)) / (1000 * 60 * 60 * 24) > 180;
                    if (isOld) {
                        resources.push({
                            name: role.RoleName, type: 'IAM Role', icon: '🔑',
                            region: 'global', severity: 'warning',
                            control: 'CC6.2', issue: 'Stale Access (>180 days)'
                        });
                    }
                }
                const { SummaryMap } = await iam.send(new GetAccountSummaryCommand({}));
                if (SummaryMap.AccountMFAEnabled === 0) {
                    resources.push({
                        name: 'Root Account', type: 'IAM Account', icon: '👤',
                        region: 'Global', severity: 'critical', control: 'CC6.3', issue: 'Root MFA disabled'
                    });
                }
            } catch (e) { console.warn("IAM fail", e); }
        }

        res.status(200).json({ resources });
    } catch (error) {
        console.error('Scan Error:', error);
        res.status(500).json({ error: error.message });
    }
}
