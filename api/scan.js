import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import { IAMClient, ListRolesCommand, ListAccountAliasesCommand } from "@aws-sdk/client-iam";

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
            const ec2 = new import("@aws-sdk/client-ec2").EC2Client(config);
            const rds = new import("@aws-sdk/client-rds").RDSClient(config);

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

            // 2. Scan EC2 Security Groups
            try {
                const { SecurityGroups } = await ec2.send(new import("@aws-sdk/client-ec2").DescribeSecurityGroupsCommand({}));
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
            } catch (e) { console.warn("EC2 fail", e); }

            // 3. Scan RDS Instances
            try {
                const { DBInstances } = await rds.send(new import("@aws-sdk/client-rds").DescribeDBInstancesCommand({}));
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

            // 4. Scan IAM Roles
            try {
                const { Roles } = await iam.send(new ListRolesCommand({}));
                for (const role of Roles || []) {
                    const isOld = (new Date() - new Date(role.CreateDate)) / (1000 * 60 * 60 * 24) > 180;
                    resources.push({
                        name: role.RoleName, type: 'IAM Role', icon: '🔑',
                        region: 'global', severity: isOld ? 'warning' : 'pass',
                        control: 'CC6.2', issue: isOld ? 'Stale Access (>180 days)' : null
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
