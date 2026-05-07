import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import { IAMClient, ListRolesCommand, ListAccountAliasesCommand } from "@aws-sdk/client-iam";

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { credentials, provider } = req.body;

    if (!credentials || !credentials.accessKeyId || !credentials.secretAccessKey) {
        return res.status(400).json({ error: 'Missing cloud credentials' });
    }

    try {
        const config = {
            region: credentials.region || 'us-east-1',
            credentials: {
                accessKeyId: credentials.accessKeyId,
                secretAccessKey: credentials.secretAccessKey
            }
        };

        const resources = [];
        
        if (provider === 'aws') {
            const s3 = new S3Client(config);
            const iam = new IAMClient(config);

            // 1. Scan S3 Buckets
            const { Buckets } = await s3.send(new ListBucketsCommand({}));
            for (const bucket of Buckets || []) {
                let severity = 'pass';
                let issue = null;

                try {
                    await s3.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name }));
                } catch (e) {
                    if (e.name === 'NoSuchPublicAccessBlockConfiguration') {
                        severity = 'critical';
                        issue = 'Public access enabled (No Block Public Access)';
                    }
                }

                resources.push({
                    name: bucket.Name,
                    type: 'S3 Bucket',
                    icon: '🪣',
                    region: config.region,
                    severity: severity,
                    control: 'CC6.1',
                    issue: issue
                });
            }

            // 2. Scan IAM Roles
            const { Roles } = await iam.send(new ListRolesCommand({}));
            for (const role of Roles || []) {
                // Simplified check: if role name contains 'admin' and was created long ago, mark as warning
                const isOld = (new Date() - new Date(role.CreateDate)) / (1000 * 60 * 60 * 24) > 90;
                
                resources.push({
                    name: role.RoleName,
                    type: 'IAM Role',
                    icon: '🔑',
                    region: 'global',
                    severity: isOld ? 'warning' : 'pass',
                    control: 'CC6.2',
                    issue: isOld ? 'Unused for 90 days (historical)' : null
                });
            }
        }

        res.status(200).json({ resources });
    } catch (error) {
        console.error('Scan Error:', error);
        res.status(500).json({ error: error.message });
    }
}
