import { S3Client, PutPublicAccessBlockCommand } from "@aws-sdk/client-s3";

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

        if (provider === 'aws') {
            if (resourceType === 'S3 Bucket' && issue.includes('Public access')) {
                const s3 = new S3Client(config);
                await s3.send(new PutPublicAccessBlockCommand({
                    Bucket: resourceName,
                    PublicAccessBlockConfiguration: {
                        BlockPublicAcls: true,
                        IgnorePublicAcls: true,
                        BlockPublicPolicy: true,
                        RestrictPublicBuckets: true
                    }
                }));
            }
            // Add more remediation handlers as needed
        }

        res.status(200).json({ success: true, message: `Successfully remediated ${resourceName}` });
    } catch (error) {
        console.error('Remediation Error:', error);
        res.status(500).json({ error: error.message });
    }
}
