import { sendReport, generateReport } from './core/reporter.js';
import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import { IAMClient, GetAccountSummaryCommand } from "@aws-sdk/client-iam";

const config = {
    region: process.env.AWS_REGION || 'us-east-1',
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY,
    }
};

async function runRealScan() {
    console.log("🚀 Starting Real AWS Scan...");
    const scanResults = [];
    const remediationDetails = [];

    const s3 = new S3Client(config);
    const iam = new IAMClient(config);

    try {
        // 1. Scan S3 Buckets
        console.log("📦 Scanning S3...");
        const { Buckets } = await s3.send(new ListBucketsCommand({}));
        for (const bucket of (Buckets || []).slice(0, 10)) {
            let severity = 'pass';
            let issue = null;
            try {
                await s3.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name }));
            } catch (e) {
                severity = 'fail';
                issue = 'Public access enabled (Block Public Access missing)';
                remediationDetails.push({ name: bucket.Name, status: 'escalated', issue });
            }
            scanResults.push({ severity, name: bucket.Name, type: 'S3 Bucket' });
        }

        // 2. Scan IAM Root MFA
        console.log("👤 Scanning IAM...");
        const { SummaryMap } = await iam.send(new GetAccountSummaryCommand({}));
        if (SummaryMap.AccountMFAEnabled === 0) {
            scanResults.push({ severity: 'fail', name: 'Root Account', type: 'IAM' });
            remediationDetails.push({ name: 'Root Account', status: 'escalated', issue: 'Root MFA is disabled' });
        } else {
            scanResults.push({ severity: 'pass', name: 'Root Account', type: 'IAM' });
        }

        const remediationSummary = {
            resolved: 0,
            escalated: remediationDetails.length,
            details: remediationDetails
        };

        console.log(`\n✅ Scan complete. Found ${scanResults.length} resources.`);
        
        const recipient = process.env.AWS_SES_FROM_EMAIL;
        const clientName = "Live AWS Environment";
        const html = generateReport(clientName, scanResults, remediationSummary);

        console.log(`📧 Sending real report to ${recipient}...`);
        const result = await sendReport(recipient, clientName, html);

        if (result.sent) {
            console.log("✨ SUCCESS: Live report sent!");
        } else {
            console.error("❌ Failed to send live report:", result.reason);
        }

    } catch (err) {
        console.error("💥 SCAN FAILED:", err.message);
    }
}

runRealScan();
