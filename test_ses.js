import { sendReport, generateReport } from './core/reporter.js';

async function testSES() {
    const recipient = process.env.AWS_SES_FROM_EMAIL; // Test by sending to yourself
    const clientName = "Test Client (ComplianceFlow)";
    
    console.log(`\n📧 Attempting to send test report...`);
    console.log(`   From: ${process.env.AWS_SES_FROM_EMAIL}`);
    console.log(`   To:   ${recipient}`);
    console.log(`   Region: ${process.env.AWS_REGION || 'us-east-1'}`);

    const dummyScanResults = [
        { severity: 'pass', name: 'IAM MFA' },
        { severity: 'fail', name: 'Open S3 Buckets' }
    ];
    
    const dummyRemediation = {
        resolved: 1,
        escalated: 1,
        details: [
            { name: 'S3 Public Access', status: 'fixed', issue: 'Bucket was public' },
            { name: 'KMS Key Rotation', status: 'escalated', issue: 'Customer managed key rotation disabled' }
        ]
    };

    const html = generateReport(clientName, dummyScanResults, dummyRemediation);

    try {
        const result = await sendReport(recipient, clientName, html);
        if (result.sent) {
            console.log("\n✅ SUCCESS: Test email sent!");
            console.log(`   MessageId: ${result.messageId}`);
        } else {
            console.error("\n❌ FAILED to send email.");
            console.error(`   Reason: ${result.reason}`);
            
            if (result.reason.includes('Identity not verified')) {
                console.log("\n💡 TIP: Make sure you verified the email in the AWS Console.");
            }
        }
    } catch (err) {
        console.error("\n💥 UNEXPECTED ERROR:", err);
    }
}

testSES();
