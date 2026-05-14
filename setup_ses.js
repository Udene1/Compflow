import { SESClient, VerifyEmailIdentityCommand, GetIdentityVerificationAttributesCommand } from '@aws-sdk/client-ses';

const client = new SESClient({
    region: process.env.AWS_REGION || 'us-east-1',
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY,
    }
});

async function setup() {
    const fromEmail = process.env.AWS_SES_FROM_EMAIL;
    if (!fromEmail) {
        console.error("❌ Error: AWS_SES_FROM_EMAIL is not set in .env");
        return;
    }

    // Determine if it's a domain or email
    const isDomain = !fromEmail.includes('@');
    const identity = isDomain ? fromEmail : fromEmail; // Simplistic
    const domain = isDomain ? fromEmail : fromEmail.split('@')[1];

    console.log(`\n🚀 Starting SES Setup for: ${fromEmail}`);

    try {
        // 1. Verify Identity
        console.log(`\n1️⃣ Requesting verification for ${fromEmail}...`);
        
        if (isDomain) {
            console.log("   (Detected Domain-level verification)");
            // For domains, we usually want DKIM
            // But we'll start with the basic VerifyDomainIdentity if needed
            // Actually, in SES v2, the simple VerifyEmailIdentity works for both 
            // but for domains you need DNS.
        }

        await client.send(new VerifyEmailIdentityCommand({ EmailAddress: fromEmail }));
        console.log("✅ Verification request sent!");
        
        if (isDomain) {
            console.log("👉 ACTION REQUIRED: Add the DNS records provided in the AWS Console for your domain.");
        } else {
            console.log("👉 ACTION REQUIRED: Check your inbox and click the verification link from Amazon.");
        }

        // 2. Check Status
        console.log(`\n2️⃣ Checking current verification status...`);
        const statusResponse = await client.send(new GetIdentityVerificationAttributesCommand({
            Identities: [fromEmail]
        }));

        const status = statusResponse.VerificationAttributes[fromEmail]?.VerificationStatus;
        if (status === 'Success') {
            console.log("✅ Status: VERIFIED");
        } else {
            console.log(`⏳ Status: ${status || 'Pending'}`);
            if (isDomain) {
                console.log("   (DNS propagation can take up to 60 minutes)");
            }
        }

        console.log("\n---");
        console.log("Once verified, you can run 'node test_ses.js' to send a test email.");

    } catch (err) {
        console.error("\n❌ FAILED:", err.message);
    }
}

setup();
