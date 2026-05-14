import { S3Client, CreateBucketCommand, DeletePublicAccessBlockCommand } from "@aws-sdk/client-s3";

const config = {
    region: process.env.AWS_REGION || 'us-east-1',
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY,
    }
};

const BUCKET_NAME = `complianceflow-honeypot-${Math.floor(Math.random() * 1000000)}`;

async function deploy() {
    const s3 = new S3Client(config);
    
    console.log(`🚀 Deploying vulnerable bucket: ${BUCKET_NAME}...`);
    try {
        // 1. Create Bucket
        await s3.send(new CreateBucketCommand({ Bucket: BUCKET_NAME }));
        console.log(`✅ Bucket created.`);

        // 2. Intentionally remove Public Access Block (Make it vulnerable)
        console.log(`🔓 DISABLING Public Access Block (Honeypot mode)...`);
        await s3.send(new DeletePublicAccessBlockCommand({ Bucket: BUCKET_NAME }));
        
        console.log(`\n✨ VULNERABLE BUCKET IS LIVE!`);
        console.log(`Now, set "autoRemediate": true in clients.json and run the agent to see it get fixed.`);
        
        // Save bucket name for cleanup later
        import('fs').then(fs => fs.appendFileSync('.test_resources', BUCKET_NAME + '\n'));
        
    } catch (e) {
        console.error(`❌ Deployment failed:`, e.message);
    }
}

deploy();
