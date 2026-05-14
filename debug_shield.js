import { ShieldClient, GetSubscriptionStateCommand } from "@aws-sdk/client-shield";

const config = {
    region: process.env.AWS_REGION || 'us-east-1',
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY,
    }
};

async function test() {
    const shield = new ShieldClient(config);
    try {
        const response = await shield.send(new GetSubscriptionStateCommand({}));
        console.log("Shield Response Keys:", Object.keys(response));
        console.log("Shield Response:", JSON.stringify(response));
    } catch (e) {
        console.log("Shield Error (expected if not subscribed):", e.message);
    }
}
test();
