import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";

const client = new LambdaClient({
    region: process.env.AWS_REGION || "us-east-1",
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY
    }
});

async function trigger() {
    console.log("🚀 Triggering Lambda: complianceflow-ains-dev-orchestrator...");
    try {
        const command = new InvokeCommand({
            FunctionName: "complianceflow-ains-dev-orchestrator",
            LogType: "Tail",
            Payload: JSON.stringify({})
        });

        const response = await client.send(command);
        const payload = JSON.parse(new TextDecoder().decode(response.Payload));
        
        console.log("\n✅ LAMBDA RESPONSE:");
        console.log(JSON.stringify(payload, null, 2));

        if (response.LogResult) {
            const logs = Buffer.from(response.LogResult, 'base64').toString('utf8');
            console.log("\n📄 EXECUTION LOGS:");
            console.log(logs);
        }
    } catch (e) {
        console.error("❌ TRIGGER FAILED:", e);
    }
}

trigger();
