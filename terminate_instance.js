import { EC2Client, TerminateInstancesCommand } from "@aws-sdk/client-ec2";

const credentials = {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
};
const region = process.env.AWS_REGION || "us-east-1";
const ec2 = new EC2Client({ region, credentials });

async function run() {
    try {
        const instanceId = "i-0132a24632e59eacf";
        console.log(`[EC2] Terminating instance ${instanceId}...`);
        await ec2.send(new TerminateInstancesCommand({
            InstanceIds: [instanceId]
        }));
        console.log(`[EC2] Termination triggered successfully.`);
    } catch (err) {
        console.error("Failed to terminate:", err.message);
    }
}

run();
