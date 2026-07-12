import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";

const client = new EC2Client({
    region: process.env.AWS_REGION || "us-east-1",
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});

async function run() {
    try {
        const response = await client.send(new DescribeInstancesCommand({}));
        const instances = [];
        
        for (const reservation of response.Reservations || []) {
            for (const instance of reservation.Instances || []) {
                const nameTag = instance.Tags?.find(t => t.Key === 'Name')?.Value || 'unnamed';
                instances.push({
                    id: instance.InstanceId,
                    state: instance.State?.Name,
                    publicIp: instance.PublicIpAddress,
                    privateIp: instance.PrivateIpAddress,
                    name: nameTag,
                    keyName: instance.KeyName
                });
            }
        }
        
        console.log(JSON.stringify({ success: true, instances }, null, 2));
    } catch (err) {
        console.error(JSON.stringify({ success: false, error: err.message }));
    }
}

run();
