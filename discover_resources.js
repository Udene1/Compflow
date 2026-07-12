import { SQSClient, ListQueuesCommand } from "@aws-sdk/client-sqs";
import { EC2Client, DescribeVpcsCommand, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";

const credentials = {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
};
const region = process.env.AWS_REGION || "us-east-1";

const sqs = new SQSClient({ region, credentials });
const ec2 = new EC2Client({ region, credentials });

async function run() {
    const results = {};
    try {
        // 1. SQS Queues
        const sqsRes = await sqs.send(new ListQueuesCommand({}));
        results.queues = sqsRes.QueueUrls || [];
        
        // 2. Default VPC
        const vpcRes = await ec2.send(new DescribeVpcsCommand({
            Filters: [{ Name: "is-default", Values: ["true"] }]
        }));
        results.defaultVpcId = vpcRes.Vpcs?.[0]?.VpcId || null;
        
        // 3. Subnets in Default VPC
        if (results.defaultVpcId) {
            const subnetRes = await ec2.send(new DescribeSubnetsCommand({
                Filters: [{ Name: "vpc-id", Values: [results.defaultVpcId] }]
            }));
            results.subnets = subnetRes.Subnets?.map(s => ({
                id: s.SubnetId,
                az: s.AvailabilityZone,
                cidr: s.CidrBlock
            })) || [];
        }
        
        console.log(JSON.stringify({ success: true, results }, null, 2));
    } catch (err) {
        console.error(JSON.stringify({ success: false, error: err.message }));
    }
}

run();
