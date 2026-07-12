import { 
    EC2Client, 
    CreateSecurityGroupCommand, 
    AuthorizeSecurityGroupIngressCommand, 
    RunInstancesCommand, 
    DescribeSecurityGroupsCommand
} from "@aws-sdk/client-ec2";
import fs from "fs";

const credentials = {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
};
const region = process.env.AWS_REGION || "us-east-1";
const vpcId = "vpc-0eb388a3f45bb0f37"; // default vpc discovered
const subnetId = "subnet-0550c5b21be926d12"; // us-east-1a public subnet discovered
const queueUrl = "https://sqs.us-east-1.amazonaws.com/716563790683/CompFlowScanQueue";

const ec2 = new EC2Client({ region, credentials });

// Load env values from current environment
const geminiApiKey = process.env.GEMINI_API_KEY;
const sesFromEmail = process.env.AWS_SES_FROM_EMAIL || "support@verimut.icu";

async function getOrCreateSecurityGroup() {
    const groupName = "complianceflow-backend-sg";
    try {
        const descRes = await ec2.send(new DescribeSecurityGroupsCommand({
            Filters: [
                { Name: "group-name", Values: [groupName] },
                { Name: "vpc-id", Values: [vpcId] }
            ]
        }));
        if (descRes.SecurityGroups && descRes.SecurityGroups.length > 0) {
            console.log(`[SG] Using existing Security Group: ${descRes.SecurityGroups[0].GroupId}`);
            return descRes.SecurityGroups[0].GroupId;
        }
    } catch (e) {
        // Continue to create
    }

    console.log(`[SG] Creating new Security Group: ${groupName}...`);
    const createRes = await ec2.send(new CreateSecurityGroupCommand({
        GroupName: groupName,
        Description: "Security Group for ComplianceFlow stand-alone backend on EC2",
        VpcId: vpcId
    }));
    const groupId = createRes.GroupId;

    // Add inbound rules for ports 22, 80, 443, and 3000
    await ec2.send(new AuthorizeSecurityGroupIngressCommand({
        GroupId: groupId,
        IpPermissions: [
            {
                IpProtocol: "tcp",
                FromPort: 22,
                ToPort: 22,
                IpRanges: [{ CidrIp: "0.0.0.0/0", Description: "SSH access" }]
            },
            {
                IpProtocol: "tcp",
                FromPort: 80,
                ToPort: 80,
                IpRanges: [{ CidrIp: "0.0.0.0/0", Description: "HTTP access" }]
            },
            {
                IpProtocol: "tcp",
                FromPort: 443,
                ToPort: 443,
                IpRanges: [{ CidrIp: "0.0.0.0/0", Description: "HTTPS access" }]
            },
            {
                IpProtocol: "tcp",
                FromPort: 3000,
                ToPort: 3000,
                IpRanges: [{ CidrIp: "0.0.0.0/0", Description: "API Port access" }]
            }
        ]
    }));
    console.log(`[SG] Authorizations set for Security Group: ${groupId}`);
    return groupId;
}

async function run() {
    try {
        const sgId = await getOrCreateSecurityGroup();
        
        // Define UserData script to run on EC2 startup
        const userDataScript = `#!/bin/bash
sudo yum update -y
sudo yum install -y docker git
sudo systemctl start docker
sudo systemctl enable docker

# Clone repository
cd /home/ec2-user
git clone https://github.com/Udene1/Compflow.git backend
cd backend

# Build Docker image
docker build -t complianceflow-backend .

# Run Docker container
docker run -d \\
  --name compflow-api \\
  -p 80:3000 \\
  -e AWS_ACCESS_KEY_ID="${credentials.accessKeyId}" \\
  -e AWS_SECRET_ACCESS_KEY="${credentials.secretAccessKey}" \\
  -e AWS_REGION="${region}" \\
  -e SCAN_QUEUE_URL="${queueUrl}" \\
  -e GEMINI_API_KEY="${geminiApiKey}" \\
  -e AWS_SES_FROM_EMAIL="${sesFromEmail}" \\
  -e NODE_ENV="production" \\
  --restart unless-stopped \\
  complianceflow-backend
`;

        const base64UserData = Buffer.from(userDataScript).toString("base64");

        console.log("[EC2] Launching t3.micro instance...");
        const runRes = await ec2.send(new RunInstancesCommand({
            ImageId: "ami-00c39f71452c08778", // standard us-east-1 Amazon Linux 2023 x86_64
            InstanceType: "t3.micro",
            MinCount: 1,
            MaxCount: 1,
            UserData: base64UserData,
            TagSpecifications: [
                {
                    ResourceType: "instance",
                    Tags: [{ Key: "Name", Value: "ComplianceFlow-Backend-Prod" }]
                }
            ],
            // We enable public IP auto-assignment on launch
            NetworkInterfaces: [
                {
                    DeviceIndex: 0,
                    AssociatePublicIpAddress: true,
                    SubnetId: subnetId,
                    Groups: [sgId]
                }
            ]
        }));

        const instanceId = runRes.Instances[0].InstanceId;
        console.log(`[EC2] Successful trigger! Instance ID: ${instanceId}`);
        console.log(`[EC2] Waiting for initialization. Please query status in a moment.`);

    } catch (err) {
        console.error("EC2 Provisioning failed:", err);
    }
}

run();
