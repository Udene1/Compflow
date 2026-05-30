import { DynamoDBClient, CreateTableCommand, DescribeTableCommand, UpdateTimeToLiveCommand } from "@aws-sdk/client-dynamodb";

const client = new DynamoDBClient({ 
    region: process.env.AWS_REGION || "us-east-1",
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY
    }
});

const TABLE_NAME = "CompFlowJobsTable";

async function provision() {
    console.log(`🛠️ PROVISIONING DynamoDB Table: ${TABLE_NAME}...`);
    
    try {
        // 1. Check if table exists
        try {
            await client.send(new DescribeTableCommand({ TableName: TABLE_NAME }));
            console.log("✅ Table already exists.");
            return;
        } catch (e) {
            if (e.name !== 'ResourceNotFoundException') throw e;
        }

        // 2. Create Table — jobId as partition key
        await client.send(new CreateTableCommand({
            TableName: TABLE_NAME,
            AttributeDefinitions: [
                { AttributeName: "jobId", AttributeType: "S" }
            ],
            KeySchema: [
                { AttributeName: "jobId", KeyType: "HASH" }
            ],
            BillingMode: "PAY_PER_REQUEST"
        }));

        console.log("⏳ Table creation initiated. Waiting for ACTIVE status...");
        
        let active = false;
        while (!active) {
            const { Table } = await client.send(new DescribeTableCommand({ TableName: TABLE_NAME }));
            if (Table.TableStatus === 'ACTIVE') {
                active = true;
                console.log("✅ Table is now ACTIVE!");
            } else {
                process.stdout.write(".");
                await new Promise(r => setTimeout(r, 2000));
            }
        }

        // 3. Enable TTL on expiresAt attribute (auto-expire jobs after 7 days)
        console.log("⏳ Enabling TTL on 'expiresAt'...");
        await client.send(new UpdateTimeToLiveCommand({
            TableName: TABLE_NAME,
            TimeToLiveSpecification: {
                AttributeName: "expiresAt",
                Enabled: true
            }
        }));
        console.log("✅ TTL enabled on 'expiresAt'.");

        console.log("✨ Provisioning complete!");

    } catch (e) {
        console.error("❌ Provisioning failed:", e.message);
    }
}

provision();
