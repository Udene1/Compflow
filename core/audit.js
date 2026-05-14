import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({ 
    region: process.env.AWS_REGION || "us-east-1",
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY
    }
});
const docClient = DynamoDBDocumentClient.from(client);

const TABLE_NAME = "ComplianceFlowAudit";

export async function saveAuditLog(clientId, level, message, details = {}) {
    try {
        await docClient.send(new PutCommand({
            TableName: TABLE_NAME,
            Item: {
                clientId,
                timestamp: new Date().toISOString(),
                level,
                message,
                details
            }
        }));
    } catch (e) {
        console.error("Audit Log Failure:", e);
    }
}

export async function getAuditLogs(clientId, limit = 50) {
    try {
        const response = await docClient.send(new QueryCommand({
            TableName: TABLE_NAME,
            KeyConditionExpression: "clientId = :id",
            ExpressionAttributeValues: { ":id": clientId },
            ScanIndexForward: false, // Latest first
            Limit: limit
        }));
        return response.Items || [];
    } catch (e) {
        console.error("Fetch Audit Logs Failure:", e);
        return [];
    }
}
