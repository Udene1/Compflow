import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";

const clientConfig = {
    region: process.env.AWS_REGION || "us-east-1"
};

if (process.env.PLATFORM_AWS_ACCESS_KEY_ID && process.env.PLATFORM_AWS_SECRET_ACCESS_KEY) {
    clientConfig.credentials = {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY
    };
}

const client = new DynamoDBClient(clientConfig);
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.AUDIT_TABLE || "CompFlowAuditTable";

function assertClientId(clientId) {
    if (typeof clientId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(clientId)) {
        throw new Error("Invalid audit client identifier");
    }
}

function sanitizeDetails(details = {}) {
    if (!details || typeof details !== "object" || Array.isArray(details)) return {};
    const clean = {};
    const sensitive = /authorization|token|secret|password|credential|private[_-]?key|api[_-]?key/i;
    for (const [key, value] of Object.entries(details)) {
        if (sensitive.test(key)) continue;
        if (typeof value === "string") clean[key] = value.length > 500 ? `${value.slice(0, 500)}...[truncated]` : value;
        else if (value === null || typeof value === "number" || typeof value === "boolean") clean[key] = value;
    }
    return clean;
}

export async function saveAuditLog(clientId, level, message, details = {}) {
    assertClientId(clientId);
    if (typeof message !== "string" || message.length < 1 || message.length > 1000) {
        throw new Error("Invalid audit message");
    }
    await docClient.send(new PutCommand({
        TableName: TABLE_NAME,
        Item: {
            clientId,
            timestamp: new Date().toISOString(),
            level: typeof level === "string" && level.length <= 32 ? level : "info",
            message,
            details: sanitizeDetails(details)
        },
        ConditionExpression: "attribute_not_exists(clientId) AND attribute_not_exists(#ts)",
        ExpressionAttributeNames: { "#ts": "timestamp" }
    }));
}

export async function getAuditLogs(clientId, limit = 50) {
    assertClientId(clientId);
    const safeLimit = Number.isInteger(limit) ? Math.min(Math.max(limit, 1), 100) : 50;
    const response = await docClient.send(new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: "clientId = :id",
        ExpressionAttributeValues: { ":id": clientId },
        ScanIndexForward: false,
        Limit: safeLimit
    }));
    return response.Items || [];
}
