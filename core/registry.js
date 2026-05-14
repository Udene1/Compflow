import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, ScanCommand, PutCommand, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({ 
    region: process.env.AWS_REGION || "us-east-1",
    credentials: {
        accessKeyId: process.env.PLATFORM_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.PLATFORM_AWS_SECRET_ACCESS_KEY
    }
});
const docClient = DynamoDBDocumentClient.from(client);

const TABLE_NAME = "ComplianceFlowClients";

/**
 * Loads all clients from the DynamoDB registry.
 */
export async function loadClients() {
    try {
        const command = new ScanCommand({ TableName: TABLE_NAME });
        const response = await docClient.send(command);
        return response.Items || [];
    } catch (e) {
        console.error("[REGISTRY] Failed to load clients from DynamoDB:", e.message);
        // Fallback or rethrow? 
        // For now, we return empty so the agent doesn't crash but logs the error.
        return [];
    }
}

/**
 * Adds or updates a client in the registry.
 */
export async function saveClient(clientData) {
    try {
        const command = new PutCommand({
            TableName: TABLE_NAME,
            Item: {
                ...clientData,
                updatedAt: new Date().toISOString()
            }
        });
        await docClient.send(command);
        console.log(`[REGISTRY] Client ${clientData.name} saved successfully.`);
    } catch (e) {
        console.error(`[REGISTRY] Failed to save client ${clientData.name}:`, e.message);
        throw e;
    }
}

/**
 * Gets a specific client by ID.
 */
export async function getClient(clientId) {
    try {
        const command = new GetCommand({
            TableName: TABLE_NAME,
            Key: { id: clientId }
        });
        const response = await docClient.send(command);
        return response.Item;
    } catch (e) {
        console.error(`[REGISTRY] Failed to get client ${clientId}:`, e.message);
        return null;
    }
}
