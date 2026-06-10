import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, GetCommand, UpdateCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { log } from './logger.js';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

const JOBS_TABLE = "CompFlowJobsTable";

/**
 * Monitoring System for ComplianceFlow
 * Tracks remediation jobs, failures, and execution times.
 */
export const Monitoring = {
    /**
     * Start a new job entry
     */
    async logJobStart(jobId, clientId, provider, action) {
        try {
            await docClient.send(new PutCommand({
                TableName: JOBS_TABLE,
                Item: {
                    id: jobId,
                    clientId: clientId,
                    provider: provider,
                    action: action,
                    status: 'PENDING',
                    startedAt: new Date().toISOString(),
                    expiresAt: Math.floor(Date.now() / 1000) + (86400 * 7) // 7 day TTL
                }
            }));
            log.info(`[MONITOR] Job ${jobId} initiated for ${provider}`);
        } catch (e) {
            log.error("Failed to log job start:", e);
        }
    },

    /**
     * Complete a job with status and message
     */
    async logJobComplete(jobId, success, message, details = {}) {
        try {
            await docClient.send(new UpdateCommand({
                TableName: JOBS_TABLE,
                Key: { id: jobId },
                UpdateExpression: "SET #status = :s, #msg = :m, #endedAt = :e, #details = :d",
                ExpressionAttributeNames: {
                    "#status": "status",
                    "#msg": "message",
                    "#endedAt": "endedAt",
                    "#details": "details"
                },
                ExpressionAttributeValues: {
                    ":s": success ? 'COMPLETED' : 'FAILED',
                    ":m": message,
                    ":e": new Date().toISOString(),
                    ":d": details
                }
            }));
            log.info(`[MONITOR] Job ${jobId} ${success ? 'succeeded' : 'failed'}`);
        } catch (e) {
            log.error("Failed to update job status:", e);
        }
    },

    /**
     * Get recent failures for a client
     */
    async getFailedJobs(clientId, limit = 10) {
        try {
            const result = await docClient.send(new QueryCommand({
                TableName: JOBS_TABLE,
                IndexName: "clientId-index", // Assumes GSI exists or we query via filter
                KeyConditionExpression: "clientId = :c",
                FilterExpression: "#status = :s",
                ExpressionAttributeNames: { "#status": "status" },
                ExpressionAttributeValues: { 
                    ":c": clientId,
                    ":s": 'FAILED'
                },
                Limit: limit,
                ScanIndexForward: false
            }));
            return result.Items || [];
        } catch (e) {
            log.error("Failed to fetch jobs:", e);
            return [];
        }
    },

    /**
     * Standardize error messages for users
     */
    standardizeError(error, provider) {
        const msg = error.message || String(error);
        
        if (msg.includes('credentials') || msg.includes('401') || msg.includes('403')) {
            return `Authentication missing or invalid for ${provider}. Please verify your Connection Settings.`;
        }
        if (msg.includes('Rate limit') || msg.includes('429')) {
            return `${provider} rate limit exceeded. Retrying in 60 seconds...`;
        }
        if (msg.includes('timeout') || msg.includes('ETIMEDOUT')) {
            return `Connection to ${provider} timed out. The resource might be undergoing maintenance.`;
        }
        if (msg.includes('not found') || msg.includes('404')) {
            return `Resource no longer exists in ${provider}. Marking as ghost record.`;
        }
        
        return `Unexpected ${provider} error: ${msg}`;
    }
};
