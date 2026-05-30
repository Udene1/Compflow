// ─── ComplianceFlow AI: Job Manager ───
// DynamoDB operations for the CompFlowJobsTable

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, UpdateCommand, GetCommand } from "@aws-sdk/lib-dynamodb";
import { randomUUID } from "crypto";

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

const TABLE_NAME = process.env.JOBS_TABLE || "CompFlowJobsTable";
const MAX_LOGS = 200;
const TTL_DAYS = 7;

/**
 * Creates a new job record. Returns the jobId.
 * @param {string} clientId - The tenant/client ID
 * @param {string} scanType - 'on_demand' or 'scheduled'
 * @returns {Promise<string>} jobId
 */
export async function createJob(clientId, scanType = 'on_demand') {
    const jobId = randomUUID();
    const now = new Date().toISOString();
    const expiresAt = Math.floor(Date.now() / 1000) + (TTL_DAYS * 86400);

    await docClient.send(new PutCommand({
        TableName: TABLE_NAME,
        Item: {
            jobId,
            clientId,
            scanType,
            status: 'queued',
            progress: 0,
            logs: [{ timestamp: now, level: 'SYSTEM', message: `Job created (${scanType})` }],
            createdAt: now,
            updatedAt: now,
            expiresAt
        }
    }));

    return jobId;
}

/**
 * Updates job progress, status, and appends a log entry.
 * @param {string} jobId
 * @param {string} status - 'queued' | 'in_progress' | 'completed' | 'failed'
 * @param {number} progress - 0-100
 * @param {string} level - log level
 * @param {string} message - log message
 */
export async function updateJobProgress(jobId, status, progress, level, message) {
    const now = new Date().toISOString();
    const logEntry = { timestamp: now, level, message };

    try {
        await docClient.send(new UpdateCommand({
            TableName: TABLE_NAME,
            Key: { jobId },
            UpdateExpression: 'SET #status = :status, progress = :progress, updatedAt = :now, logs = list_append(if_not_exists(logs, :empty), :log)',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: {
                ':status': status,
                ':progress': progress,
                ':now': now,
                ':log': [logEntry],
                ':empty': []
            }
        }));
    } catch (e) {
        console.error(`[JOBS] Failed to update job ${jobId}:`, e.message);
    }
}

/**
 * Marks a job as completed or failed, stores final resources.
 * @param {string} jobId
 * @param {'completed'|'failed'} status
 * @param {Array} resources - scan results (only on completed)
 * @param {string} [errorMessage] - error message (only on failed)
 */
export async function completeJob(jobId, status, resources = [], errorMessage = null) {
    const now = new Date().toISOString();
    const finalLog = {
        timestamp: now,
        level: status === 'completed' ? 'OUTPUT' : 'INSIGHT',
        message: status === 'completed' 
            ? `Scan completed. ${resources.length} resources found.`
            : `Scan failed: ${errorMessage}`
    };

    const updateExpr = [
        '#status = :status',
        'progress = :progress',
        'updatedAt = :now',
        'completedAt = :now',
        'logs = list_append(if_not_exists(logs, :empty), :log)',
        'resources = :resources'
    ];
    const exprValues = {
        ':status': status,
        ':progress': status === 'completed' ? 100 : -1,
        ':now': now,
        ':log': [finalLog],
        ':empty': [],
        ':resources': resources
    };

    if (errorMessage) {
        updateExpr.push('errorMessage = :err');
        exprValues[':err'] = errorMessage;
    }

    try {
        await docClient.send(new UpdateCommand({
            TableName: TABLE_NAME,
            Key: { jobId },
            UpdateExpression: `SET ${updateExpr.join(', ')}`,
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: exprValues
        }));
    } catch (e) {
        console.error(`[JOBS] Failed to complete job ${jobId}:`, e.message);
    }
}

/**
 * Reads the current state of a job (lightweight).
 * @param {string} jobId
 * @returns {Promise<Object|null>}
 */
export async function getJob(jobId) {
    try {
        const response = await docClient.send(new GetCommand({
            TableName: TABLE_NAME,
            Key: { jobId }
        }));
        return response.Item || null;
    } catch (e) {
        console.error(`[JOBS] Failed to get job ${jobId}:`, e.message);
        return null;
    }
}
