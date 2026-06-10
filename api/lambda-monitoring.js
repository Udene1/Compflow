import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand, ScanCommand } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

const JOBS_TABLE = "CompFlowJobsTable";

export const handler = async (event) => {
    try {
        const { clientId = 'default' } = JSON.parse(event.body || '{}');

        // 1. Get recent jobs (last 24h approximation via Scan - in prod use GSI)
        const recentJobs = await docClient.send(new ScanCommand({
            TableName: JOBS_TABLE,
            Limit: 50
        }));

        const items = recentJobs.Items || [];
        const total = items.length;
        const failed = items.filter(i => i.status === 'FAILED');
        const successRate = total > 0 ? ((total - failed.length) / total * 100).toFixed(0) : 100;

        return {
            statusCode: 200,
            headers: { "Access-Control-Allow-Origin": "*" },
            body: JSON.stringify({
                totalJobs: total,
                successRate: `${successRate}%`,
                failedCount: failed.length,
                failures: failed.slice(0, 10).map(f => ({
                    time: f.startedAt,
                    provider: f.provider,
                    action: f.action,
                    error: f.message || 'Unknown error',
                    status: f.status
                }))
            })
        };
    } catch (e) {
        return {
            statusCode: 500,
            headers: { "Access-Control-Allow-Origin": "*" },
            body: JSON.stringify({ error: e.message })
        };
    }
};
