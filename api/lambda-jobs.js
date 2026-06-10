import { getJobHistory, getJob } from '../core/jobs.js';

export const handler = async (event) => {
    const isApiGateway = !!event.httpMethod;
    const body = isApiGateway ? JSON.parse(event.body || '{}') : event;
    const { clientId, jobId, action } = body;

    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
    };

    if (isApiGateway && event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        if (action === 'history') {
            if (!clientId) throw new Error('Missing clientId');
            const history = await getJobHistory(clientId);
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ history })
            };
        }

        if (action === 'details') {
            if (!jobId) throw new Error('Missing jobId');
            const job = await getJob(jobId);
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ job })
            };
        }

        return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid action' })
        };

    } catch (e) {
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: e.message })
        };
    }
};
