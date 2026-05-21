/**
 * Vercel Scan Proxy
 * Forwards scan requests to the Lambda backend where the full 15-minute
 * timeout is available for enumerating 22+ AWS services.
 */
export const maxDuration = 60;

export default async function handler(req, res) {
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const LAMBDA_API_URL = process.env.LAMBDA_API_URL;

    if (!LAMBDA_API_URL) {
        return res.status(503).json({
            error: 'Backend not configured. Set LAMBDA_API_URL in Vercel environment variables.'
        });
    }

    try {
        const lambdaResponse = await fetch(`${LAMBDA_API_URL}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });

        const data = await lambdaResponse.json();
        return res.status(lambdaResponse.status).json(data);
    } catch (e) {
        console.error('[SCAN-PROXY] Failed to reach Lambda backend:', e);
        return res.status(502).json({
            error: 'Could not reach the scanning backend. Please try again later.'
        });
    }
}
