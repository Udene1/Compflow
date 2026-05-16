import { runScan } from '../core/scanner.js';
import { log } from '../core/logger.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { credentials, provider } = req.body;

    if (!provider || !credentials) {
        return res.status(400).json({ error: 'Missing provider or credentials' });
    }

    try {
        log.info(`API: Dispatching scan request for ${provider.toUpperCase()}`);
        const result = await runScan(provider, credentials);
        
        return res.status(200).json(result);
    } catch (e) {
        log.error(`API: Scan failed for ${provider}:`, e);
        return res.status(500).json({ error: e.message });
    }
}
