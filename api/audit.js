import { getAuditLogs } from '../core/audit.js';

export default async function handler(req, res) {
    const { clientId } = req.query;
    
    if (!clientId) {
        return res.status(400).json({ error: 'clientId is required' });
    }

    try {
        const logs = await getAuditLogs(clientId);
        return res.status(200).json(logs);
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
}
