import { getAuditLogs } from '../core/audit.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return res.status(405).end();

    const { clientId } = req.query;
    if (!clientId) return res.status(400).json({ error: "Missing clientId" });

    try {
        const logs = await getAuditLogs(clientId);
        return res.status(200).json({ logs });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
}
