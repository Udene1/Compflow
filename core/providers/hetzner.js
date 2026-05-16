import { log } from '../logger.js';

export async function runScan(provider, credentials) {
    const token = credentials.apiToken;
    if (!token) throw new Error("Missing Hetzner API Token");

    const resources = [];
    const baseUrl = "https://api.hetzner.cloud/v1";

    try {
        // 1. Scan Servers
        const serversRes = await fetch(`${baseUrl}/servers`, {
            headers: { "Authorization": `Bearer ${token}` }
        });
        const { servers } = await serversRes.json();

        if (servers) {
            servers.forEach(s => {
                resources.push({
                    name: s.name,
                    type: 'Hetzner Server',
                    icon: '🖥️',
                    region: s.datacenter.location.name,
                    severity: 'pass',
                    control: 'CC6.6',
                    issue: null
                });
            });
        }

        // 2. Scan Firewalls (Critical for Compliance)
        const fwRes = await fetch(`${baseUrl}/firewalls`, {
            headers: { "Authorization": `Bearer ${token}` }
        });
        const { firewalls } = await fwRes.json();

        if (firewalls) {
            firewalls.forEach(f => {
                const hasBroadRules = f.rules.some(r => r.source_ips.includes("0.0.0.0/0") && (r.port === "22" || !r.port));
                resources.push({
                    name: f.name,
                    type: 'Hetzner Firewall',
                    icon: '🧱',
                    region: 'Global',
                    severity: hasBroadRules ? 'warning' : 'pass',
                    control: 'CC6.6',
                    issue: hasBroadRules ? 'Inbound rule permits 0.0.0.0/0 on sensitive ports' : null
                });
            });
        }

        return { resources };
    } catch (e) {
        log.error("Hetzner Scan Error:", e);
        throw e;
    }
}
