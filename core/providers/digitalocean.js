import { log } from '../logger.js';

export async function runScan(provider, credentials) {
    const token = credentials.apiToken;
    if (!token) throw new Error("Missing DigitalOcean API Token");

    const resources = [];
    const baseUrl = "https://api.digitalocean.com/v2";

    try {
        // 1. Droplets
        const dRes = await fetch(`${baseUrl}/droplets`, {
            headers: { "Authorization": `Bearer ${token}` }
        });
        const { droplets } = await dRes.json();
        
        if (droplets) {
            droplets.forEach(d => {
                resources.push({
                    name: d.name,
                    type: 'DO Droplet',
                    icon: '💧',
                    region: d.region.slug,
                    severity: 'pass',
                    control: 'CC6.6',
                    issue: null
                });
            });
        }

        // 2. Firewalls
        const fRes = await fetch(`${baseUrl}/firewalls`, {
            headers: { "Authorization": `Bearer ${token}` }
        });
        const { firewalls } = await fRes.json();

        if (firewalls) {
            firewalls.forEach(f => {
                const isBroad = f.inbound_rules.some(r => r.sources.addresses.includes("0.0.0.0/0"));
                resources.push({
                    name: f.name,
                    type: 'DO Firewall',
                    icon: '🛡️',
                    region: 'Global',
                    severity: isBroad ? 'warning' : 'pass',
                    control: 'CC6.6',
                    issue: isBroad ? 'Open inbound rules detected' : null
                });
            });
        }

        return { resources };
    } catch (e) {
        log.error("DigitalOcean Scan Error:", e);
        throw e;
    }
}
