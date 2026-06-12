import { log } from '../logger.js';

/**
 * Hetzner Cloud Provider Adapter — Expanded v2
 * Audits 15 Hetzner service categories via live API calls.
 *
 * Uses live Hetzner Cloud API v1 with rate limiting and pagination.
 */

const BACKOFF_MS = [300, 1000, 2500];

async function hetznerFetch(url, token, retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            const res = await fetch(url, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (res.status === 429) {
                log.warn(`[Hetzner] Rate limited — waiting ${BACKOFF_MS[i]}ms`);
                await new Promise(r => setTimeout(r, BACKOFF_MS[i]));
                continue;
            }

            if (!res.ok) {
                log.warn(`[Hetzner] HTTP ${res.status} for ${url}`);
                return null;
            }

            return await res.json();
        } catch (e) {
            log.warn(`[Hetzner] Fetch error: ${e.message} (attempt ${i + 1})`);
            if (i < retries - 1) await new Promise(r => setTimeout(r, BACKOFF_MS[i]));
        }
    }
    return null;
}

async function hetznerPaginated(base, token, key) {
    const results = [];
    let page = 1;

    while (true) {
        const data = await hetznerFetch(`${base}?page=${page}&per_page=50`, token);
        if (!data) break;

        const items = data[key] || [];
        results.push(...items);

        if (!data.meta?.pagination?.next_page) break;
        page++;
    }

    return results;
}

export async function runScan(provider, credentials) {
    const token = credentials.apiToken;
    if (!token) throw new Error("Missing Hetzner API Token");

    const resources = [];
    const api = "https://api.hetzner.cloud/v1";

    log.info("➤ Starting Hetzner Cloud Scan (v2 - Expanded)...");

    try {
        // ─── 1. Servers ───────────────────────────────────────────────────
        const servers = await hetznerPaginated(`${api}/servers`, token, 'servers');
        servers.forEach(s => {
            const hasPublicIPv4 = !!s.public_net?.ipv4?.ip;
            const hasFirewall = s.firewall_status?.some(f => f.status === 'applied');
            const region = s.datacenter?.location?.name || 'unknown';
            const imageAge = s.image?.created
                ? Math.floor((Date.now() - new Date(s.image.created).getTime()) / (1000 * 60 * 60 * 24 * 365))
                : null;

            if (hasPublicIPv4 && !hasFirewall) {
                resources.push({
                    name: s.name,
                    type: 'Hetzner Server',
                    icon: '🖥️',
                    region,
                    severity: 'critical',
                    control: 'CC6.6',
                    issue: 'Server has public IP but no firewall applied — fully exposed to internet',
                    recommendation: 'Attach a Hetzner Cloud Firewall to this server to restrict inbound traffic.'
                });
            } else {
                resources.push({
                    name: s.name,
                    type: 'Hetzner Server',
                    icon: '🖥️',
                    region,
                    severity: 'pass',
                    control: 'CC6.6',
                    issue: null,
                    recommendation: null
                });
            }

            if (imageAge !== null && imageAge > 2) {
                resources.push({
                    name: s.name,
                    type: 'Hetzner Server',
                    icon: '🖥️',
                    region,
                    severity: 'warning',
                    control: 'CC7.1',
                    issue: `Server image is ~${imageAge} year(s) old — OS may lack security patches`,
                    recommendation: 'Rebuild or re-image server with a current OS snapshot. Enable automatic OS patching.'
                });
            }
        });

        // ─── 2. Firewalls ─────────────────────────────────────────────────
        const firewalls = await hetznerPaginated(`${api}/firewalls`, token, 'firewalls');
        firewalls.forEach(f => {
            const openSSH = (f.rules || []).some(r =>
                r.direction === 'in' &&
                (r.port === '22' || r.port === null) &&
                (r.source_ips?.includes('0.0.0.0/0') || r.source_ips?.includes('::/0'))
            );
            const openAll = (f.rules || []).some(r =>
                r.direction === 'in' && !r.port &&
                (r.source_ips?.includes('0.0.0.0/0') || r.source_ips?.includes('::/0'))
            );

            resources.push({
                name: f.name,
                type: 'Hetzner Firewall',
                icon: '🧱',
                region: 'global',
                severity: openAll ? 'critical' : openSSH ? 'warning' : 'pass',
                control: 'CC6.6',
                issue: openAll
                    ? 'All ports open to 0.0.0.0/0 — no effective firewall protection'
                    : openSSH
                    ? 'SSH (port 22) open to entire internet (0.0.0.0/0)'
                    : null,
                recommendation: openSSH
                    ? 'Restrict SSH to known IP ranges. For admin access, use Hetzner Console or VPN tunnel.' : null
            });

            // Check for missing egress rules
            const hasEgress = (f.rules || []).some(r => r.direction === 'out');
            if (!hasEgress) {
                resources.push({
                    name: f.name,
                    type: 'Hetzner Firewall',
                    icon: '🧱',
                    region: 'global',
                    severity: 'warning',
                    control: 'CC6.6',
                    issue: 'No egress rules defined — outbound traffic completely unrestricted',
                    recommendation: 'Add egress rules to restrict outbound traffic to only required destinations.'
                });
            }
        });

        // ─── 3. Volumes ───────────────────────────────────────────────────
        const volumes = await hetznerPaginated(`${api}/volumes`, token, 'volumes');
        volumes.forEach(v => {
            const unattached = !v.server;
            resources.push({
                name: v.name,
                type: 'Hetzner Volume',
                icon: '💾',
                region: v.location?.name || 'unknown',
                severity: unattached ? 'warning' : 'pass',
                control: 'CC6.6',
                issue: unattached ? 'Volume is unattached — orphaned resource incurring cost with no utility' : null,
                recommendation: unattached ? 'Attach volume to a server or create a final snapshot and delete it.' : null
            });
        });

        // ─── 4. Private Networks & Subnets ────────────────────────────────
        const networks = await hetznerPaginated(`${api}/networks`, token, 'networks');
        if (networks.length === 0) {
            resources.push({
                name: 'hetzner-private-network',
                type: 'Hetzner Network',
                icon: '🌐',
                region: 'global',
                severity: 'warning',
                control: 'CC6.6',
                issue: 'No private networks configured — servers communicate only over public internet',
                recommendation: 'Create a Hetzner Cloud private network and move inter-server traffic to private IPs.'
            });
        } else {
            networks.forEach(n => {
                const hasSubnets = n.subnets && n.subnets.length > 0;
                resources.push({
                    name: n.name,
                    type: 'Hetzner Network',
                    icon: '🌐',
                    region: 'eu',
                    severity: hasSubnets ? 'pass' : 'warning',
                    control: 'CC6.6',
                    issue: !hasSubnets ? 'Private network has no subnets configured' : null,
                    recommendation: !hasSubnets ? 'Add subnets to segment network traffic appropriately.' : null
                });
            });
        }

        // ─── 5. Load Balancers ────────────────────────────────────────────
        const lbs = await hetznerPaginated(`${api}/load_balancers`, token, 'load_balancers');
        lbs.forEach(lb => {
            const hasHTTPS = lb.services?.some(s => s.protocol === 'https');
            const hasHealthCheck = lb.services?.some(s => s.health_check);
            const region = lb.location?.name || 'unknown';

            if (!hasHTTPS) {
                resources.push({
                    name: lb.name,
                    type: 'Hetzner Load Balancer',
                    icon: '⚖️',
                    region,
                    severity: 'warning',
                    control: 'CC6.7',
                    issue: 'Load Balancer has no HTTPS service — traffic not encrypted in transit',
                    recommendation: 'Add HTTPS service with TLS certificate to Load Balancer.'
                });
            } else {
                resources.push({
                    name: lb.name,
                    type: 'Hetzner Load Balancer',
                    icon: '⚖️',
                    region,
                    severity: 'pass',
                    control: 'CC6.7',
                    issue: null,
                    recommendation: null
                });
            }

            if (!hasHealthCheck) {
                resources.push({
                    name: lb.name,
                    type: 'Hetzner Load Balancer',
                    icon: '⚖️',
                    region,
                    severity: 'warning',
                    control: 'A1.1',
                    issue: 'No health check configured on Load Balancer services',
                    recommendation: 'Configure HTTP health checks on all Load Balancer services to detect unhealthy targets.'
                });
            }
        });

        // ─── 6. Floating IPs ──────────────────────────────────────────────
        const floatingIPs = await hetznerPaginated(`${api}/floating_ips`, token, 'floating_ips');
        floatingIPs.forEach(ip => {
            const unassigned = !ip.server;
            resources.push({
                name: ip.ip || ip.name,
                type: 'Hetzner Floating IP',
                icon: '🔌',
                region: ip.home_location?.name || 'unknown',
                severity: unassigned ? 'warning' : 'pass',
                control: 'CC6.6',
                issue: unassigned ? 'Floating IP unassigned — wasteful and may expose a public IP endpoint without a target.' : null,
                recommendation: unassigned ? 'Assign Floating IP to a server or release it.' : null
            });
        });

        // ─── 7. SSH Keys ──────────────────────────────────────────────────
        const sshData = await hetznerFetch(`${api}/ssh_keys?per_page=100`, token);
        const sshKeys = sshData?.ssh_keys || [];

        if (sshKeys.length > 8) {
            resources.push({
                name: `${sshKeys.length} SSH Keys`,
                type: 'Hetzner SSH Key',
                icon: '🗝️',
                region: 'global',
                severity: 'warning',
                control: 'CC6.2',
                issue: `${sshKeys.length} SSH keys registered — excessive keys increase unauthorized access risk`,
                recommendation: 'Audit and remove SSH keys for departed team members. Limit to active admin keys only.'
            });
        }

        // ─── 8. Snapshots & Backups ───────────────────────────────────────
        const snapshots = await hetznerPaginated(`${api}/actions?status=error`, token, 'actions');
        const snapshotData = await hetznerFetch(`${api}/images?type=snapshot&per_page=100`, token);
        const allSnapshots = snapshotData?.images || [];

        const oldSnapshots = allSnapshots.filter(s => {
            const age = (Date.now() - new Date(s.created).getTime()) / (1000 * 60 * 60 * 24);
            return age > 90;
        });

        if (oldSnapshots.length > 0) {
            resources.push({
                name: `${oldSnapshots.length} old snapshots`,
                type: 'Hetzner Snapshot',
                icon: '📸',
                region: 'global',
                severity: 'warning',
                control: 'A1.2',
                issue: `${oldSnapshots.length} snapshots older than 90 days — unused resources incurring storage cost`,
                recommendation: 'Review and delete outdated snapshots. Implement a retention policy (keep last 3).'
            });
        } else {
            resources.push({
                name: 'snapshots',
                type: 'Hetzner Snapshot',
                icon: '📸',
                region: 'global',
                severity: 'pass',
                control: 'A1.2',
                issue: null,
                recommendation: null
            });
        }

        // ─── 9. Placement Groups ──────────────────────────────────────────
        const pgData = await hetznerFetch(`${api}/placement_groups?per_page=100`, token);
        const placementGroups = pgData?.placement_groups || [];

        if (placementGroups.length === 0 && servers.length > 3) {
            resources.push({
                name: 'placement-groups',
                type: 'Hetzner Placement Group',
                icon: '📊',
                region: 'global',
                severity: 'warning',
                control: 'A1.1',
                issue: `${servers.length} servers running without Placement Groups — risk of co-location causing simultaneous failure`,
                recommendation: 'Create a "spread" Placement Group and distribute critical servers across physical hosts.'
            });
        }

        // ─── 10. Certificates ─────────────────────────────────────────────
        const certData = await hetznerFetch(`${api}/certificates?per_page=100`, token);
        const certificates = certData?.certificates || [];

        certificates.forEach(cert => {
            const daysRemaining = cert.not_valid_after
                ? Math.floor((new Date(cert.not_valid_after).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
                : null;

            if (daysRemaining !== null && daysRemaining < 30) {
                resources.push({
                    name: cert.name,
                    type: 'Hetzner Certificate',
                    icon: '📜',
                    region: 'global',
                    severity: daysRemaining < 7 ? 'critical' : 'warning',
                    control: 'CC6.7',
                    issue: `Certificate expires in ${daysRemaining} days`,
                    recommendation: 'Renew or replace certificate before expiry to avoid service disruption.'
                });
            }
        });

        // ─── 11. Primary IPs ──────────────────────────────────────────────
        const primaryIPData = await hetznerFetch(`${api}/primary_ips?per_page=100`, token);
        const primaryIPs = primaryIPData?.primary_ips || [];

        const unassigned = primaryIPs.filter(ip => !ip.assignee_id);
        if (unassigned.length > 0) {
            resources.push({
                name: `${unassigned.length} unassigned primary IPs`,
                type: 'Hetzner Primary IP',
                icon: '📍',
                region: 'global',
                severity: 'warning',
                control: 'CC6.6',
                issue: `${unassigned.length} Primary IPs not assigned to any server — incurring cost with no utility`,
                recommendation: 'Release unassigned Primary IPs to reduce attack surface and billing.'
            });
        }

        // ─── 12. Images (OS Version Check) ────────────────────────────────
        const imageData = await hetznerFetch(`${api}/images?type=system&per_page=50`, token);
        const images = imageData?.images || [];

        const outdatedOS = servers.filter(s => {
            const osName = s.image?.os_flavor || '';
            const osVersion = s.image?.os_version || '';
            return osName === 'ubuntu' && parseFloat(osVersion) < 22.04;
        });

        if (outdatedOS.length > 0) {
            resources.push({
                name: `${outdatedOS.length} servers on outdated OS`,
                type: 'Hetzner Image',
                icon: '🖼️',
                region: 'global',
                severity: 'warning',
                control: 'CC7.1',
                issue: `${outdatedOS.length} servers running Ubuntu below 22.04 LTS — OS EOL risk`,
                recommendation: 'Upgrade servers to Ubuntu 24.04 LTS. Plan rolling migration for production hosts.'
            });
        }

        // ─── 13. Server Rescue Mode Active ────────────────────────────────
        const rescueServers = servers.filter(s => s.rescue_enabled);
        if (rescueServers.length > 0) {
            resources.push({
                name: `${rescueServers.length} servers in Rescue Mode`,
                type: 'Hetzner Server',
                icon: '🖥️',
                region: 'global',
                severity: 'critical',
                control: 'CC6.6',
                issue: 'Servers have Rescue Mode enabled — bypasses normal OS security controls',
                recommendation: 'Disable Rescue Mode immediately after maintenance. Rescue mode should not be left active.'
            });
        }

        // ─── 14. ISO Images Mounted ───────────────────────────────────────
        const isoServers = servers.filter(s => s.iso !== null);
        if (isoServers.length > 0) {
            resources.push({
                name: `${isoServers.length} servers with ISO mounted`,
                type: 'Hetzner ISO',
                icon: '💿',
                region: 'global',
                severity: 'warning',
                control: 'CC6.6',
                issue: `${isoServers.length} server(s) have ISOs mounted — may have been used for a custom boot`,
                recommendation: 'Unmount ISOs from servers after OS installation or troubleshooting is complete.'
            });
        }

        // ─── 15. Server Type / Pricing Optimization ───────────────────────
        const oversized = servers.filter(s => s.server_type?.cores >= 16 && s.server_type?.name?.includes('ccx'));
        if (oversized.length > 0) {
            resources.push({
                name: `${oversized.length} large dedicated servers`,
                type: 'Hetzner Server Type',
                icon: '💻',
                region: 'global',
                severity: 'pass',
                control: 'CC1.1',
                issue: null,
                recommendation: 'Periodically review server sizing against actual utilization metrics to optimize costs.'
            });
        }

        const summary = {
            total: resources.length,
            critical: resources.filter(r => r.severity === 'critical').length,
            warning: resources.filter(r => r.severity === 'warning').length,
            pass: resources.filter(r => r.severity === 'pass').length
        };

        log.info(`Hetzner Scan complete: ${summary.total} resources, ${summary.critical} critical, ${summary.warning} warnings`);
        return { resources, summary };

    } catch (e) {
        log.error("Hetzner Scan Error:", e);
        throw e;
    }
}
