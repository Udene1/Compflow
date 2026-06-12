import { log } from '../logger.js';

/**
 * DigitalOcean Provider Adapter — Expanded v2
 * Audits 15 DigitalOcean service categories via live API calls.
 * 
 * Uses live DigitalOcean API v2 with proper rate limiting, pagination,
 * and exponential backoff retry logic.
 */

const BACKOFF_MS = [500, 1500, 3000];

async function doFetch(url, token, retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            const res = await fetch(url, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (res.status === 429) {
                log.warn(`[DO] Rate limited — waiting ${BACKOFF_MS[i]}ms`);
                await new Promise(r => setTimeout(r, BACKOFF_MS[i]));
                continue;
            }

            if (!res.ok) {
                log.warn(`[DO] HTTP ${res.status} for ${url}`);
                return null;
            }

            return await res.json();
        } catch (e) {
            log.warn(`[DO] Fetch error: ${e.message} (attempt ${i + 1})`);
            if (i < retries - 1) await new Promise(r => setTimeout(r, BACKOFF_MS[i]));
        }
    }
    return null;
}

async function fetchPaginated(baseUrl, token, key) {
    const results = [];
    let url = baseUrl;

    while (url) {
        const data = await doFetch(url, token);
        if (!data) break;

        const items = data[key];
        if (items) results.push(...items);

        url = data.links?.pages?.next || null;
    }

    return results;
}

export async function runScan(provider, credentials) {
    const token = credentials.apiToken;
    if (!token) throw new Error("Missing DigitalOcean API Token");

    const resources = [];
    const api = "https://api.digitalocean.com/v2";

    log.info("➤ Starting DigitalOcean Hyperscale Scan (v2 - Expanded)...");

    try {
        // ─── 1. Droplets ──────────────────────────────────────────────────
        const droplets = await fetchPaginated(`${api}/droplets?per_page=100`, token, 'droplets');
        droplets.forEach(d => {
            const hasPublicIPv4 = d.networks?.v4?.some(n => n.type === 'public');
            const hasMonitoring = d.features?.includes('monitoring');
            const hasBackups = d.features?.includes('backups');
            const region = d.region?.slug || 'unknown';

            resources.push({
                name: d.name,
                type: 'DO Droplet',
                icon: '💧',
                region,
                severity: hasPublicIPv4 && !hasMonitoring ? 'warning' : 'pass',
                control: 'CC6.6',
                issue: hasPublicIPv4 && !hasMonitoring ? 'Public IP assigned with no monitoring agent configured' : null,
                recommendation: hasPublicIPv4 && !hasMonitoring
                    ? 'Enable DigitalOcean monitoring agent on this Droplet for metrics and alerting.' : null
            });

            if (!hasBackups) {
                resources.push({
                    name: d.name,
                    type: 'DO Droplet',
                    icon: '💧',
                    region,
                    severity: 'warning',
                    control: 'A1.2',
                    issue: 'Automated backups not enabled — data loss risk',
                    recommendation: 'Enable automated weekly backups on this Droplet.'
                });
            }
        });

        // ─── 2. Firewalls ─────────────────────────────────────────────────
        const firewalls = await fetchPaginated(`${api}/firewalls`, token, 'firewalls') || [];
        firewalls.forEach(f => {
            const openSSH = (f.inbound_rules || []).some(r =>
                r.protocol === 'tcp' && (r.ports === '22' || r.ports === 'all') &&
                (r.sources?.addresses?.includes('0.0.0.0/0') || r.sources?.addresses?.includes('::/0'))
            );
            const openAll = (f.inbound_rules || []).some(r =>
                r.protocol === 'tcp' && r.ports === 'all' &&
                r.sources?.addresses?.some(a => a === '0.0.0.0/0' || a === '::/0')
            );

            resources.push({
                name: f.name,
                type: 'DO Firewall',
                icon: '🛡️',
                region: 'global',
                severity: openAll ? 'critical' : openSSH ? 'warning' : 'pass',
                control: 'CC6.6',
                issue: openAll
                    ? 'All ports open to 0.0.0.0/0 — completely unrestricted inbound traffic'
                    : openSSH ? 'SSH (port 22) open to entire internet (0.0.0.0/0)' : null,
                recommendation: openSSH
                    ? 'Restrict SSH to specific IP addresses or VPN ranges only.' : null
            });
        });

        // ─── 3. Spaces (Object Storage) ───────────────────────────────────
        const spacesData = await doFetch(`${api}/spaces`, token);
        const spaces = spacesData?.spaces || [];
        spaces.forEach(s => {
            resources.push({
                name: s.name,
                type: 'DO Spaces',
                icon: '🪣',
                region: s.region || 'unknown',
                severity: s.is_public ? 'critical' : 'pass',
                control: 'CC6.1',
                issue: s.is_public ? 'Space bucket is publicly accessible — objects readable without authentication' : null,
                recommendation: s.is_public
                    ? 'Disable public ACL on Space. Restrict access to signed URLs or private IAM policies.' : null
            });
        });

        // ─── 4. Managed Databases ─────────────────────────────────────────
        const dbData = await doFetch(`${api}/databases?per_page=100`, token);
        const databases = dbData?.databases || [];
        databases.forEach(db => {
            const hasTrustedSources = db.rules && db.rules.length > 0;
            const region = db.region || 'unknown';

            resources.push({
                name: db.name,
                type: 'DO Database',
                icon: '🗃️',
                region,
                severity: !hasTrustedSources ? 'critical' : 'pass',
                control: 'CC6.6',
                issue: !hasTrustedSources ? 'No trusted sources configured — database accessible from any IP' : null,
                recommendation: !hasTrustedSources
                    ? 'Add trusted source IPs/CIDR ranges to restrict database network access.' : null
            });

            if (!db.maintenance_window) {
                resources.push({
                    name: db.name,
                    type: 'DO Database',
                    icon: '🗃️',
                    region,
                    severity: 'warning',
                    control: 'A1.2',
                    issue: 'No maintenance window configured — automated backups may be unpredictable',
                    recommendation: 'Set a maintenance window during low-traffic hours for controlled updates.'
                });
            }
        });

        // ─── 5. Kubernetes Clusters (DOKS) ────────────────────────────────
        const k8sData = await doFetch(`${api}/kubernetes/clusters?per_page=100`, token);
        const clusters = k8sData?.kubernetes_clusters || [];
        clusters.forEach(c => {
            const region = c.region || 'unknown';
            const autoUpgrade = c.auto_upgrade;
            const surgeUpgrade = c.surge_upgrade;

            resources.push({
                name: c.name,
                type: 'DO Kubernetes',
                icon: '☸️',
                region,
                severity: !autoUpgrade ? 'warning' : 'pass',
                control: 'CC7.1',
                issue: !autoUpgrade ? 'Auto-upgrade disabled — cluster may run outdated Kubernetes version' : null,
                recommendation: !autoUpgrade
                    ? 'Enable auto-upgrade to keep control plane and node pools on supported Kubernetes versions.' : null
            });

            if (!surgeUpgrade) {
                resources.push({
                    name: c.name,
                    type: 'DO Kubernetes',
                    icon: '☸️',
                    region,
                    severity: 'warning',
                    control: 'CC8.1',
                    issue: 'Surge upgrade disabled — upgrades may cause downtime',
                    recommendation: 'Enable surge upgrades to roll new nodes before removing old ones during upgrades.'
                });
            }
        });

        // ─── 6. Load Balancers ────────────────────────────────────────────
        const lbData = await doFetch(`${api}/load_balancers?per_page=100`, token);
        const loadBalancers = lbData?.load_balancers || [];
        loadBalancers.forEach(lb => {
            const hasHTTPS = lb.forwarding_rules?.some(r => r.entry_protocol === 'https');
            const hasHTTP = lb.forwarding_rules?.some(r => r.entry_protocol === 'http');
            const redirectsHTTPS = lb.redirect_http_to_https;
            const region = lb.region?.slug || 'unknown';

            resources.push({
                name: lb.name,
                type: 'DO Load Balancer',
                icon: '⚖️',
                region,
                severity: hasHTTP && !redirectsHTTPS ? 'warning' : 'pass',
                control: 'CC6.7',
                issue: hasHTTP && !redirectsHTTPS ? 'HTTP listener active without HTTPS redirect — traffic not encrypted in transit' : null,
                recommendation: hasHTTP && !redirectsHTTPS
                    ? 'Enable redirect_http_to_https=true on Load Balancer.' : null
            });

            if (!hasHTTPS) {
                resources.push({
                    name: lb.name,
                    type: 'DO Load Balancer',
                    icon: '⚖️',
                    region,
                    severity: 'critical',
                    control: 'CC6.7',
                    issue: 'No HTTPS forwarding rule configured — all traffic unencrypted',
                    recommendation: 'Add HTTPS forwarding rule with a valid SSL certificate.'
                });
            }
        });

        // ─── 7. VPC Networks ──────────────────────────────────────────────
        const vpcData = await doFetch(`${api}/vpcs?per_page=100`, token);
        const vpcs = vpcData?.vpcs || [];
        vpcs.forEach(v => {
            resources.push({
                name: v.name,
                type: 'DO VPC',
                icon: '🌐',
                region: v.region || 'unknown',
                severity: v.default ? 'warning' : 'pass',
                control: 'CC6.6',
                issue: v.default ? 'Using default VPC — resources may not be properly isolated' : null,
                recommendation: v.default
                    ? 'Create a custom VPC with proper IP range planning for production workloads.' : null
            });
        });

        // ─── 8. Floating IPs ──────────────────────────────────────────────
        const fipData = await doFetch(`${api}/floating_ips?per_page=100`, token);
        const floatingIPs = fipData?.floating_ips || [];
        floatingIPs.forEach(ip => {
            const unassigned = !ip.droplet;
            resources.push({
                name: ip.ip,
                type: 'DO Floating IP',
                icon: '🔌',
                region: ip.region?.slug || 'unknown',
                severity: unassigned ? 'warning' : 'pass',
                control: 'CC6.6',
                issue: unassigned ? 'Floating IP not assigned to any Droplet — incurring cost with no utility' : null,
                recommendation: unassigned
                    ? 'Assign Floating IP to a Droplet or release it to reduce unnecessary exposure and billing.' : null
            });
        });

        // ─── 9. Snapshots ────────────────────────────────────────────────
        const snapshotData = await doFetch(`${api}/snapshots?per_page=100`, token);
        const snapshots = snapshotData?.snapshots || [];
        const oldSnapshots = snapshots.filter(s => {
            const age = (Date.now() - new Date(s.created_at).getTime()) / (1000 * 60 * 60 * 24);
            return age > 90;
        });

        if (oldSnapshots.length > 0) {
            resources.push({
                name: `${oldSnapshots.length} old snapshots`,
                type: 'DO Snapshot',
                icon: '📸',
                region: 'global',
                severity: 'warning',
                control: 'A1.2',
                issue: `${oldSnapshots.length} snapshots older than 90 days — potential storage cost waste`,
                recommendation: 'Review and delete snapshots older than 90 days. Implement retention policy.'
            });
        }

        // ─── 10. SSH Keys ─────────────────────────────────────────────────
        const sshData = await doFetch(`${api}/account/keys?per_page=100`, token);
        const sshKeys = sshData?.ssh_keys || [];

        if (sshKeys.length > 5) {
            resources.push({
                name: `${sshKeys.length} SSH keys registered`,
                type: 'DO SSH Key',
                icon: '🗝️',
                region: 'global',
                severity: 'warning',
                control: 'CC6.2',
                issue: `${sshKeys.length} SSH keys in account — excessive keys increase unauthorized access risk`,
                recommendation: 'Audit and remove SSH keys for departed team members. Implement key rotation policy.'
            });
        }

        // ─── 11. Container Registry ───────────────────────────────────────
        const regData = await doFetch(`${api}/registry`, token);
        if (regData?.registry) {
            const reg = regData.registry;
            resources.push({
                name: reg.name,
                type: 'DO Container Registry',
                icon: '📦',
                region: reg.region || 'global',
                severity: 'pass',
                control: 'CC6.6',
                issue: null,
                recommendation: null
            });
        }

        // ─── 12. Monitoring Alerts ────────────────────────────────────────
        const alertData = await doFetch(`${api}/monitoring/alerts?per_page=100`, token);
        const alerts = alertData?.policies || [];

        if (alerts.length === 0) {
            resources.push({
                name: 'monitoring-alerts',
                type: 'DO Monitoring',
                icon: '🚨',
                region: 'global',
                severity: 'warning',
                control: 'CC7.2',
                issue: 'No monitoring alert policies configured — resource failures will go undetected',
                recommendation: 'Create alert policies for CPU, memory, disk usage, and network anomalies on all Droplets.'
            });
        }

        // ─── 13. Domains & DNS Records ────────────────────────────────────
        const domainData = await fetchPaginated(`${api}/domains?per_page=100`, token, 'domains');
        domainData.forEach(d => {
            resources.push({
                name: d.name,
                type: 'DO Domain',
                icon: '🔗',
                region: 'global',
                severity: 'pass',
                control: 'CC6.6',
                issue: null,
                recommendation: null
            });
        });

        // ─── 14. App Platform Apps ─────────────────────────────────────────
        const appData = await doFetch(`${api}/apps?per_page=100`, token);
        const apps = appData?.apps || [];
        apps.forEach(app => {
            const hasEnvVarSecrets = (app.spec?.services || []).some(s =>
                (s.envs || []).some(e => e.type !== 'SECRET' && /key|password|secret|token/i.test(e.key))
            );

            resources.push({
                name: app.spec?.name || app.id,
                type: 'DO App Platform',
                icon: '🚀',
                region: app.region?.label || 'unknown',
                severity: hasEnvVarSecrets ? 'warning' : 'pass',
                control: 'CC6.7',
                issue: hasEnvVarSecrets ? 'Possible secrets in plaintext environment variables (non-SECRET type)' : null,
                recommendation: hasEnvVarSecrets
                    ? 'Mark sensitive env vars as type=SECRET in App Platform configuration.' : null
            });
        });

        // ─── 15. Account Team Members ──────────────────────────────────────
        const teamData = await doFetch(`${api}/teams/members`, token);
        if (teamData) {
            const members = teamData.members || [];
            const owners = members.filter(m => m.role === 'owner');
            if (owners.length > 2) {
                resources.push({
                    name: `${owners.length} team owners`,
                    type: 'DO Account',
                    icon: '👤',
                    region: 'global',
                    severity: 'warning',
                    control: 'CC6.2',
                    issue: `${owners.length} team members have Owner role — excessive privilege`,
                    recommendation: 'Limit Owner access to 1–2 admins. Assign Member or custom roles to others.'
                });
            }
        }

        const summary = {
            total: resources.length,
            critical: resources.filter(r => r.severity === 'critical').length,
            warning: resources.filter(r => r.severity === 'warning').length,
            pass: resources.filter(r => r.severity === 'pass').length
        };

        log.info(`DigitalOcean Scan complete: ${summary.total} resources, ${summary.critical} critical, ${summary.warning} warnings`);
        return { resources, summary };

    } catch (e) {
        log.error("DigitalOcean Scan Error:", e);
        throw e;
    }
}
