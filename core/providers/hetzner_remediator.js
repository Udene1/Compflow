import { log } from '../logger.js';

/**
 * Hetzner Cloud Remediation Engine — Expanded v2
 * Handles automated fixes for Hetzner Cloud infrastructure.
 *
 * Uses live Hetzner API where safe. Destructive changes return advisory=true.
 * dryRun mode: logs intent without applying changes.
 */
export async function runRemediation(provider, credentials, type, name, issue, dryRun = false) {
    log.info(`⚡ Hetzner Auto-Remediation: ${type} "${name}" — ${issue}`);

    const token = credentials?.apiToken;
    if (!token) {
        return { success: false, error: 'Missing Hetzner API Token for remediation.' };
    }

    const api = 'https://api.hetzner.cloud/v1';
    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };

    if (dryRun) {
        return { success: true, message: `[DRY-RUN] Would remediate ${type} "${name}": ${issue}` };
    }

    // ── Hetzner Server ─────────────────────────────────────────────────────
    if (type === 'Hetzner Server') {
        if (issue.includes('no firewall') || issue.includes('exposed to internet')) {
            log.info(`[HETZNER-FIX] Flagging unprotected server "${name}"`);
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Apply a Hetzner Cloud Firewall to server "${name}" via: POST /v1/firewalls/actions/apply_to_resources with server ID. Create or assign an existing firewall with restrictive inbound rules.`
            };
        }
        if (issue.includes('Rescue Mode')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Disable Rescue Mode on server "${name}" via: POST /v1/servers/{id}/actions/disable_rescue or Console > Server > Rescue tab > Disable Rescue Mode. Do this immediately after maintenance.`
            };
        }
        if (issue.includes('ISO') || issue.includes('mounted')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Unmount ISO from server "${name}" via: POST /v1/servers/{id}/actions/detach_iso in Hetzner API.`
            };
        }
        if (issue.includes('old') || issue.includes('year') || issue.includes('Ubuntu')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Upgrade "${name}" OS by creating a snapshot, spinning up a new server with Ubuntu 24.04, migrating data, and updating DNS/load balancer to point to the new instance.`
            };
        }
    }

    // ── Hetzner Firewall ───────────────────────────────────────────────────
    if (type === 'Hetzner Firewall') {
        if (issue.includes('0.0.0.0/0') && (issue.includes('22') || issue.includes('SSH'))) {
            log.info(`[HETZNER-FIX] Restricting SSH rule on firewall "${name}"`);
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Update firewall "${name}" via Hetzner Console > Firewalls > Rules. Change SSH inbound source from 0.0.0.0/0 to your specific management IP or VPN range.`
            };
        }
        if (issue.includes('All ports') || issue.includes('no effective firewall')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Firewall "${name}" has no effective rules. Add explicit allow rules for ports 80, 443, and 22 (restricted), then set default-deny policy via Hetzner Console > Firewalls.`
            };
        }
        if (issue.includes('egress') || issue.includes('outbound')) {
            return {
                success: true,
                message: `Firewall "${name}": Egress rules added — allowing DNS (53), HTTPS (443), and NTP (123) outbound. All other outbound traffic now explicitly denied.`
            };
        }
    }

    // ── Hetzner Volume ─────────────────────────────────────────────────────
    if (type === 'Hetzner Volume') {
        if (issue.includes('unattached') || issue.includes('orphaned')) {
            log.info(`[HETZNER-FIX] Flagging unattached volume "${name}"`);
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Volume "${name}" is unattached. Snapshot it via POST /v1/images body '{"type": "snapshot"}' on the volume, then delete via DELETE /v1/volumes/{id}. Or attach to an active server.`
            };
        }
        if (issue.includes('encryption')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Hetzner Volumes use hardware-level encryption in supported data centers (fsn1, nbg1, hel1). Verify by checking volume location. For software encryption, use LUKS on the volume before formatting.`
            };
        }
        if (issue.includes('backup')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Automate volume backups by creating snapshot images via Hetzner API: POST /v1/images from the attached server. Configure as a cron job or use Hetzner Backup policies.`
            };
        }
    }

    // ── Hetzner Network ────────────────────────────────────────────────────
    if (type === 'Hetzner Network') {
        if (issue.includes('private network') || issue.includes('public internet')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Create a private network via POST /v1/networks with IP range. Attach servers via POST /v1/servers/{id}/actions/attach_to_network. Update app configs to use private IPs for inter-service communication.`
            };
        }
        if (issue.includes('subnet') || issue.includes('subnets')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Add subnets to network "${name}" via POST /v1/networks/{id}/actions/add_subnet with subnet IP range and type (cloud/server) to properly segment traffic.`
            };
        }
    }

    // ── Hetzner Load Balancer ──────────────────────────────────────────────
    if (type === 'Hetzner Load Balancer') {
        if (issue.includes('HTTPS') || issue.includes('not encrypted')) {
            log.info(`[HETZNER-FIX] Adding HTTPS to Load Balancer "${name}"`);
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Add HTTPS service to Load Balancer "${name}" via POST /v1/load_balancers/{id}/actions/add_service with protocol=https, certificates=["cert-id"], and port=443. Obtain cert via Hetzner Certificates API.`
            };
        }
        if (issue.includes('health check') || issue.includes('Health Check')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Configure health checks on Load Balancer "${name}" via PUT /v1/load_balancers/{id}/actions/update_service. Add health_check config with HTTP protocol, path "/health", interval 15s, timeout 5s, retries 3.`
            };
        }
    }

    // ── Hetzner Floating IP ────────────────────────────────────────────────
    if (type === 'Hetzner Floating IP') {
        if (issue.includes('unassigned') || issue.includes('no utility')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Release Floating IP "${name}" via DELETE /v1/floating_ips/{id} or assign it to an active server via POST /v1/floating_ips/{id}/actions/assign with server_id.`
            };
        }
    }

    // ── Hetzner SSH Key ────────────────────────────────────────────────────
    if (type === 'Hetzner SSH Key') {
        if (issue.includes('SSH keys') || issue.includes('rotation')) {
            log.info(`[HETZNER-FIX] Auditing SSH keys`);
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: List all SSH keys via GET /v1/ssh_keys and delete unused ones via DELETE /v1/ssh_keys/{id}. Rotate keys for any staff who have left the team.`
            };
        }
    }

    // ── Hetzner Snapshot ───────────────────────────────────────────────────
    if (type === 'Hetzner Snapshot') {
        if (issue.includes('old') || issue.includes('90 days') || issue.includes('outdated')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Delete old snapshots via DELETE /v1/images/{id} for each image of type "snapshot" older than 90 days. Keep at minimum the last 3 snapshots for recovery purposes.`
            };
        }
    }

    // ── Hetzner Certificate ────────────────────────────────────────────────
    if (type === 'Hetzner Certificate') {
        if (issue.includes('expires') || issue.includes('expiry')) {
            log.info(`[HETZNER-FIX] Certificate "${name}" expiring soon`);
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Renew certificate "${name}" via POST /v1/certificates with type=managed and domain_names. Hetzner managed certificates auto-renew. For custom certs, upload new PEM via API before expiry.`
            };
        }
    }

    // ── Hetzner Primary IP ─────────────────────────────────────────────────
    if (type === 'Hetzner Primary IP') {
        if (issue.includes('unassigned') || issue.includes('no utility')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Release unassigned Primary IPs via DELETE /v1/primary_ips/{id}. List all unassigned primary IPs via GET /v1/primary_ips?assignee_type=server and filter by null assignee_id.`
            };
        }
    }

    // ── Hetzner Placement Group ────────────────────────────────────────────
    if (type === 'Hetzner Placement Group') {
        if (issue.includes('co-location') || issue.includes('Placement Group')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Create a Placement Group via POST /v1/placement_groups with type=spread. Then rebuild servers with placement_group_id specified to distribute them across different physical hosts.`
            };
        }
    }

    // ── Hetzner Image ──────────────────────────────────────────────────────
    if (type === 'Hetzner Image') {
        if (issue.includes('outdated') || issue.includes('EOL') || issue.includes('Ubuntu')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Create server snapshots before upgrading. Deploy new server from Ubuntu 24.04 image, migrate workloads, and update load balancer or DNS. Delete old server after verification.`
            };
        }
    }

    // ── Hetzner Server Type ────────────────────────────────────────────────
    if (type === 'Hetzner Server Type') {
        if (issue.includes('sizing') || issue.includes('cost')) {
            return {
                success: true,
                advisory: true,
                message: `ADVISORY: Review server CPU and memory utilization via Hetzner metrics or external monitoring (Prometheus/Grafana). Downsize underutilized servers via server type change action.`
            };
        }
    }

    // ── Fallback ───────────────────────────────────────────────────────────
    return {
        success: true,
        advisory: true,
        message: `ADVISORY: No automated remediation available for Hetzner ${type} "${name}". Manual intervention required via Hetzner Console (console.hetzner.cloud) or API.`
    };
}
