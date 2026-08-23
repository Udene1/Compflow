import { log } from './logger.js';

/**
 * ComplianceFlow AI — Custom Governance Policy Rules Engine
 * Allows organizations to define and enforce custom governance guardrails
 * alongside standard regulatory frameworks (SOC2, ISO27001, HIPAA, GDPR, PCI-DSS).
 */

export const BUILT_IN_POLICY_TEMPLATES = {
    ALLOWED_REGIONS: {
        id: 'POLICY_ALLOWED_REGIONS',
        name: 'Restricted Geographic Deployment',
        description: 'Ensures all cloud infrastructure resides exclusively in approved jurisdiction regions (e.g. US or EU).',
        severity: 'critical',
        control: 'ORG-GOV-01'
    },
    REQUIRED_TAGS: {
        id: 'POLICY_MANDATORY_TAGS',
        name: 'Mandatory Resource Tagging',
        description: 'Requires all resources to declare mandatory operational tags (e.g., Environment, Owner, DataClassification).',
        severity: 'warning',
        control: 'ORG-GOV-02'
    },
    PORT_WHITELIST: {
        id: 'POLICY_PORT_WHITELIST',
        name: 'Authorized Inbound Port Whitelist',
        description: 'Flags any public inbound firewall/NSG rule exposing ports outside the approved corporate whitelist.',
        severity: 'critical',
        control: 'ORG-NET-01'
    },
    MANDATORY_BACKUPS: {
        id: 'POLICY_MANDATORY_BACKUPS',
        name: 'Automated Snapshot & Backup Policy',
        description: 'Enforces automated snapshot schedules for all compute, disk, and database assets.',
        severity: 'critical',
        control: 'ORG-RES-01'
    }
};

/**
 * Evaluates a list of discovered cloud resources against custom organization policies.
 * 
 * @param {Array} resources - The scanned cloud resources
 * @param {Object} policiesConfig - Organization custom policies configuration
 * @returns {Array} List of findings including policy violation findings
 */
export function evaluateCustomPolicies(resources = [], policiesConfig = {}) {
    if (!resources || !Array.isArray(resources) || resources.length === 0) {
        return [];
    }

    const policyFindings = [];

    // ────────────────────────────────────────────────────────────────────────
    // Policy 1: Allowed Regions Constraint
    // ────────────────────────────────────────────────────────────────────────
    if (policiesConfig.allowedRegions && Array.isArray(policiesConfig.allowedRegions) && policiesConfig.allowedRegions.length > 0) {
        const allowed = new Set(policiesConfig.allowedRegions.map(r => r.toLowerCase().trim()));
        
        for (const resource of resources) {
            const resRegion = (resource.region || '').toLowerCase().trim();
            // Skip global assets from region constraints
            if (resRegion && resRegion !== 'global' && !allowed.has(resRegion)) {
                policyFindings.push({
                    name: resource.name,
                    type: resource.type,
                    icon: '🌐',
                    region: resource.region,
                    severity: policiesConfig.regionSeverity || 'critical',
                    technicalId: 'POLICY_UNAUTHORIZED_REGION',
                    control: 'ORG-GOV-01',
                    issue: `Resource deployed in unauthorized region "${resource.region}". Approved regions: [${policiesConfig.allowedRegions.join(', ')}]`,
                    recommendation: `Migrate or reprovision resource to an approved compliance jurisdiction region: ${policiesConfig.allowedRegions.join(', ')}.`,
                    customPolicy: true
                });
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Policy 2: Mandatory Resource Tagging
    // ────────────────────────────────────────────────────────────────────────
    if (policiesConfig.requiredTags && Array.isArray(policiesConfig.requiredTags) && policiesConfig.requiredTags.length > 0) {
        const requiredTags = policiesConfig.requiredTags;

        for (const resource of resources) {
            // Check if resource has tags or metadata
            const tags = resource.tags || resource.labels || {};
            const tagKeys = new Set(Object.keys(tags).map(k => k.toLowerCase()));
            const missingTags = requiredTags.filter(req => !tagKeys.has(req.toLowerCase()));

            if (missingTags.length > 0) {
                policyFindings.push({
                    name: resource.name,
                    type: resource.type,
                    icon: '🏷️',
                    region: resource.region || 'global',
                    severity: policiesConfig.tagSeverity || 'warning',
                    technicalId: 'POLICY_MISSING_TAGS',
                    control: 'ORG-GOV-02',
                    issue: `Missing required organizational tags: [${missingTags.join(', ')}]`,
                    recommendation: `Apply mandatory governance tags (${missingTags.join(', ')}) in Infrastructure as Code (Terraform/Bicep).`,
                    customPolicy: true
                });
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Policy 3: Inbound Port Whitelist
    // ────────────────────────────────────────────────────────────────────────
    if (policiesConfig.allowedInboundPorts && Array.isArray(policiesConfig.allowedInboundPorts)) {
        const allowedPorts = new Set(policiesConfig.allowedInboundPorts.map(p => String(p)));

        for (const resource of resources) {
            if (resource.type?.includes('NSG') || resource.type?.includes('Security Group') || resource.type?.includes('Firewall')) {
                // If the finding or resource relates to an open port
                const issueText = resource.issue || '';
                const portMatch = issueText.match(/port\s+(\d+|\*)/i);
                if (portMatch) {
                    const port = portMatch[1];
                    if (port === '*' || !allowedPorts.has(port)) {
                        policyFindings.push({
                            name: resource.name,
                            type: resource.type,
                            icon: '🛡️',
                            region: resource.region || 'global',
                            severity: 'critical',
                            technicalId: 'POLICY_DISALLOWED_PORT',
                            control: 'ORG-NET-01',
                            issue: `Public ingress on port "${port}" violates organization port whitelist (Allowed: ${policiesConfig.allowedInboundPorts.join(', ')})`,
                            recommendation: `Close public ingress on port ${port} or restrict access to corporate VPN.`,
                            customPolicy: true
                        });
                    }
                }
            }
        }
    }

    if (policyFindings.length > 0) {
        log.info(`[POLICY-ENGINE] Custom policy evaluation generated ${policyFindings.length} findings.`);
    }

    return policyFindings;
}
