// ─── ComplianceFlow AI: Custom Governance Policies Module ───
// Manages organization compliance rules: allowed regions, mandatory tags, port whitelists, and backup enforcement

window.PoliciesUI = (() => {
    const DEFAULT_POLICIES = {
        allowedRegions: ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1'],
        mandatoryTags: ['Environment', 'Owner', 'DataClassification'],
        whitelistedPorts: [80, 443, 8443],
        enforceBackups: true,
        enforceEncryption: true,
        enforceBucketVersioning: true
    };

    let currentPolicies = { ...DEFAULT_POLICIES };

    function init() {
        load();
        renderPoliciesPanel();
    }

    function load() {
        try {
            const saved = localStorage.getItem('cf_custom_policies');
            if (saved) {
                currentPolicies = { ...DEFAULT_POLICIES, ...JSON.parse(saved) };
            }
        } catch (e) {
            console.error('Error loading custom policies:', e);
            currentPolicies = { ...DEFAULT_POLICIES };
        }
    }

    function save() {
        try {
            localStorage.setItem('cf_custom_policies', JSON.stringify(currentPolicies));
            if (window.showToast) window.showToast('Governance Policies saved & activated.');
            if (window.LiveTerminal) {
                LiveTerminal.log('system', `Custom governance rules updated: ${currentPolicies.allowedRegions.length} regions, ${currentPolicies.mandatoryTags.length} mandatory tags.`);
            }
        } catch (e) {
            console.error('Error saving custom policies:', e);
        }
    }

    function renderPoliciesPanel() {
        const panel = document.getElementById('panel-policies');
        if (!panel) return;

        // Render Region Chips
        const availableRegions = [
            { id: 'us-east-1', name: 'US East (N. Virginia)' },
            { id: 'us-west-2', name: 'US West (Oregon)' },
            { id: 'eu-west-1', name: 'EU (Ireland)' },
            { id: 'eu-central-1', name: 'EU (Frankfurt)' },
            { id: 'ap-southeast-1', name: 'Asia Pacific (Singapore)' },
            { id: 'sa-east-1', name: 'South America (São Paulo)' },
            { id: 'me-central-1', name: 'Middle East (UAE)' }
        ];

        const regionChipsContainer = document.getElementById('policy-region-chips');
        if (regionChipsContainer) {
            regionChipsContainer.innerHTML = availableRegions.map(reg => {
                const active = currentPolicies.allowedRegions.includes(reg.id) ? 'active' : '';
                return `<button type="button" class="policy-chip ${active}" onclick="PoliciesUI.toggleRegion('${reg.id}')">
                    <span class="chip-status">${active ? '✓' : '○'}</span>
                    <span class="chip-label">${reg.id}</span>
                    <small class="chip-desc">${reg.name}</small>
                </button>`;
            }).join('');
        }

        // Render Tag Badges
        const tagContainer = document.getElementById('policy-tags-container');
        if (tagContainer) {
            tagContainer.innerHTML = currentPolicies.mandatoryTags.map(tag => `
                <span class="policy-tag-badge">
                    <code>${tag}</code>
                    <button type="button" class="tag-remove-btn" onclick="PoliciesUI.removeTag('${tag}')">✕</button>
                </span>
            `).join('');
        }

        // Render Whitelisted Ports
        const portContainer = document.getElementById('policy-ports-container');
        if (portContainer) {
            portContainer.innerHTML = currentPolicies.whitelistedPorts.map(port => `
                <span class="policy-tag-badge port-badge">
                    <code>Port ${port}</code>
                    <button type="button" class="tag-remove-btn" onclick="PoliciesUI.removePort(${port})">✕</button>
                </span>
            `).join('');
        }

        // Render Toggles
        const backupToggle = document.getElementById('policy-toggle-backups');
        if (backupToggle) backupToggle.checked = !!currentPolicies.enforceBackups;

        const encryptionToggle = document.getElementById('policy-toggle-encryption');
        if (encryptionToggle) encryptionToggle.checked = !!currentPolicies.enforceEncryption;

        const versioningToggle = document.getElementById('policy-toggle-versioning');
        if (versioningToggle) versioningToggle.checked = !!currentPolicies.enforceBucketVersioning;
    }

    function toggleRegion(regionId) {
        if (currentPolicies.allowedRegions.includes(regionId)) {
            if (currentPolicies.allowedRegions.length <= 1) {
                if (window.showToast) window.showToast('At least one region must remain authorized.');
                return;
            }
            currentPolicies.allowedRegions = currentPolicies.allowedRegions.filter(r => r !== regionId);
        } else {
            currentPolicies.allowedRegions.push(regionId);
        }
        renderPoliciesPanel();
        save();
    }

    function addTag() {
        const input = document.getElementById('policy-tag-input');
        if (!input) return;
        const tag = input.value.trim();
        if (!tag) return;
        if (currentPolicies.mandatoryTags.includes(tag)) {
            if (window.showToast) window.showToast(`Tag '${tag}' already exists.`);
            return;
        }
        currentPolicies.mandatoryTags.push(tag);
        input.value = '';
        renderPoliciesPanel();
        save();
    }

    function removeTag(tag) {
        currentPolicies.mandatoryTags = currentPolicies.mandatoryTags.filter(t => t !== tag);
        renderPoliciesPanel();
        save();
    }

    function addPort() {
        const input = document.getElementById('policy-port-input');
        if (!input) return;
        const port = parseInt(input.value.trim(), 10);
        if (isNaN(port) || port < 1 || port > 65535) {
            if (window.showToast) window.showToast('Please enter a valid port number (1-65535).');
            return;
        }
        if (currentPolicies.whitelistedPorts.includes(port)) {
            if (window.showToast) window.showToast(`Port ${port} is already in whitelist.`);
            return;
        }
        currentPolicies.whitelistedPorts.push(port);
        input.value = '';
        renderPoliciesPanel();
        save();
    }

    function removePort(port) {
        currentPolicies.whitelistedPorts = currentPolicies.whitelistedPorts.filter(p => p !== port);
        renderPoliciesPanel();
        save();
    }

    function updateToggles() {
        const backupToggle = document.getElementById('policy-toggle-backups');
        if (backupToggle) currentPolicies.enforceBackups = backupToggle.checked;

        const encryptionToggle = document.getElementById('policy-toggle-encryption');
        if (encryptionToggle) currentPolicies.enforceEncryption = encryptionToggle.checked;

        const versioningToggle = document.getElementById('policy-toggle-versioning');
        if (versioningToggle) currentPolicies.enforceBucketVersioning = versioningToggle.checked;

        save();
    }

    function resetToDefaults() {
        currentPolicies = { ...DEFAULT_POLICIES };
        renderPoliciesPanel();
        save();
    }

    function getPolicies() {
        return { ...currentPolicies };
    }

    // Helper to evaluate a scanned resource against custom policies
    function evaluateResource(resource) {
        const violations = [];

        // Check Region Policy
        if (resource.region && !currentPolicies.allowedRegions.includes(resource.region)) {
            violations.push({
                policyId: 'ORG-GOV-01',
                title: 'Restricted Geographic Region',
                description: `Resource deployed in unauthorized region '${resource.region}'. Allowed: [${currentPolicies.allowedRegions.join(', ')}]`,
                severity: 'HIGH'
            });
        }

        // Check Mandatory Tags
        if (resource.tags) {
            const missingTags = currentPolicies.mandatoryTags.filter(t => !Object.prototype.hasOwnProperty.call(resource.tags, t));
            if (missingTags.length > 0) {
                violations.push({
                    policyId: 'ORG-GOV-02',
                    title: 'Missing Mandatory Governance Tags',
                    description: `Resource is missing mandatory tags: [${missingTags.join(', ')}]`,
                    severity: 'MEDIUM'
                });
            }
        }

        return violations;
    }

    return {
        init,
        load,
        save,
        renderPoliciesPanel,
        toggleRegion,
        addTag,
        removeTag,
        addPort,
        removePort,
        updateToggles,
        resetToDefaults,
        getPolicies,
        evaluateResource
    };
})();

document.addEventListener('DOMContentLoaded', PoliciesUI.init);
