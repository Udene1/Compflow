/**
 * ComplianceFlow AI — Truthful Compliance Phrasing & Assessment Standards
 * 
 * Enforces technical accuracy in compliance status displays.
 * BAN: "82% compliant", "90% SOC 2 compliant".
 * REQUIRE: "X of Y selected [Framework] controls assessed".
 */

const FRAMEWORK_DISPLAY_NAMES = {
    soc2: 'SOC 2',
    iso27001: 'ISO 27001',
    hipaa: 'HIPAA',
    gdpr: 'GDPR',
    pci: 'PCI-DSS',
    nist: 'NIST CSF'
};

const FRAMEWORK_TOTAL_CONTROLS = {
    soc2: 106,
    iso27001: 93,
    hipaa: 54,
    gdpr: 42,
    pci: 78,
    nist: 108
};

export function getFrameworkDisplayName(frameworkId) {
    const key = (frameworkId || '').toLowerCase().trim();
    for (const [prefix, name] of Object.entries(FRAMEWORK_DISPLAY_NAMES)) {
        if (key.includes(prefix)) return name;
    }
    return (frameworkId || 'COMPLIANCE').toUpperCase();
}

export function getFrameworkTotalControls(frameworkId) {
    const key = (frameworkId || '').toLowerCase().trim();
    for (const [prefix, total] of Object.entries(FRAMEWORK_TOTAL_CONTROLS)) {
        if (key.includes(prefix)) return total;
    }
    return 100;
}

/**
 * Formats an authoritative, truthful control assessment label.
 * Example: "68 of 106 selected SOC 2 controls assessed"
 */
export function formatAssessmentSummary({ assessed = 0, total = null, framework = 'SOC 2' }) {
    const name = getFrameworkDisplayName(framework);
    const totalCount = total || getFrameworkTotalControls(framework);
    const validAssessed = Math.max(0, parseInt(assessed, 10) || 0);

    return `${validAssessed} of ${totalCount} selected ${name} controls assessed`;
}

/**
 * Asserts that a given text or payload does not claim percentage compliance.
 * Throws an error if deceptive compliance phrasing is detected.
 */
export function assertTruthfulPhrasing(text) {
    if (!text || typeof text !== 'string') return true;

    const bannedPatterns = [
        /\d+%(?:\s+[\w\d\s]+)?\s*(?:compliant|compliance|passed|certified)/i,
        /compliant\s*:\s*\d+%/i,
        /you are \d+%/i,
        /100%\s*secure/i
    ];

    for (const pattern of bannedPatterns) {
        if (pattern.test(text)) {
            throw new Error(`Deceptive compliance claim detected: "${text.match(pattern)[0]}". Must use "X of Y selected controls assessed".`);
        }
    }

    return true;
}
