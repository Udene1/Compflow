import crypto from 'crypto';

/**
 * ComplianceFlow AI: Intelligent Compliance Mapper
 * Handles multi-framework cross-walking, timeline conflict detection,
 * and side-by-side matrix generation.
 */

const FRAMEWORK_METADATA = {
    soc2: {
        id: 'soc2',
        name: 'SOC2 Type II',
        timeline: 'None (Operational adherence)',
        priority: 2
    },
    gdpr: {
        id: 'gdpr',
        name: 'GDPR',
        timeline: '72 hours (Art. 33)',
        priority: 1
    },
    iso27001: {
        id: 'iso27001',
        name: 'ISO 27001',
        timeline: 'None (Without undue delay)',
        priority: 3
    },
    hipaa: {
        id: 'hipaa',
        name: 'HIPAA',
        timeline: '60 days (Privacy Rule)',
        priority: 2
    }
};

// Cross-framework mapping definitions (technical -> regulatory)
const CONTROL_MAP = {
    'S3 Bucket': {
        'Public access enabled': {
            soc2: 'CC6.1',
            gdpr: 'Art. 32',
            hipaa: '§164.312(a)(1)',
            iso27001: 'A.9.1.1'
        },
        'Versioning not enabled': {
            soc2: 'CC7.2',
            iso27001: 'A.12.1.2'
        },
        default: { soc2: 'CC6.1' }
    },
    'IAM Role': {
        'Stale Access': {
            soc2: 'CC6.2',
            iso27001: 'A.9.1.1'
        },
        default: { soc2: 'CC6.2' }
    },
    'Security Group': {
        'Allows 0.0.0.0/0': {
            soc2: 'CC6.7',
            gdpr: 'Art. 32',
            iso27001: 'A.12.1.2'
        },
        default: { soc2: 'CC6.7' }
    },
    // Fallback for unknown types
    default: { soc2: 'CC6.1' }
};

/**
 * Enriches a finding with framework-specific interpretations and integrity hashes.
 */
export function enrichFinding(finding) {
    const rawData = JSON.stringify(finding);
    finding.evidence_hash = crypto.createHash('sha256').update(rawData).digest('hex');
    
    const mappings = CONTROL_MAP[finding.type] || CONTROL_MAP.default;
    const frameworkRes = {};

    // Map finding to every supported framework
    for (const [fwId, meta] of Object.entries(FRAMEWORK_METADATA)) {
        const control = mappings[finding.issue] 
            ? (mappings[finding.issue][fwId] || null)
            : (mappings.default[fwId] || null);

        if (control) {
            frameworkRes[fwId] = {
                control,
                status: finding.severity === 'pass' ? 'compliant' : 'gap',
                timeline: meta.timeline,
                notes: `Mapped via ComplianceFlow AI automated cross-walk.`
            };
        } else {
            frameworkRes[fwId] = { status: 'not_applicable' };
        }
    }

    finding.framework_mappings = frameworkRes;

    // Detect conflicts that require legal review
    const conflicts = detectConflicts(finding);
    if (conflicts.length > 0) {
        finding.requires_legal_review = true;
        finding.legal_review_reason = conflicts.join(' | ');
    }

    return finding;
}

/**
 * Logic to detect material differences between frameworks for the same finding.
 */
function detectConflicts(finding) {
    const conflicts = [];
    const mappings = finding.framework_mappings || {};

    // 1. Timeline Conflicts (GDPR 72h vs others)
    if (mappings.gdpr?.status === 'gap' && mappings.hipaa?.status === 'gap') {
        conflicts.push(`Timeline conflict: GDPR (72h) vs HIPAA (60 days)`);
    }

    // 2. High Priority Flagging
    if (finding.severity === 'critical' && mappings.gdpr?.status === 'gap') {
        conflicts.push(`Critical PII exposure risk under GDPR Article 32`);
    }

    // 3. Status Conflicts (Compliant in one, Gap in another - if implemented via granular checks)
    // (Future logic placeholder)

    return conflicts;
}

/**
 * Generates a side-by-side compliance matrix for reporting.
 */
export function generateComplianceMatrix(findings) {
    const frameworks = Object.keys(FRAMEWORK_METADATA);
    const matrix = {
        headers: ['Resource', 'Issue', ...frameworks.map(f => FRAMEWORK_METADATA[f].name)],
        rows: []
    };

    findings.forEach(f => {
        const row = [
            f.name,
            f.issue || 'Passed',
            ...frameworks.map(fwId => {
                const map = f.framework_mappings?.[fwId];
                if (!map || map.status === 'not_applicable') return 'N/A';
                return `${map.control} (${map.status.toUpperCase()})`;
            })
        ];
        matrix.rows.push(row);
    });

    return matrix;
}
