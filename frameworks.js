// ─── ComplianceFlow AI: Multi-Framework Orchestration ───
// Maps technical findings to SOC2, GDPR, HIPAA, and ISO 27001 controls.

window.Frameworks = (() => {
    const DATA = {
        soc2: {
            name: 'SOC2 Type II',
            type: 'Trust Service Criteria',
            controls: {
                'CC6.1': { id: 'CC6.1', name: 'Logical Access Protection', desc: 'The entity restricts logical access to system components.' },
                'CC6.2': { id: 'CC6.2', name: 'User Access Management', desc: 'The entity manages user access through authentication and authorization.' },
                'CC6.3': { id: 'CC6.3', name: 'Security Policy Compliance', desc: 'The entity monitors and enforces compliance with its security policies.' },
                'CC6.7': { id: 'CC6.7', name: 'Boundary Protection', desc: 'The entity restricts unauthorized traffic from entering the network.' },
                'CC7.1': { id: 'CC7.1', name: 'System Monitoring', desc: 'The entity monitors the system to detect and address anomalies.' },
                'CC7.2': { id: 'CC7.2', name: 'Audit Logging', desc: 'The entity evaluates and responds to identified security incidents.' }
            }
        },
        gdpr: {
            name: 'GDPR',
            type: 'Articles',
            controls: {
                'Art. 32': { id: 'Art. 32', name: 'Security of Processing', desc: 'Appropriate technical and organizational measures to ensure security.' },
                'Art. 25': { id: 'Art. 25', name: 'Privacy by Design', desc: 'Implement appropriate technical measures to protect sensitive data.' },
                'Art. 33': { id: 'Art. 33', name: 'Breach Notification', desc: 'Ability to detect, report, and document personal data breaches.' }
            }
        },
        hipaa: {
            name: 'HIPAA',
            type: 'Technical Safeguards',
            controls: {
                '§164.312(a)(1)': { id: '§164.312(a)(1)', name: 'Access Control', desc: 'Implement policies to restrict access to ePHI.' },
                '§164.312(c)(1)': { id: '§164.312(c)(1)', name: 'Integrity', desc: 'Protect ePHI from improper alteration or destruction.' },
                '§164.312(e)(1)': { id: '§164.312(e)(1)', name: 'Transmission Security', desc: 'Protect ePHI against unauthorized access during transmission.' }
            }
        },
        iso27001: {
            name: 'ISO 27001',
            type: 'Annex A Controls',
            controls: {
                'A.9.1.1': { id: 'A.9.1.1', name: 'Access Control Policy', desc: 'Establish and document an access control policy.' },
                'A.12.4.1': { id: 'A.12.4.1', name: 'Event Logging', desc: 'Event logs recording user activities and security events shall be produced.' },
                'A.12.1.2': { id: 'A.12.1.2', name: 'Change Management', desc: 'Changes to facilities and systems shall be controlled.' },
                'A.18.1.1': { id: 'A.18.1.1', name: 'Applicable Legislation', desc: 'Statutory, regulatory, and contractual requirements shall be identified.' }
            }
        }
    };

    // Crosswalk: Maps Finding Types to multiple framework controls
    const MAPPING = {
        'S3 Bucket': {
            'Public access enabled': ['soc2:CC6.1', 'gdpr:Art. 32', 'hipaa:§164.312(a)(1)', 'iso27001:A.9.1.1'],
            'Versioning not enabled': ['soc2:CC7.2', 'iso27001:A.12.1.2'],
            'MFA Delete disabled': ['soc2:CC6.3', 'hipaa:§164.312(a)(1)'],
            'Server access logging disabled': ['soc2:CC7.2', 'gdpr:Art. 33'],
            default: ['soc2:CC6.1']
        },
        'IAM Role': {
            'Stale Access': ['soc2:CC6.2', 'iso27001:A.9.1.1'],
            default: ['soc2:CC6.2']
        },
        'IAM Account': {
            'Root MFA disabled': ['soc2:CC6.3', 'gdpr:Art. 32', 'iso27001:A.9.1.1'],
            default: ['soc2:CC6.3']
        },
        'Security Group': {
            'Allows 0.0.0.0/0': ['soc2:CC6.7', 'gdpr:Art. 32', 'iso27001:A.12.1.2'],
            default: ['soc2:CC6.7']
        },
        'VPC': {
            'Flow Logs disabled': ['soc2:CC7.2', 'gdpr:Art. 33', 'iso27001:A.12.4.1'],
            default: ['soc2:CC7.2']
        },
        'RDS Database': {
            'Encryption at rest disabled': ['soc2:CC6.1', 'gdpr:Art. 32', 'hipaa:§164.312(c)(1)'],
            default: ['soc2:CC6.1']
        },
        'KMS Key': {
            'Key Rotation disabled': ['soc2:CC6.7', 'iso27001:A.12.1.2'],
            default: ['soc2:CC6.7']
        },
        'CloudTrail': {
            'No trail enabled': ['soc2:CC7.2', 'gdpr:Art. 33', 'iso27001:A.12.4.1'],
            'Log Validation disabled': ['soc2:CC7.2', 'iso27001:A.12.4.1'],
            default: ['soc2:CC7.2']
        },
        'Macie': {
            'Data Discovery disabled': ['gdpr:Art. 25', 'hipaa:§164.312(c)(1)'],
            default: ['gdpr:Art. 25']
        },
        'Lambda': {
            'Deprecated runtime': ['soc2:CC7.1', 'iso27001:A.12.1.2'],
            default: ['soc2:CC7.1']
        },
        'WAF': {
            'No WAF WebACLs': ['soc2:CC6.7', 'iso27001:A.12.1.2'],
            default: ['soc2:CC6.7']
        },
        'Shield': {
            'Shield Advanced not active': ['soc2:CC6.7'],
            default: ['soc2:CC6.7']
        },
        'DynamoDB Table': {
            'PITR': ['soc2:CC7.2', 'hipaa:§164.312(c)(1)', 'gdpr:Art. 32'],
            'KMS Encryption': ['soc2:CC6.7', 'iso27001:A.12.1.2', 'gdpr:Art. 25'],
            default: ['soc2:CC6.1']
        },
        'Redshift Cluster': {
            'Cluster encryption disabled': ['soc2:CC6.7', 'gdpr:Art. 32', 'hipaa:§164.312(e)(1)'],
            'Publicly Accessible': ['soc2:CC6.6', 'iso27001:A.9.1.1'],
            default: ['soc2:CC6.1']
        },
        'EKS Cluster': {
            'Control Plane Logging': ['soc2:CC7.2', 'gdpr:Art. 33'],
            'Cluster Endpoint publicly accessible': ['soc2:CC6.6', 'iso27001:A.9.1.1'],
            'Secrets encryption disabled': ['soc2:CC6.7', 'hipaa:§164.312(c)(1)'],
            default: ['soc2:CC6.1']
        },
        'API Gateway': {
            'execute-api endpoint': ['soc2:CC6.6', 'iso27001:A.9.1.1'],
            default: ['soc2:CC6.1']
        },
        'API Gateway Stage': {
            'X-Ray Tracing disabled': ['soc2:CC7.2', 'gdpr:Art. 33'],
            'No WAF WebACL': ['soc2:CC6.6', 'gdpr:Art. 32'],
            default: ['soc2:CC6.1']
        },
        'CloudFront Distribution': {
            'No WAF Integration': ['soc2:CC6.6', 'iso27001:A.12.1.2'],
            'HTTP traffic allowed': ['soc2:CC6.7', 'hipaa:§164.312(e)(1)'],
            default: ['soc2:CC6.1']
        },
        'SQS Queue': {
            'Server-Side Encryption disabled': ['soc2:CC6.7', 'gdpr:Art. 25'],
            default: ['soc2:CC6.1']
        },
        'SNS Topic': {
            'Server-Side Encryption disabled': ['soc2:CC6.7'],
            default: ['soc2:CC6.1']
        },
        'Threat Detection': {
            default: ['soc2:CC7.1', 'gdpr:Art. 32', 'iso27001:A.12.4.1']
        },
        'Configuration': {
            default: ['soc2:CC8.1', 'iso27001:A.12.1.2']
        },
        'Log Group': {
            default: ['soc2:CC7.2', 'gdpr:Art. 33', 'hipaa:§164.312(c)(1)']
        },
        'CloudWatch Alarms': {
            default: ['soc2:CC7.2', 'iso27001:A.12.4.1']
        }
    };

    let currentFramework = 'soc2';

    function setFramework(id) {
        if (DATA[id]) currentFramework = id;
    }

    function getCurrent() {
        return DATA[currentFramework];
    }

    function getCurrentId() {
        return currentFramework;
    }

    function getMapping(resourceType, issueText) {
        const typeMap = MAPPING[resourceType];
        if (!typeMap) return ['soc2:CC6.1']; 

        // Find specific issue or fallback to default
        let matchedKeys = [];
        for (const key in typeMap) {
            if (key !== 'default' && issueText && issueText.toLowerCase().includes(key.toLowerCase())) {
                matchedKeys = typeMap[key];
                break;
            }
        }

        if (matchedKeys.length === 0) matchedKeys = typeMap.default;
        return matchedKeys;
    }

    // Returns details for a specific control key like 'gdpr:Art. 32'
    function getControlDetails(key) {
        const [fwId, ctrlId] = key.split(':');
        return DATA[fwId]?.controls[ctrlId];
    }

    return { DATA, setFramework, getCurrent, getMapping, getControlDetails };
})();
