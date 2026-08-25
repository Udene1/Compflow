#!/usr/bin/env node

/**
 * ComplianceFlow AI — IaC Static Compliance Analyzer
 * 
 * Zero-dependency static analysis engine for Infrastructure as Code files.
 * Scans Terraform (.tf), Bicep (.bicep), CloudFormation (.yaml/.yml),
 * and ARM Templates (.json) for security misconfigurations.
 * 
 * Usage:
 *   node scripts/iac-compliance-check.js [--dir <path>] [--output <path>] [--format json|markdown]
 * 
 * Exit Codes:
 *   0 = No critical findings (PR can merge)
 *   1 = Critical findings detected (PR should be blocked)
 */

import fs from 'fs';
import path from 'path';

// ─── Rule Definitions ────────────────────────────────────────────────────────

const RULES = [
    {
        id: 'TF-SEC-001',
        name: 'Public Access Exposure',
        severity: 'critical',
        category: 'Security',
        patterns: [
            { regex: /(?:acl|AccessControl)\s*[:=]\s*['"]?(?:public-read|PublicRead)['"]?/gi, message: 'S3 bucket configured with public-read ACL' },
            { regex: /(?:acl|AccessControl)\s*[:=]\s*['"]?(?:public-read-write|PublicReadWrite)['"]?/gi, message: 'S3 bucket configured with public-read-write ACL' },
            { regex: /block_public_acls\s*=\s*false/gi, message: 'S3 public access block disabled (block_public_acls = false)' },
            { regex: /block_public_policy\s*=\s*false/gi, message: 'S3 public policy block disabled' },
            { regex: /ignore_public_acls\s*=\s*false/gi, message: 'S3 ignoring public ACLs disabled' },
            { regex: /restrict_public_buckets\s*=\s*false/gi, message: 'S3 restrict public buckets disabled' },
            { regex: /public_network_access_enabled\s*=\s*true/gi, message: 'Azure resource has public network access enabled' },
            { regex: /(?:publicly_accessible|PubliclyAccessible)\s*[:=]\s*true/gi, message: 'Database instance is publicly accessible' },
            { regex: /uniform_bucket_level_access\s*=\s*false/gi, message: 'GCS bucket uniform access disabled' },
        ]
    },
    {
        id: 'TF-SEC-002',
        name: 'Missing Encryption',
        severity: 'critical',
        category: 'Security',
        patterns: [
            { regex: /(?:storage_encrypted|StorageEncrypted)\s*[:=]\s*false/gi, message: 'RDS storage encryption disabled' },
            { regex: /encrypted\s*[:=]\s*false/gi, message: 'Resource encryption explicitly disabled' },
            { regex: /kms_key_id\s*=\s*""/gi, message: 'Empty KMS key ID — no encryption key specified' },
            { regex: /server_side_encryption_configuration\s*\{\s*\}/gi, message: 'Empty server-side encryption configuration block' },
            { regex: /enable_https_traffic_only\s*=\s*false/gi, message: 'Azure storage allows non-HTTPS traffic' },
            { regex: /min_tls_version\s*=\s*"TLS1_0"/gi, message: 'Minimum TLS version set to insecure TLS 1.0' },
            { regex: /min_tls_version\s*=\s*"TLS1_1"/gi, message: 'Minimum TLS version set to deprecated TLS 1.1' },
        ]
    },
    {
        id: 'TF-SEC-003',
        name: 'Open Ports to World',
        severity: 'critical',
        category: 'Network',
        patterns: [
            { regex: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/gi, message: 'Security group allows inbound from 0.0.0.0/0 (entire internet)' },
            { regex: /CidrIp\s*[:=]\s*['"]?0\.0\.0\.0\/0['"]?/gi, message: 'CloudFormation SecurityGroupIngress allows 0.0.0.0/0' },
            { regex: /source_address_prefix\s*=\s*"\*"/gi, message: 'Azure NSG allows inbound from * (entire internet)' },
            { regex: /source_address_prefix\s*=\s*"0\.0\.0\.0\/0"/gi, message: 'Azure NSG allows inbound from 0.0.0.0/0' },
            { regex: /source_ranges\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/gi, message: 'GCP firewall allows inbound from 0.0.0.0/0' },
        ]
    },
    {
        id: 'TF-SEC-004',
        name: 'Logging & Monitoring Disabled',
        severity: 'high',
        category: 'Observability',
        patterns: [
            { regex: /enable_log_file_validation\s*=\s*false/gi, message: 'CloudTrail log file validation disabled' },
            { regex: /is_multi_region_trail\s*=\s*false/gi, message: 'CloudTrail not configured as multi-region' },
            { regex: /enable_logging\s*=\s*false/gi, message: 'Logging explicitly disabled on resource' },
            { regex: /flow_logs_enabled\s*=\s*false/gi, message: 'VPC flow logs disabled' },
        ]
    },
    {
        id: 'TF-SEC-005',
        name: 'Backup & Recovery Missing',
        severity: 'high',
        category: 'Resilience',
        patterns: [
            { regex: /(?:backup_retention_period|BackupRetentionPeriod)\s*[:=]\s*0/gi, message: 'Database backup retention set to 0 days (no backups)' },
            { regex: /point_in_time_recovery\s*\{[\s\S]*?enabled\s*=\s*false/gi, message: 'Point-in-time recovery (PITR) disabled' },
            { regex: /deletion_protection\s*=\s*false/gi, message: 'Deletion protection disabled — resource can be accidentally destroyed' },
            { regex: /skip_final_snapshot\s*=\s*true/gi, message: 'Final snapshot skipped on deletion — data loss risk' },
        ]
    },
    {
        id: 'TF-GOV-001',
        name: 'Unauthorized Region Deployment',
        severity: 'warning',
        category: 'Governance',
        patterns: []
    },
    {
        id: 'TF-GOV-002',
        name: 'Missing Mandatory Tags',
        severity: 'warning',
        category: 'Governance',
        patterns: []
    },
    {
        id: 'TF-IAM-001',
        name: 'IAM Wildcard Permissions',
        severity: 'critical',
        category: 'Identity',
        patterns: [
            { regex: /["']?Action["']?\s*[:=]\s*["']?\*["']?/gi, message: 'IAM policy grants wildcard Action (*) — full access to all AWS services' },
            { regex: /["']?Action["']?\s*[:=]\s*\[\s*["']?\*["']?\s*\]/gi, message: 'IAM policy grants wildcard Action [*] — full access to all AWS services' },
            { regex: /actions\s*=\s*\[\s*"\*"\s*\]/gi, message: 'Terraform IAM actions set to wildcard [*]' },
            { regex: /["']?Principal["']?\s*[:=]\s*["']?\*["']?/gi, message: 'IAM policy allows any principal (*) — world-accessible' },
            { regex: /"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"\s*\}/gi, message: 'IAM policy allows any AWS principal' },
            { regex: /"Effect"\s*:\s*"Allow"[\s\S]*?"Resource"\s*:\s*"\*"/gi, message: 'IAM policy allows actions on all resources (Resource: *)' },
        ]
    },
    {
        id: 'TF-NET-001',
        name: 'Public Endpoints Without Protection',
        severity: 'high',
        category: 'Network',
        patterns: [
            { regex: /endpoint_type\s*=\s*"EDGE"/gi, message: 'API Gateway using EDGE endpoint (consider PRIVATE or REGIONAL with WAF)' },
            { regex: /associate_public_ip_address\s*=\s*true/gi, message: 'Instance configured with public IP address' },
        ]
    }
];

// ─── Default Configuration ───────────────────────────────────────────────────

const DEFAULT_CONFIG = {
    approvedRegions: ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1'],
    mandatoryTags: ['Environment', 'Owner', 'DataClassification'],
    excludeDirs: ['node_modules', '.git', '.serverless', '.terraform', 'dist', 'build', '.next'],
    excludeFiles: ['package.json', 'package-lock.json', 'tsconfig.json', 'vitest.config.js'],
    iacExtensions: ['.tf', '.bicep', '.yaml', '.yml', '.json'],
};

// ─── File Discovery ──────────────────────────────────────────────────────────

export function discoverIaCFiles(dir, config = DEFAULT_CONFIG) {
    const results = [];

    function walk(currentDir) {
        let entries;
        try {
            entries = fs.readdirSync(currentDir, { withFileTypes: true });
        } catch {
            return;
        }

        for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);

            if (entry.isDirectory()) {
                if (!config.excludeDirs.includes(entry.name)) {
                    walk(fullPath);
                }
                continue;
            }

            if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                if (config.iacExtensions.includes(ext) && !config.excludeFiles.includes(entry.name)) {
                    // For JSON files, only include if they look like ARM/CloudFormation templates
                    if (ext === '.json') {
                        try {
                            const content = fs.readFileSync(fullPath, 'utf-8');
                            if (content.includes('"$schema"') || content.includes('"AWSTemplateFormatVersion"') || content.includes('"resources"')) {
                                results.push(fullPath);
                            }
                        } catch {
                            // Skip unreadable files
                        }
                    } else {
                        results.push(fullPath);
                    }
                }
            }
        }
    }

    walk(dir);
    return results;
}

// ─── Analysis Engine ─────────────────────────────────────────────────────────

export function analyzeFile(filePath, config = DEFAULT_CONFIG) {
    const findings = [];
    let content;
    try {
        content = fs.readFileSync(filePath, 'utf-8');
    } catch (err) {
        return [{ ruleId: 'SCAN-ERR', severity: 'warning', file: filePath, line: 0, message: `Could not read file: ${err.message}` }];
    }

    const relPath = filePath;

    // ── Pattern-Based Rules ──
    for (const rule of RULES) {
        for (const pat of rule.patterns) {
            // Reset regex state
            pat.regex.lastIndex = 0;
            let match;
            while ((match = pat.regex.exec(content)) !== null) {
                const lineNum = content.substring(0, match.index).split('\n').length;
                findings.push({
                    ruleId: rule.id,
                    ruleName: rule.name,
                    severity: rule.severity,
                    category: rule.category,
                    file: relPath,
                    line: lineNum,
                    message: pat.message,
                    matchedText: match[0].trim().substring(0, 120),
                });
            }
        }
    }

    // ── TF-GOV-001: Region Check (Programmatic) ──
    const regionPatterns = [
        /region\s*=\s*"([^"]+)"/gi,
        /location\s*=\s*"([^"]+)"/gi,
    ];
    for (const rp of regionPatterns) {
        rp.lastIndex = 0;
        let match;
        while ((match = rp.exec(content)) !== null) {
            const region = match[1].toLowerCase().trim();
            if (region.startsWith('var.') || region.startsWith('local.') || region.startsWith('data.') || region.startsWith('$')) continue;
            if (!config.approvedRegions.map(r => r.toLowerCase()).includes(region)) {
                const lineNum = content.substring(0, match.index).split('\n').length;
                findings.push({
                    ruleId: 'TF-GOV-001',
                    ruleName: 'Unauthorized Region Deployment',
                    severity: 'warning',
                    category: 'Governance',
                    file: relPath,
                    line: lineNum,
                    message: `Resource targets unapproved region "${match[1]}". Approved: [${config.approvedRegions.join(', ')}]`,
                    matchedText: match[0].trim(),
                });
            }
        }
    }

    // ── TF-GOV-002: Missing Tags Check (Programmatic) ──
    const resourceBlockRegex = /resource\s+"[^"]+"\s+"[^"]+"\s*\{/gi;
    let resourceMatch;
    while ((resourceMatch = resourceBlockRegex.exec(content)) !== null) {
        const blockStart = resourceMatch.index;
        const blockContent = content.substring(blockStart, blockStart + 2000);
        const tagBlockMatch = blockContent.match(/tags\s*=?\s*\{([^}]*)\}/i);

        if (tagBlockMatch) {
            const tagBlock = tagBlockMatch[1];
            const missingTags = config.mandatoryTags.filter(
                tag => !new RegExp(`["']?${tag}["']?\\s*[=:]`, 'i').test(tagBlock)
            );
            if (missingTags.length > 0) {
                const lineNum = content.substring(0, blockStart).split('\n').length;
                findings.push({
                    ruleId: 'TF-GOV-002',
                    ruleName: 'Missing Mandatory Tags',
                    severity: 'warning',
                    category: 'Governance',
                    file: relPath,
                    line: lineNum,
                    message: `Resource missing mandatory tags: [${missingTags.join(', ')}]`,
                    matchedText: resourceMatch[0].trim(),
                });
            }
        } else {
            const lineNum = content.substring(0, blockStart).split('\n').length;
            findings.push({
                ruleId: 'TF-GOV-002',
                ruleName: 'Missing Mandatory Tags',
                severity: 'warning',
                category: 'Governance',
                file: relPath,
                line: lineNum,
                message: `Resource has no tags block — missing all mandatory tags: [${config.mandatoryTags.join(', ')}]`,
                matchedText: resourceMatch[0].trim(),
            });
        }
    }

    return findings;
}

// ─── Result Aggregation ──────────────────────────────────────────────────────

export function analyzeDirectory(dir, config = DEFAULT_CONFIG) {
    const files = discoverIaCFiles(dir, config);
    const allFindings = [];

    for (const file of files) {
        const findings = analyzeFile(file, config);
        allFindings.push(...findings);
    }

    const summary = {
        totalFiles: files.length,
        totalFindings: allFindings.length,
        critical: allFindings.filter(f => f.severity === 'critical').length,
        high: allFindings.filter(f => f.severity === 'high').length,
        warning: allFindings.filter(f => f.severity === 'warning').length,
        hasCritical: allFindings.some(f => f.severity === 'critical'),
        files,
        findings: allFindings,
    };

    return summary;
}

// ─── Markdown Report Generator ───────────────────────────────────────────────

export function generateMarkdownReport(summary) {
    const statusIcon = summary.hasCritical ? '❌' : summary.totalFindings > 0 ? '⚠️' : '✅';
    const statusText = summary.hasCritical
        ? 'BLOCKED — Critical compliance violations detected'
        : summary.totalFindings > 0
            ? 'PASSED WITH WARNINGS — Non-critical issues found'
            : 'PASSED — All IaC files are compliant';

    let md = `## ${statusIcon} ComplianceFlow IaC Compliance Gate\n\n`;
    md += `**Status**: ${statusText}\n\n`;
    md += `| Metric | Count |\n|---|---|\n`;
    md += `| Files Scanned | ${summary.totalFiles} |\n`;
    md += `| Total Findings | ${summary.totalFindings} |\n`;
    md += `| 🔴 Critical | ${summary.critical} |\n`;
    md += `| 🟠 High | ${summary.high} |\n`;
    md += `| 🟡 Warning | ${summary.warning} |\n\n`;

    if (summary.findings.length === 0) {
        md += `> ✅ No compliance issues found in any IaC files. Great work!\n`;
        return md;
    }

    const grouped = { critical: [], high: [], warning: [] };
    for (const f of summary.findings) {
        (grouped[f.severity] || grouped.warning).push(f);
    }

    for (const [severity, findings] of Object.entries(grouped)) {
        if (findings.length === 0) continue;

        const icon = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : '🟡';
        const label = severity.charAt(0).toUpperCase() + severity.slice(1);
        md += `### ${icon} ${label} (${findings.length})\n\n`;
        md += `| Rule | File | Line | Finding |\n|---|---|---|---|\n`;

        for (const f of findings) {
            const shortFile = path.basename(f.file);
            md += `| \`${f.ruleId}\` | \`${shortFile}\` | L${f.line} | ${f.message} |\n`;
        }
        md += '\n';
    }

    if (summary.hasCritical) {
        md += `---\n\n> ❌ **This PR is blocked.** Fix all critical findings before merging. Run \`node scripts/iac-compliance-check.js\` locally to verify.\n`;
    }

    return md;
}

// ─── CLI Entry Point ─────────────────────────────────────────────────────────

function main() {
    const args = process.argv.slice(2);
    let scanDir = '.';
    let outputFile = null;
    let format = 'both';

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--dir' && args[i + 1]) scanDir = args[++i];
        else if (args[i] === '--output' && args[i + 1]) outputFile = args[++i];
        else if (args[i] === '--format' && args[i + 1]) format = args[++i];
        else if (args[i] === '--help') {
            console.log(`
ComplianceFlow AI — IaC Static Compliance Analyzer

Usage:
  node scripts/iac-compliance-check.js [options]

Options:
  --dir <path>        Directory to scan (default: current directory)
  --output <path>     Write markdown report to file
  --format <type>     Output format: json, markdown, both (default: both)
  --help              Show this help message

Exit Codes:
  0  No critical findings
  1  Critical findings detected (should block PR merge)
`);
            process.exit(0);
        }
    }

    const resolvedDir = path.resolve(scanDir);
    console.log(`\n🔍 ComplianceFlow IaC Compliance Gate`);
    console.log(`   Scanning: ${resolvedDir}\n`);

    const summary = analyzeDirectory(resolvedDir);

    if (format === 'json' || format === 'both') {
        console.log(JSON.stringify(summary, null, 2));
    }

    const markdown = generateMarkdownReport(summary);
    if (format === 'markdown' || format === 'both') {
        console.log('\n' + markdown);
    }

    if (outputFile) {
        fs.writeFileSync(outputFile, markdown, 'utf-8');
        console.log(`\n📄 Report written to: ${outputFile}`);
    }

    if (summary.hasCritical) {
        console.log('\n❌ COMPLIANCE GATE FAILED — Critical findings detected.\n');
        process.exit(1);
    } else {
        console.log('\n✅ COMPLIANCE GATE PASSED.\n');
        process.exit(0);
    }
}

const isMainModule = process.argv[1] && (
    process.argv[1].endsWith('iac-compliance-check.js') ||
    process.argv[1].includes('iac-compliance-check')
);

if (isMainModule) {
    main();
}
