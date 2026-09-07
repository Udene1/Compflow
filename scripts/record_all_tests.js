import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const RESULTS_DIR = path.join(process.cwd(), 'tests', 'results');
fs.mkdirSync(RESULTS_DIR, { recursive: true });

const isoTimestamp = new Date().toISOString();
const safeTimestamp = isoTimestamp.replace(/[:.]/g, '-');

console.log("================================================================================");
console.log(`🧪 COMPLIANCEFLOW AI — UNIFIED TEST RUNNER & AUDIT RECORDER (${isoTimestamp})`);
console.log("================================================================================\n");

const runLog = {
    timestamp: isoTimestamp,
    summary: { totalSuites: 0, passedSuites: 0, failedSuites: 0 },
    runs: []
};

function executeTestStep(stepName, command) {
    console.log(`➤ Running: ${stepName} [${command}]...`);
    const startTime = Date.now();
    let status = 'PASSED';
    let output = '';

    try {
        output = execSync(command, { encoding: 'utf8', stdio: 'pipe' });
        console.log(`  ✓ ${stepName} completed successfully (${((Date.now() - startTime) / 1000).toFixed(2)}s).`);
    } catch (err) {
        status = 'FAILED';
        output = [err.stdout, err.stderr, err.message].filter(Boolean).join('\n');
        console.error(`  ❌ ${stepName} failed (${((Date.now() - startTime) / 1000).toFixed(2)}s).`);
    }

    const durationMs = Date.now() - startTime;
    runLog.runs.push({ stepName, command, status, durationMs, output });
    runLog.summary.totalSuites++;
    if (status === 'PASSED') runLog.summary.passedSuites++;
    else runLog.summary.failedSuites++;
}

// These are the authoritative, source-controlled suites. The recorder must never
// depend on local-only scripts or untracked test harnesses.
executeTestStep(
    'Security & Tenant Isolation',
    'npx vitest run tests/unit/auth.test.js tests/unit/auth-hardening.test.js tests/unit/csrf-security.test.js tests/unit/oauth-security.test.js tests/unit/credential-security.test.js tests/unit/tenant-isolation.test.js tests/unit/audit-events.test.js'
);

executeTestStep(
    'Onboarding & Cloud Verification',
    'npx vitest run tests/unit/onboarding.test.js tests/unit/onboarding-hardening.test.js tests/unit/azure.test.js tests/unit/digitalocean.test.js tests/unit/gcp.test.js tests/unit/hetzner.test.js'
);

executeTestStep(
    'Compliance, Policy & Remediation',
    'npx vitest run tests/unit/auditor_portal.test.js tests/unit/compliance_mapper.test.js tests/unit/iac-compliance.test.js tests/unit/policy_engine.test.js tests/unit/remediation-robustness.test.js tests/unit/execution-engine.test.js'
);

executeTestStep(
    'Multi-Cloud E2E',
    'npx vitest run tests/e2e/all_clouds_e2e.test.js'
);

const historyJsonPath = path.join(RESULTS_DIR, 'test_execution_history.json');
let history = [];
if (fs.existsSync(historyJsonPath)) {
    try { history = JSON.parse(fs.readFileSync(historyJsonPath, 'utf8')); }
    catch { history = []; }
}
history.unshift({
    timestamp: isoTimestamp,
    summary: runLog.summary,
    steps: runLog.runs.map(r => ({
        step: r.stepName,
        status: r.status,
        duration: `${(r.durationMs / 1000).toFixed(2)}s`
    }))
});
fs.writeFileSync(historyJsonPath, JSON.stringify(history.slice(0, 50), null, 2), 'utf8');

const markdownContent = `# ComplianceFlow AI — Test Execution Report\n\n**Execution Timestamp**: \`${isoTimestamp}\`  \n**Overall Status**: ${runLog.summary.failedSuites === 0 ? '🟢 ALL SUITES PASSED' : '🔴 SUITE FAILURES DETECTED'}  \n**Total Test Suites**: ${runLog.summary.totalSuites} (Passed: ${runLog.summary.passedSuites}, Failed: ${runLog.summary.failedSuites})\n\n---\n\n## 📊 Summary Table\n\n| Test Suite | Command | Status | Duration |\n| :--- | :--- | :---: | :---: |\n${runLog.runs.map(r => `| **${r.stepName}** | \`${r.command}\` | **${r.status}** | ${(r.durationMs / 1000).toFixed(2)}s |`).join('\n')}\n\n---\n\n## 📝 Detailed Execution Outputs\n\n${runLog.runs.map(r => `\n### ${r.stepName} (${r.status})\n\`\`\`text\n${r.output.trim()}\n\`\`\`\n`).join('\n')}\n`;

fs.writeFileSync(path.join(RESULTS_DIR, 'latest_test_run.md'), markdownContent, 'utf8');
fs.writeFileSync(path.join(RESULTS_DIR, `test_run_${safeTimestamp}.md`), markdownContent, 'utf8');

console.log("\n================================================================================");
console.log("📊 ALL TEST RESULTS PERSISTED TO:");
console.log("   - tests/results/latest_test_run.md");
console.log(`   - tests/results/test_run_${safeTimestamp}.md`);
console.log("   - tests/results/test_execution_history.json");
console.log("================================================================================\n");

if (runLog.summary.failedSuites > 0) process.exitCode = 1;
