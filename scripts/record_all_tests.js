import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const RESULTS_DIR = path.join(process.cwd(), 'tests', 'results');
if (!fs.existsSync(RESULTS_DIR)) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
}

const isoTimestamp = new Date().toISOString();
const safeTimestamp = isoTimestamp.replace(/[:.]/g, '-');

console.log("================================================================================");
console.log(`🧪 COMPLIANCEFLOW AI — UNIFIED TEST RUNNER & AUDIT RECORDER (${isoTimestamp})`);
console.log("================================================================================\n");

const runLog = {
    timestamp: isoTimestamp,
    summary: {
        totalSuites: 0,
        passedSuites: 0,
        failedSuites: 0
    },
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
        output = err.stdout || err.stderr || err.message;
        console.error(`  ❌ ${stepName} failed (${((Date.now() - startTime) / 1000).toFixed(2)}s).`);
    }

    const durationMs = Date.now() - startTime;
    runLog.runs.push({
        stepName,
        command,
        status,
        durationMs,
        output
    });

    runLog.summary.totalSuites++;
    if (status === 'PASSED') runLog.summary.passedSuites++;
    else runLog.summary.failedSuites++;
}

// 1. Vitest Full Test Suite
executeTestStep('Vitest Automated Suite (Unit & E2E)', 'npx vitest run');

// 2. SOC2 Auditor Evidence Portal Engine
executeTestStep('SOC2 Auditor Evidence Portal Engine', 'node test_auditor_portal.js');

// 3. Autonomous Scheduled Sweeps & Policy Engine
executeTestStep('Autonomous Scheduled Sweeps & Custom Policies', 'node test_scheduled_sweeps.js');

// 4. Multi-Cloud E2E Lifecycle Engine
executeTestStep('Multi-Cloud E2E Engine', 'node test_e2e_all_clouds.js');

// ── Save Timestamped Result Files ──

// 1. Specific Auditor Portal Log File (appended with timestamp)
const auditorRun = runLog.runs.find(r => r.stepName === 'SOC2 Auditor Evidence Portal Engine');
const auditorLogPath = path.join(RESULTS_DIR, 'auditor_portal_runs.log');
const auditorEntry = `\n================================================================================\nTIMESTAMP: ${isoTimestamp} | STATUS: ${auditorRun?.status || 'UNKNOWN'} (${auditorRun?.durationMs || 0}ms)\n================================================================================\n${auditorRun?.output || ''}\n`;
fs.appendFileSync(auditorLogPath, auditorEntry, 'utf8');

// 2. Test Run History JSON (persistent array)
const historyJsonPath = path.join(RESULTS_DIR, 'test_execution_history.json');
let history = [];
if (fs.existsSync(historyJsonPath)) {
    try {
        history = JSON.parse(fs.readFileSync(historyJsonPath, 'utf8'));
    } catch (e) {
        history = [];
    }
}
history.unshift({
    timestamp: isoTimestamp,
    summary: runLog.summary,
    steps: runLog.runs.map(r => ({ step: r.stepName, status: r.status, duration: `${(r.durationMs / 1000).toFixed(2)}s` }))
});
fs.writeFileSync(historyJsonPath, JSON.stringify(history.slice(0, 50), null, 2), 'utf8');

// 3. Latest Test Run Markdown Summary
const markdownPath = path.join(RESULTS_DIR, 'latest_test_run.md');
const specificRunPath = path.join(RESULTS_DIR, `test_run_${safeTimestamp}.md`);

const markdownContent = `# ComplianceFlow AI — Test Execution Report

**Execution Timestamp**: \`${isoTimestamp}\`  
**Overall Status**: ${runLog.summary.failedSuites === 0 ? '🟢 ALL SUITES PASSED' : '🔴 SUITE FAILURES DETECTED'}  
**Total Test Suites**: ${runLog.summary.totalSuites} (Passed: ${runLog.summary.passedSuites}, Failed: ${runLog.summary.failedSuites})

---

## 📊 Summary Table

| Test Suite | Command | Status | Duration |
| :--- | :--- | :---: | :---: |
${runLog.runs.map(r => `| **${r.stepName}** | \`${r.command}\` | **${r.status}** | ${(r.durationMs / 1000).toFixed(2)}s |`).join('\n')}

---

## 📝 Detailed Execution Outputs

${runLog.runs.map(r => `
### ${r.stepName} (${r.status})
\`\`\`text
${r.output.trim()}
\`\`\`
`).join('\n\n')}
`;

fs.writeFileSync(markdownPath, markdownContent, 'utf8');
fs.writeFileSync(specificRunPath, markdownContent, 'utf8');

console.log("\n================================================================================");
console.log("📊 ALL TEST RESULTS PERSISTED TO:");
console.log("   - tests/results/latest_test_run.md");
console.log(`   - tests/results/test_run_${safeTimestamp}.md`);
console.log("   - tests/results/test_execution_history.json");
console.log("   - tests/results/auditor_portal_runs.log");
console.log("================================================================================\n");
