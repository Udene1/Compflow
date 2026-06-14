import { execSync } from 'child_process';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

const resultsDir = join(process.cwd(), 'tests', 'results');
if (!existsSync(resultsDir)) {
    mkdirSync(resultsDir, { recursive: true });
}

const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const logFile = join(resultsDir, `test-results-${timestamp}.log`);

console.log(`🚀 Running tests and saving results to ${logFile}...`);

try {
    // Run vitest and capture output
    // Using --reporter=default and --reporter=json to get both human readable and parsable if needed
    const output = execSync('npm run test:unit', { encoding: 'utf8', stdio: 'pipe' });
    writeFileSync(logFile, output);
    console.log('✅ Tests passed!');
} catch (error) {
    writeFileSync(logFile, error.stdout || error.message);
    console.log('❌ Tests failed. See log for details.');
    process.exit(1);
}
