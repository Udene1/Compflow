import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(process.cwd());

function read(path) {
    return readFileSync(resolve(root, path), 'utf8');
}

describe('runtime architecture boundary', () => {
    it('does not retain obsolete Lambda/serverless runtime entrypoints', () => {
        for (const path of [
            'serverless.yml',
            'worker.js',
            'provision_jobs_table.js',
            'api/lambda-jobs.js',
            'api/lambda-monitoring.js',
            'api/lambda-scan.js'
        ]) {
            expect(existsSync(resolve(root, path)), path).toBe(false);
        }

        const server = read('server.js');
        expect(server).not.toContain('lambdaAdapter');
        expect(server).not.toContain('/api/lambda-');
    });

    it('preserves AWS Lambda as a scanned cloud resource rather than a runtime', () => {
        const pkg = JSON.parse(read('package.json'));
        expect(pkg.dependencies['@aws-sdk/client-lambda']).toBeTruthy();

        const awsProvider = read('core/providers/aws.js');
        expect(awsProvider).toContain('LambdaClient');
        expect(awsProvider).toContain('ListFunctionsCommand');
    });
});
