import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('product trust instrumentation', () => {
  const source = readFileSync(resolve(process.cwd(), 'trust-instrumentation.js'), 'utf8');

  it('reads trust state from durable execution and remediation APIs', () => {
    expect(source).toContain('CompflowExecution.get(executionId, 0)');
    expect(source).toContain('CompflowExecution.evidence(executionId)');
    expect(source).toContain('CompflowExecution.exposurePaths(executionId)');
    expect(source).toContain('/api/remediation/executions/');
    expect(source).toContain('/impact`');
  });

  it('does not manufacture customer evidence or security proof locally', () => {
    expect(source).not.toContain('localStorage');
    expect(source).not.toContain('Math.random');
    expect(source).not.toContain('captureFromScan');
    expect(source).not.toContain('captureFromRemediation');
    expect(source).toContain('No security claim is made.');
    expect(source).toContain('No reduction claim is made.');
  });

  it('keeps compromise outside the product proof boundary', () => {
    expect(source).toContain('Compromise is never inferred from correlation.');
    expect(source).toContain('measurable risk/path reduction');
  });
});
