import { describe, expect, it } from 'vitest';
import { buildAnalystContext } from '../../core/ai_analyst.js';

describe('evidence-grounded AI analyst', () => {
  it('passes only bounded deterministic facts into the analyst context', () => {
    const context = buildAnalystContext({
      findings: [{ id: 'f1', code: 'SG_OPEN_HTTP_WORLD', resource_id: 'web', control_id: 'CC6.6', severity: 'HIGH', status: 'FAIL' }],
      paths: [{ id: 'p1', status: 'POTENTIAL', severity: 'HIGH', confidence: '0.75', evidence_complete: true, title: 'web → bucket', summary: 'candidate', nodes: [{ resource_id: 'web', node_type: 'COMPUTE', label: 'web', finding_ids: ['f1'], evidence_ids: ['e1'] }], edges: [] }],
      evidence: [{ id: 'e1', control_id: 'CC6.6', provider: 'aws', resource_id: 'web', source_type: 'ec2', evidence_hash: 'hash', observed_at: '2026-09-08T00:00:00Z', secret: 'must-not-be-forwarded' }]
    });

    expect(context.findings[0]).toEqual({ id: 'f1', code: 'SG_OPEN_HTTP_WORLD', resourceId: 'web', controlId: 'CC6.6', severity: 'HIGH', status: 'FAIL' });
    expect(context.paths[0].id).toBe('p1');
    expect(context.paths[0].confidence).toBe(0.75);
    expect(context.evidence[0]).not.toHaveProperty('secret');
  });

  it('does not require a fake AI response when the provider is unavailable', async () => {
    const previous = process.env.GEMINI_API_KEY;
    delete process.env.GEMINI_API_KEY;
    const { analyzeSecurityContext } = await import('../../core/ai_analyst.js');
    await expect(analyzeSecurityContext({ findings: [{ id: 'f1', code: 'X', resource_id: 'r1' }] })).rejects.toThrow('AI_ANALYST_UNAVAILABLE');
    if (previous !== undefined) process.env.GEMINI_API_KEY = previous;
  });
});
