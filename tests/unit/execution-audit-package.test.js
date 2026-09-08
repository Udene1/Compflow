import { describe, expect, it } from 'vitest';
import crypto from 'crypto';
import { verifyExecutionAuditPackage } from '../../core/execution_audit_package.js';

describe('durable execution audit package verification', () => {
  it('verifies a package manifest and signature', () => {
    const secret = 'execution-audit-test-secret';
    const pkg = { executionId: 'exec-1', evidence: [{ evidenceHash: 'abc' }], finalDecision: { outcome: 'PASS' } };
    const canonicalPkg = { evidence: pkg.evidence, executionId: pkg.executionId, finalDecision: pkg.finalDecision };
    const manifestHash = crypto.createHash('sha256').update(JSON.stringify(canonicalPkg)).digest('hex');
    const digitalSignature = crypto.createHmac('sha256', secret).update(manifestHash).digest('hex');
    const result = verifyExecutionAuditPackage({ manifestHash, digitalSignature, package: pkg }, secret);
    expect(result).toEqual({ verified: true, manifestHash });
  });

  it('rejects package tampering before signature acceptance', () => {
    const secret = 'execution-audit-test-secret';
    const pkg = { executionId: 'exec-1', evidence: [{ evidenceHash: 'abc' }] };
    const manifestHash = crypto.createHash('sha256').update(JSON.stringify({ evidence: pkg.evidence, executionId: pkg.executionId })).digest('hex');
    const digitalSignature = crypto.createHmac('sha256', secret).update(manifestHash).digest('hex');
    const tampered = { ...pkg, evidence: [{ evidenceHash: 'tampered' }] };
    const result = verifyExecutionAuditPackage({ manifestHash, digitalSignature, package: tampered }, secret);
    expect(result).toEqual({ verified: false, reason: 'AUDIT_PACKAGE_MANIFEST_MISMATCH' });
  });

  it('fails closed when the signing secret is unavailable', () => {
    const result = verifyExecutionAuditPackage({ manifestHash: 'a'.repeat(64), digitalSignature: 'b'.repeat(64), package: {} }, undefined);
    expect(result).toEqual({ verified: false, reason: 'AUDITOR_SIGNING_SECRET_REQUIRED' });
  });
});
