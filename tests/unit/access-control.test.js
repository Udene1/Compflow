import { describe, expect, it } from 'vitest';
import { evaluateEntitlement, ENTITLEMENT_STATUS, PLAN } from '../../core/access_control.js';

describe('service entitlement contract', () => {
  it('denies organizations with no entitlement', () => {
    const result = evaluateEntitlement(null);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('SERVICE_ENTITLEMENT_REQUIRED');
  });

  it('allows active paid service', () => {
    const result = evaluateEntitlement({ plan: PLAN.STANDARD, status: ENTITLEMENT_STATUS.ACTIVE, expires_at: null });
    expect(result.allowed).toBe(true);
  });

  it('allows an explicit pilot entitlement until it expires', () => {
    const now = new Date('2026-09-09T00:00:00.000Z');
    const result = evaluateEntitlement({ plan: PLAN.PILOT, status: ENTITLEMENT_STATUS.PILOT, expires_at: '2026-09-10T00:00:00.000Z' }, now);
    expect(result.allowed).toBe(true);
  });

  it('fails closed for expired, canceled, and past-due access', () => {
    const now = new Date('2026-09-09T00:00:00.000Z');
    expect(evaluateEntitlement({ plan: PLAN.PILOT, status: ENTITLEMENT_STATUS.PILOT, expires_at: '2026-09-08T00:00:00.000Z' }, now).allowed).toBe(false);
    expect(evaluateEntitlement({ plan: PLAN.STANDARD, status: ENTITLEMENT_STATUS.CANCELED }, now).allowed).toBe(false);
    expect(evaluateEntitlement({ plan: PLAN.STANDARD, status: ENTITLEMENT_STATUS.PAST_DUE }, now).allowed).toBe(false);
  });
});
