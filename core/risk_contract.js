const SEVERITY = Object.freeze({ LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 });

export function normalizeSeverity(value) {
  const normalized = String(value ?? '').trim().toUpperCase();
  return SEVERITY[normalized] ? normalized : 'LOW';
}

export function severityWeight(value) {
  return SEVERITY[normalizeSeverity(value)];
}

export function riskLevel(score) {
  const value = Number(score) || 0;
  if (value >= 80) return 'CRITICAL';
  if (value >= 55) return 'HIGH';
  if (value >= 30) return 'MEDIUM';
  return 'LOW';
}

export function capScore(score) {
  return Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
}

export const RISK_CONTRACT_VERSION = 'deterministic-risk-v1';
