const PROVIDERS = Object.freeze({
  aws: { scan: () => import('./providers/aws.js'), remediate: () => import('./providers/aws_remediator.js') },
  azure: { scan: () => import('./providers/azure.js'), remediate: () => import('./providers/azure_remediator.js') },
  gcp: { scan: () => import('./providers/gcp.js'), remediate: () => import('./providers/gcp_remediator.js') },
  digitalocean: { scan: () => import('./providers/digitalocean.js'), remediate: () => import('./providers/digitalocean_remediator.js') },
  hetzner: { scan: () => import('./providers/hetzner.js'), remediate: () => import('./providers/hetzner_remediator.js') }
});

export function normalizeProvider(provider) {
  const value = String(provider || '').trim().toLowerCase();
  return value === 'do' ? 'digitalocean' : value;
}

export function getProvider(provider) {
  const normalized = normalizeProvider(provider);
  const definition = PROVIDERS[normalized];
  if (!definition) throw new Error(`Unsupported cloud provider: ${provider}`);
  return { id: normalized, ...definition };
}

export function listProviders() {
  return Object.keys(PROVIDERS);
}
