import { describe, it, expect } from 'vitest';
import { runRemediation } from '../../core/remediator.js';

const providers = [
  ['digitalocean', 'DO Droplet', 'prod-droplet-db', 'backups disabled'],
  ['hetzner', 'Hetzner Server', 'node-01', 'backups disabled'],
  ['gcp', 'GCP Bucket', 'vault-bucket', 'Uniform bucket-level access disabled'],
  ['aws', 'S3 Bucket', 'public-data', 'Public access enabled'],
  ['azure', 'Azure App Service', 'app-portal', 'App Service does not enforce HTTPS-only traffic']
];

describe('Multi-cloud remediation execution boundary', () => {
  it.each(providers)('%s refuses execution without real credentials', async (provider, resourceType, resourceName, issue) => {
    const result = await runRemediation(provider, {}, resourceType, resourceName, issue, false);
    expect(result.success).toBe(false);
    expect(String(result.error || '')).toMatch(/credential/i);
  });
});
