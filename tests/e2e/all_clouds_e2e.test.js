import { describe, it, expect } from 'vitest';
import { runRemediation } from '../../core/remediator.js';
import { getRemediationBreakpointDefinition } from '../../core/remediation_breakpoints.js';

const supported = [
  ['aws', 'S3 Bucket', 'public-data', 'S3_PUBLIC_ACCESS'],
  ['azure', 'Azure App Service', 'app-portal', 'AZURE_APPSERVICE_HTTP_ALLOWED']
];

const unsupported = [
  ['digitalocean', 'DO Droplet', 'prod-droplet-db', 'backups disabled'],
  ['hetzner', 'Hetzner Server', 'node-01', 'backups disabled'],
  ['gcp', 'GCP Bucket', 'vault-bucket', 'Uniform bucket-level access disabled']
];

describe('Multi-cloud remediation execution boundary', () => {
  it.each(supported)('%s refuses execution without real credentials', async (provider, resourceType, resourceName, findingCode) => {
    const candidate = getRemediationBreakpointDefinition(findingCode);
    const result = await runRemediation(provider, {}, resourceType, resourceName, candidate.action, false, { findingCode });
    expect(result.success).toBe(false);
    expect(String(result.error || '')).toMatch(/credential/i);
  });

  it.each(unsupported)('%s fails closed when no canonical remediation authority exists', async (provider, resourceType, resourceName, issue) => {
    await expect(runRemediation(provider, {}, resourceType, resourceName, issue, false)).rejects.toThrow(/REMEDIATION_POLICY_UNDEFINED/);
  });
});
