import { describe, expect, it } from 'vitest';
import { normalizeProviderVerificationObservation } from '../../core/provider_verification_observation.js';

describe('provider verification observation normalization', () => {
  it('preserves Azure Storage public-access state from the provider object', () => {
    const result = normalizeProviderVerificationObservation({
      provider: 'azure', code: 'AZURE_STORAGE_PUBLIC_BLOB', resourceId: 'storage-1',
      observedResource: { name: 'storage-1', allowBlobPublicAccess: false }
    });
    expect(result.allowBlobPublicAccess).toBe(false);
    expect(result.observedResource.name).toBe('storage-1');
  });

  it('preserves Azure App Service HTTPS state without manufacturing a value', () => {
    const result = normalizeProviderVerificationObservation({
      provider: 'azure', code: 'AZURE_APPSERVICE_HTTP_ALLOWED', resourceId: 'app-1',
      observedResource: { name: 'app-1', httpsOnly: true }
    });
    expect(result.httpsOnly).toBe(true);
  });

  it('does not invent a verification field when Azure did not return it', () => {
    const result = normalizeProviderVerificationObservation({
      provider: 'azure', code: 'AZURE_SQL_PUBLIC_ACCESS', resourceId: 'sql-1',
      observedResource: { name: 'sql-1' }
    });
    expect(Object.hasOwn(result, 'publicNetworkAccess')).toBe(false);
    expect(Object.hasOwn(result, 'publicNetworkAccessEnabled')).toBe(false);
  });

  it('leaves non-Azure observations provider-backed and untouched', () => {
    const observedResource = { id: 'bucket-1', public: false };
    const result = normalizeProviderVerificationObservation({ provider: 'gcp', code: 'GCP_BUCKET_PUBLIC', resourceId: 'bucket-1', observedResource });
    expect(result.observedResource).toBe(observedResource);
  });
});
