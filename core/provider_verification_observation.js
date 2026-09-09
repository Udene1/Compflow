/**
 * Converts real provider scan objects into the small, deterministic observation
 * shapes consumed by remediation verification. No value here is invented: a
 * field is emitted only when the provider actually returned it.
 */
export function normalizeProviderVerificationObservation({ provider, code, resourceId, observedResource }) {
  const normalizedProvider = String(provider || '').trim().toLowerCase();
  const normalizedCode = String(code || '').trim().toUpperCase();
  const resource = observedResource && typeof observedResource === 'object' ? observedResource : null;
  if (!resource) throw new Error('POSTCHECK_RESOURCE_NOT_OBSERVED');

  if (normalizedProvider !== 'azure') return { resource: resourceId, findingCode: normalizedCode, observedResource: resource };

  const observation = { resource: resourceId, findingCode: normalizedCode };
  if (normalizedCode === 'AZURE_STORAGE_PUBLIC_BLOB') {
    if (Object.prototype.hasOwnProperty.call(resource, 'allowBlobPublicAccess')) observation.allowBlobPublicAccess = resource.allowBlobPublicAccess;
  } else if (normalizedCode === 'AZURE_STORAGE_HTTPS') {
    if (Object.prototype.hasOwnProperty.call(resource, 'enableHttpsTrafficOnly')) observation.enableHttpsTrafficOnly = resource.enableHttpsTrafficOnly;
    if (Object.prototype.hasOwnProperty.call(resource, 'supportsHttpsTrafficOnly')) observation.supportsHttpsTrafficOnly = resource.supportsHttpsTrafficOnly;
  } else if (normalizedCode === 'AZURE_STORAGE_TLS') {
    if (Object.prototype.hasOwnProperty.call(resource, 'minimumTlsVersion')) observation.minimumTlsVersion = resource.minimumTlsVersion;
  } else if (normalizedCode === 'AZURE_SQL_PUBLIC_ACCESS') {
    if (Object.prototype.hasOwnProperty.call(resource, 'publicNetworkAccess')) observation.publicNetworkAccess = resource.publicNetworkAccess;
    if (Object.prototype.hasOwnProperty.call(resource, 'publicNetworkAccessEnabled')) observation.publicNetworkAccessEnabled = resource.publicNetworkAccessEnabled;
  } else if (normalizedCode === 'AZURE_APPSERVICE_HTTP_ALLOWED' || normalizedCode === 'AZURE_APP_HTTPS') {
    if (Object.prototype.hasOwnProperty.call(resource, 'httpsOnly')) observation.httpsOnly = resource.httpsOnly;
  } else if (normalizedCode === 'AZURE_NSG_OPEN_INBOUND') {
    if (Array.isArray(resource.securityRules)) observation.securityRules = resource.securityRules;
    if (Array.isArray(resource.rules)) observation.rules = resource.rules;
  }

  observation.observedResource = resource;
  return observation;
}
