import { S3Client, GetPublicAccessBlockCommand, GetBucketVersioningCommand, GetBucketEncryptionCommand, GetBucketLifecycleConfigurationCommand } from '@aws-sdk/client-s3';
import { EC2Client, DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { IAMClient, GetRoleCommand, ListRolePoliciesCommand, GetRolePolicyCommand, ListAttachedRolePoliciesCommand, GetPolicyCommand, GetPolicyVersionCommand } from '@aws-sdk/client-iam';
import pool from './db.js';
import { defaultSecretStore } from './secret_store.js';
import { getProvider } from './provider_registry.js';
import { recordEvidence } from './evidence.js';
import { appendExecutionEvent } from './execution_events.js';
import { upsertGraphNode, startNodeAttempt, finishNodeAttempt } from './execution_engine.js';

const CODES = new Set(['S3_PUBLIC_ACCESS','S3_VERSIONING_DISABLED','S3_ENCRYPTION_DISABLED','S3_LIFECYCLE_MISSING','SG_OPEN_SSH_WORLD','SG_OPEN_RDP_WORLD','SG_OPEN_HTTP_WORLD','RDS_PUBLICLY_ACCESSIBLE','RDS_BACKUP_DISABLED','IAM_WILDCARD_PERMISSION']);
function clean(value, max = 256) { return String(value ?? '').slice(0, max); }
function awsConfig(credentials) { if (!credentials?.accessKeyId || !credentials?.secretAccessKey) throw new Error('REMEDIATION_CREDENTIALS_UNAVAILABLE'); return { region: credentials.region || 'us-east-1', credentials: { accessKeyId: credentials.accessKeyId, secretAccessKey: credentials.secretAccessKey, ...(credentials.sessionToken ? { sessionToken: credentials.sessionToken } : {}) } }; }
function world(rule) { return (rule?.IpRanges || []).some(r => r?.CidrIp === '0.0.0.0/0') || (rule?.Ipv6Ranges || []).some(r => r?.CidrIpv6 === '::/0'); }
function covers(rule, port) { return rule?.IpProtocol === '-1' || (Number(rule?.FromPort) <= port && Number(rule?.ToPort) >= port); }
function decodePolicy(value) { try { return JSON.parse(decodeURIComponent(String(value))); } catch { try { return JSON.parse(String(value)); } catch { return null; } } }
function hasWildcardPermission(policy) {
  const statements = Array.isArray(policy?.Statement) ? policy.Statement : policy?.Statement ? [policy.Statement] : [];
  return statements.some(statement => {
    if (String(statement?.Effect || '').toUpperCase() !== 'ALLOW') return false;
    const actions = Array.isArray(statement?.Action) ? statement.Action : [statement?.Action];
    const resources = Array.isArray(statement?.Resource) ? statement.Resource : [statement?.Resource];
    return actions.some(action => action === '*') || resources.some(resource => resource === '*');
  });
}

async function collectIamWildcard(client, roleName) {
  await client.send(new GetRoleCommand({ RoleName: roleName }));
  const inlineNames = (await client.send(new ListRolePoliciesCommand({ RoleName: roleName }))).PolicyNames || [];
  const attached = (await client.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName }))).AttachedPolicies || [];
  const policies = [];
  for (const policyName of inlineNames.slice(0, 100)) {
    const value = await client.send(new GetRolePolicyCommand({ RoleName: roleName, PolicyName: policyName }));
    const document = decodePolicy(value.PolicyDocument);
    if (!document) throw new Error('IAM_POLICY_DOCUMENT_INVALID');
    policies.push({ type: 'inline', name: policyName, wildcard: hasWildcardPermission(document) });
  }
  for (const attachedPolicy of attached.slice(0, 100)) {
    if (!attachedPolicy?.PolicyArn) throw new Error('IAM_ATTACHED_POLICY_INVALID');
    const metadata = await client.send(new GetPolicyCommand({ PolicyArn: attachedPolicy.PolicyArn }));
    const versionId = metadata.Policy?.DefaultVersionId;
    if (!versionId) throw new Error('IAM_POLICY_VERSION_UNAVAILABLE');
    const version = await client.send(new GetPolicyVersionCommand({ PolicyArn: attachedPolicy.PolicyArn, VersionId: versionId }));
    const document = decodePolicy(version.PolicyVersion?.Document);
    if (!document) throw new Error('IAM_POLICY_DOCUMENT_INVALID');
    policies.push({ type: 'managed', name: attachedPolicy.PolicyName || attachedPolicy.PolicyArn, wildcard: hasWildcardPermission(document) });
  }
  return { resource: roleName, policyCount: policies.length, policies, inspectionComplete: true, wildcardPermission: policies.some(policy => policy.wildcard) };
}

async function collectAws(code, credentials, resourceId) {
  if (!CODES.has(code)) throw new Error('POSTCHECK_UNSUPPORTED_CODE');
  const config = awsConfig(credentials);
  if (code.startsWith('S3_')) {
    const client = new S3Client(config);
    if (code === 'S3_PUBLIC_ACCESS') {
      try { const value = await client.send(new GetPublicAccessBlockCommand({ Bucket: resourceId })); return { resource: resourceId, publicAccessBlockConfiguration: value.PublicAccessBlockConfiguration || {} }; }
      catch (error) { if (error?.name === 'NoSuchPublicAccessBlockConfiguration') return { resource: resourceId, publicAccessBlockConfiguration: null }; throw error; }
    }
    if (code === 'S3_VERSIONING_DISABLED') { const value = await client.send(new GetBucketVersioningCommand({ Bucket: resourceId })); return { resource: resourceId, versioningStatus: value.Status || null }; }
    if (code === 'S3_ENCRYPTION_DISABLED') { try { const value = await client.send(new GetBucketEncryptionCommand({ Bucket: resourceId })); return { resource: resourceId, encryptionRules: value.ServerSideEncryptionConfiguration?.Rules || [] }; } catch (error) { if (error?.name === 'ServerSideEncryptionConfigurationNotFoundError') return { resource: resourceId, encryptionRules: [] }; throw error; } }
    try { const value = await client.send(new GetBucketLifecycleConfigurationCommand({ Bucket: resourceId })); return { resource: resourceId, lifecycleRules: value.Rules || [] }; } catch (error) { if (error?.name === 'NoSuchLifecycleConfiguration') return { resource: resourceId, lifecycleRules: [] }; throw error; }
  }
  if (code.startsWith('SG_')) {
    const client = new EC2Client(config); const request = /^sg-[A-Za-z0-9]+$/.test(resourceId) ? { GroupIds: [resourceId] } : { GroupNames: [resourceId] };
    const value = await client.send(new DescribeSecurityGroupsCommand(request)); const sg = value.SecurityGroups?.[0]; if (!sg) throw new Error('POSTCHECK_RESOURCE_NOT_OBSERVED');
    const inspectedPort = code === 'SG_OPEN_SSH_WORLD' ? 22 : code === 'SG_OPEN_RDP_WORLD' ? 3389 : 80;
    return { resource: resourceId, groupId: sg.GroupId, groupName: sg.GroupName, worldOpen: (sg.IpPermissions || []).some(rule => covers(rule, inspectedPort) && world(rule)), inspectedPort };
  }
  if (code.startsWith('RDS_')) {
    const client = new RDSClient(config); const value = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: resourceId })); const db = value.DBInstances?.[0]; if (!db) throw new Error('POSTCHECK_RESOURCE_NOT_OBSERVED');
    return { resource: resourceId, publiclyAccessible: db.PubliclyAccessible === true, backupRetentionPeriod: Number(db.BackupRetentionPeriod || 0), multiAZ: db.MultiAZ === true };
  }
  if (code === 'IAM_WILDCARD_PERMISSION') return collectIamWildcard(new IAMClient(config), resourceId);
  throw new Error('POSTCHECK_UNSUPPORTED_CODE');
}

/** Collects fresh targeted provider state. It never creates synthetic success evidence. */
export async function collectRemediationPostcheck({ organizationId, executionId, remediationId, provider, credentials, connectionId, resourceId, code }) {
  if (!organizationId || !executionId || !remediationId || !provider || !credentials || !connectionId || !resourceId || !code) throw new Error('REMEDIATION_POSTCHECK_INPUT_INVALID');
  const definition = getProvider(provider); const normalizedCode = clean(code, 64).toUpperCase();
  const node = await upsertGraphNode({ organizationId, executionId, nodeType: 'REMEDIATION_POSTCHECK', logicalKey: remediationId, status: 'PENDING', label: `Post-remediation verification — ${resourceId}`, metadata: { provider: definition.id, connectionId, remediationId, findingCode: normalizedCode, resourceId } });
  const attempt = await startNodeAttempt({ organizationId, executionId, nodeId: node.id, metadata: { provider: definition.id, connectionId, remediationId, findingCode: normalizedCode, resourceId } });
  await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: 'REMEDIATION_POSTCHECK_STARTED', actorType: 'SYSTEM', result: 'started', payload: { remediationId, provider: definition.id, findingCode: normalizedCode, resourceId } });
  try {
    if (definition.id !== 'aws') throw new Error('POSTCHECK_PROVIDER_UNSUPPORTED');
    const observation = await collectAws(normalizedCode, credentials, resourceId);
    const evidenceRow = await recordEvidence({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, controlId: normalizedCode, provider: definition.id, connectionId, resourceId, sourceType: 'post_remediation_targeted_check', sourceRef: remediationId, evidenceKind: 'post_remediation_observation', observedAt: new Date().toISOString(), evidence: observation });
    await finishNodeAttempt({ attemptId: attempt.id, status: 'SUCCEEDED', metadata: { evidenceCount: 1 } });
    await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: 'REMEDIATION_POSTCHECK_FINISHED', actorType: 'SYSTEM', result: 'success', payload: { remediationId, findingCode: normalizedCode, resourceId, evidenceRecorded: 1 } });
    return { status: 'COLLECTED', evidence: [{ id: evidenceRow.id, resourceId: evidenceRow.resource_id, collectedAt: evidenceRow.collected_at, evidenceHash: evidenceRow.evidence_hash }], observation };
  } catch (error) {
    await finishNodeAttempt({ attemptId: attempt.id, status: 'FAILED', errorCode: clean(error.code || 'POSTCHECK_FAILED'), errorMessage: clean(error.message, 500) }).catch(() => {});
    await appendExecutionEvent({ organizationId, executionId, nodeId: node.id, attemptId: attempt.id, eventType: 'REMEDIATION_POSTCHECK_FINISHED', actorType: 'SYSTEM', result: 'failed', payload: { remediationId, findingCode: normalizedCode, resourceId, errorCode: clean(error.code || 'POSTCHECK_FAILED') } }).catch(() => {});
    throw error;
  }
}

/** Resolves the same org-scoped connection/secret used for remediation and performs a fresh targeted check. */
export async function runRemediationPostcheck({ organizationId, executionId, remediationId, actorId, req = null }) {
  const result = await pool.query(`SELECT r.payload FROM execution_events r WHERE r.organization_id=$1 AND r.execution_id=$2 AND r.event_type='REMEDIATION_PROPOSED' AND r.payload->'remediation'->>'id'=$3 ORDER BY r.occurred_at ASC LIMIT 1`, [organizationId, executionId, remediationId]);
  const remediation = result.rows[0]?.payload?.remediation;
  if (!remediation) throw new Error('REMEDIATION_NOT_FOUND');
  const execution = await pool.query('SELECT metadata FROM execution_runs WHERE organization_id=$1 AND id=$2', [organizationId, executionId]);
  const scanId = execution.rows[0]?.metadata?.scanId || execution.rows[0]?.metadata?.scan_id || null;
  if (!scanId) throw new Error('REMEDIATION_CONNECTION_UNAVAILABLE');
  const scan = await pool.query(`SELECT c.id,c.provider,c.region FROM scans s JOIN cloud_connections c ON c.id=s.connection_id WHERE s.organization_id=$1 AND s.id=$2`, [organizationId, scanId]);
  if (!scan.rows[0]) throw new Error('REMEDIATION_CONNECTION_UNAVAILABLE');
  const connection = scan.rows[0];
  const credentials = await defaultSecretStore.getSecret(organizationId, connection.id, 'remediation', actorId, req);
  if (!credentials) throw new Error('REMEDIATION_CREDENTIALS_UNAVAILABLE');
  return collectRemediationPostcheck({ organizationId, executionId, remediationId, provider: connection.provider, credentials: { ...credentials, ...(connection.region ? { region: credentials.region || connection.region } : {}) }, connectionId: connection.id, resourceId: remediation.resourceId, code: remediation.code });
}
