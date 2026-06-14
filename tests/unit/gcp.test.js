import { describe, it, expect, vi } from 'vitest';
import { runScan } from '../../core/providers/gcp.js';

// Mock GCP SDKs
vi.mock('@google-cloud/compute', () => ({
    InstancesClient: vi.fn().mockImplementation(function() {
        return {
            aggregatedList: vi.fn(async () => [{
                'zones/us-central1-a': {
                    instances: [{
                        name: 'test-instance-public',
                        networkInterfaces: [{ accessConfigs: [{ natIP: '1.2.3.4' }] }],
                        shieldedInstanceConfig: { enableSecureBoot: false }
                    }]
                }
            }])
        };
    }),
    SnapshotsClient: vi.fn().mockImplementation(function() {
        return {
            list: vi.fn(async () => [[{
                name: 'test-old-snapshot',
                creationTimestamp: '2020-01-01T00:00:00Z'
            }]])
        };
    }),
    FirewallsClient: vi.fn().mockImplementation(function() { return {}; }),
    NetworksClient: vi.fn().mockImplementation(function() { return {}; })
}));

vi.mock('@google-cloud/container', () => ({
    ClusterManagerClient: vi.fn().mockImplementation(function() {
        return {
            listClusters: vi.fn(async () => [{
                clusters: [{
                    name: 'test-cluster-insecure',
                    location: 'us-central1',
                    masterAuthorizedNetworksConfig: { enabled: false },
                    shieldedNodes: { enabled: false },
                    workloadIdentityConfig: {} // Disabled
                }]
            }])
        };
    })
}));

vi.mock('@google-cloud/storage', () => ({
    Storage: vi.fn().mockImplementation(function() {
        return {
            getBuckets: vi.fn(async () => [[
                {
                    name: 'test-bucket',
                    getMetadata: vi.fn(async () => [{
                        location: 'US',
                        iamConfiguration: { uniformBucketLevelAccess: { enabled: false } },
                        versioning: { enabled: false }
                    }])
                }
            ]])
        };
    })
}));

vi.mock('@google-cloud/bigquery', () => ({
    BigQuery: vi.fn().mockImplementation(function() {
        return {
            getDatasets: vi.fn(async () => [[
                {
                    id: 'test-dataset-public',
                    getMetadata: vi.fn(async () => [{
                        location: 'US',
                        access: [{ iamMember: 'allUsers' }]
                    }])
                }
            ]])
        };
    })
}));

vi.mock('@google-cloud/sql', () => ({
    CloudSqlClient: vi.fn().mockImplementation(function() {
        return {
            instances: {
                list: vi.fn(async () => [[{
                    name: 'test-sql-public',
                    region: 'us-central1',
                    settings: { ipConfiguration: { ipv4Enabled: true }, backupConfiguration: { enabled: false } }
                }]])
            }
        };
    })
}));

vi.mock('@google-cloud/iam', () => ({
    IAMClient: vi.fn().mockImplementation(function() {
        return {
            listServiceAccounts: vi.fn(async () => [[{ name: 'projects/test/serviceAccounts/test-sa@test.iam.gserviceaccount.com', email: 'test-sa@test.iam.gserviceaccount.com' }]]),
            listServiceAccountKeys: vi.fn(async () => [[{ keyType: 'USER_MANAGED', validAfterTime: { seconds: 1577836800 } }]]) // 2020
        };
    })
}));

// Mock others
vi.mock('@google-cloud/secret-manager', () => ({ SecretManagerServiceClient: vi.fn().mockImplementation(function() { return { listSecrets: vi.fn(async () => [[]]) }; }) }));
vi.mock('@google-cloud/functions', () => ({ CloudFunctionsServiceClient: vi.fn().mockImplementation(function() { return { listFunctions: vi.fn(async () => [[]]) }; }) }));
vi.mock('@google-cloud/pubsub', () => ({ PubSub: vi.fn().mockImplementation(function() { return { getTopics: vi.fn(async () => [[]]) }; }) }));
vi.mock('@google-cloud/artifact-registry', () => ({ ArtifactRegistryClient: vi.fn().mockImplementation(function() { return { listRepositories: vi.fn(async () => [[]]) }; }) }));
vi.mock('@google-cloud/cloudbuild', () => ({ CloudBuildClient: vi.fn().mockImplementation(function() { return { listBuildTriggers: vi.fn(async () => [[]]) }; }) }));
vi.mock('@google-cloud/run', () => ({ ServicesClient: vi.fn().mockImplementation(function() { return { listServices: vi.fn(async () => [[]]) }; }) }));
vi.mock('@google-cloud/logging', () => ({ LoggingServiceV2Client: vi.fn().mockImplementation(function() { return { listSinks: vi.fn(async () => [[]]) }; }) }));
vi.mock('@google-cloud/resource-manager', () => ({ ProjectsClient: vi.fn().mockImplementation(function() { return {}; }) }));

describe('GCP Provider Scanner', () => {
    const credentials = {
        projectId: 'test-project',
        apiToken: JSON.stringify({ type: 'service_account' }),
        isObfuscated: false
    };

    it('should detect external IP on instances', async () => {
        const { resources } = await runScan('gcp', credentials);
        const instIssue = resources.find(r => r.issue === 'External IP address assigned');
        expect(instIssue).toBeDefined();
        expect(instIssue.severity).toBe('warning');
    });

    it('should detect old snapshots', async () => {
        const { resources } = await runScan('gcp', credentials);
        const snapIssue = resources.find(r => r.technicalId === 'GCP_OLD_SNAPSHOT');
        expect(snapIssue).toBeDefined();
    });

    it('should detect insecure GKE settings', async () => {
        const { resources } = await runScan('gcp', credentials);
        const masterNetIssue = resources.find(r => r.technicalId === 'GKE_MASTER_NETWORKS');
        const shieldedIssue = resources.find(r => r.technicalId === 'GKE_SHIELDED_NODES');
        const workloadIssue = resources.find(r => r.issue === 'Workload Identity is disabled');
        expect(masterNetIssue).toBeDefined();
        expect(shieldedIssue).toBeDefined();
        expect(workloadIssue).toBeDefined();
    });

    it('should detect public BigQuery datasets', async () => {
        const { resources } = await runScan('gcp', credentials);
        const bqIssue = resources.find(r => r.technicalId === 'BQ_PUBLIC_DATASET');
        expect(bqIssue).toBeDefined();
        expect(bqIssue.severity).toBe('critical');
    });

    it('should detect old Service Account Keys', async () => {
        const { resources } = await runScan('gcp', credentials);
        const keyIssue = resources.find(r => r.technicalId === 'GCP_SA_ROTATION');
        expect(keyIssue).toBeDefined();
        expect(keyIssue.issue).toContain('days old');
    });
});
