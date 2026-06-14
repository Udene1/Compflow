import { describe, it, expect, vi } from 'vitest';
import { runScan } from '../../core/providers/azure.js';

// Mock Azure SDKs
vi.mock('@azure/identity', () => ({
    ClientSecretCredential: vi.fn().mockImplementation(function() { return {}; })
}));

// Helper to create an async iterator mock
const createAsyncIterable = (items) => ({
    [Symbol.asyncIterator]: async function* () {
        for (const item of items) {
            yield item;
        }
    }
});

vi.mock('@azure/arm-compute', () => ({
    ComputeManagementClient: vi.fn().mockImplementation(function() {
        return {
            virtualMachines: {
                listAll: vi.fn(() => createAsyncIterable([{
                    name: 'test-vm-public',
                    location: 'eastus',
                    networkProfile: {
                        networkInterfaces: [{ id: '/publicIPAddresses/test-ip' }]
                    },
                    storageProfile: {
                        osDisk: {
                            createOption: 'FromImage',
                            managedDisk: {}
                        }
                    }
                }]))
            }
        };
    })
}));

vi.mock('@azure/arm-network', () => ({
    NetworkManagementClient: vi.fn().mockImplementation(function() {
        return {
            networkSecurityGroups: {
                listAll: vi.fn(() => createAsyncIterable([{
                    name: 'test-nsg-open',
                    location: 'eastus',
                    securityRules: [
                        {
                            name: 'AllowSSH',
                            access: 'Allow',
                            direction: 'Inbound',
                            sourceAddressPrefix: '*',
                            destinationPortRange: '22'
                        }
                    ]
                }]))
            }
        };
    })
}));

vi.mock('@azure/arm-storage', () => ({
    StorageManagementClient: vi.fn().mockImplementation(function() {
        return {
            storageAccounts: {
                list: vi.fn(() => createAsyncIterable([
                    { name: 'teststorage', location: 'eastus', id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/teststorage' }
                ]))
            }
        };
    })
}));

vi.mock('@azure/arm-sql', () => ({
    SqlManagementClient: vi.fn().mockImplementation(function() {
        return {
            servers: {
                list: vi.fn(() => createAsyncIterable([
                    { name: 'testsql', location: 'eastus', publicNetworkAccess: 'Enabled' }
                ]))
            }
        };
    })
}));

vi.mock('@azure/arm-appservice', () => ({
    WebSiteManagementClient: vi.fn().mockImplementation(function() {
        return {
            webApps: {
                list: vi.fn(() => createAsyncIterable([
                    { name: 'testapp', location: 'eastus', httpsOnly: false }
                ]))
            }
        };
    })
}));

vi.mock('@azure/arm-recoveryservices', () => ({
    RecoveryServicesManagementClient: vi.fn().mockImplementation(function() {
        return {
            vaults: {
                listBySubscriptionId: vi.fn(() => createAsyncIterable([
                    { name: 'testvault', location: 'eastus', properties: { storageModelType: 'LocallyRedundant', softDeleteFeatureState: 'Disabled' } }
                ]))
            }
        };
    })
}));

// Mock other clients as empty lists to prevent errors
vi.mock('@azure/arm-keyvault', () => ({ KeyVaultManagementClient: vi.fn().mockImplementation(function() { return { vaults: { list: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-monitor', () => ({ MonitorClient: vi.fn().mockImplementation(function() { return { diagnosticSettings: { listByResource: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-servicebus', () => ({ ServiceBusManagementClient: vi.fn().mockImplementation(function() { return { namespaces: { list: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-policy', () => ({ PolicyClient: vi.fn().mockImplementation(function() { return {}; }) }));
vi.mock('@azure/arm-cdn', () => ({ CdnManagementClient: vi.fn().mockImplementation(function() { return { profiles: { list: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-dns', () => ({ DnsManagementClient: vi.fn().mockImplementation(function() { return {}; }) }));
vi.mock('@azure/arm-containerservice', () => ({ ContainerServiceClient: vi.fn().mockImplementation(function() { return { managedClusters: { list: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-containerregistry', () => ({ ContainerRegistryManagementClient: vi.fn().mockImplementation(function() { return { registries: { list: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-security', () => ({ SecurityCenter: vi.fn().mockImplementation(function() { return { pricings: { list: vi.fn(async () => [[]]) } }; }) }));
vi.mock('@azure/arm-authorization', () => ({ AuthorizationManagementClient: vi.fn().mockImplementation(function() { return { roleAssignments: { listForSubscription: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-logic', () => ({ LogicManagementClient: vi.fn().mockImplementation(function() { return { workflows: { listBySubscription: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-frontdoor', () => ({ FrontDoorManagementClient: vi.fn().mockImplementation(function() { return { frontDoors: { list: vi.fn(() => createAsyncIterable([])) } }; }) }));
vi.mock('@azure/arm-appinsights', () => ({ ApplicationInsightsManagementClient: vi.fn().mockImplementation(function() { return {}; }) }));
vi.mock('@azure/arm-subscriptions', () => ({ SubscriptionClient: vi.fn().mockImplementation(function() { return {}; }) }));
vi.mock('@azure/arm-containerinstance', () => ({ ContainerInstanceManagementClient: vi.fn().mockImplementation(function() { return {}; }) }));

describe('Azure Provider Scanner', () => {
    const credentials = {
        tenantId: 'test-tenant',
        accessKeyId: 'test-client-id',
        secretAccessKey: 'test-client-secret',
        projectId: 'test-sub-id',
        isObfuscated: false
    };

    it('should detect public IP exposure on VMs', async () => {
        const { resources } = await runScan('azure', credentials);
        const vmIssue = resources.find(r => r.technicalId === 'AZ_VM_PUBLIC_IP');
        expect(vmIssue).toBeDefined();
        expect(vmIssue.severity).toBe('warning');
    });

    it('should detect open SSH in NSG rules', async () => {
        const { resources } = await runScan('azure', credentials);
        const nsgIssue = resources.find(r => r.technicalId === 'SG_OPEN_PORTS');
        expect(nsgIssue).toBeDefined();
        expect(nsgIssue.severity).toBe('critical');
    });

    it('should detect HTTPS disabled on App Service', async () => {
        const { resources } = await runScan('azure', credentials);
        const appIssue = resources.find(r => r.technicalId === 'AZ_APP_HTTPS');
        expect(appIssue).toBeDefined();
        expect(appIssue.severity).toBe('critical');
    });

    it('should detect SQL public network access', async () => {
        const { resources } = await runScan('azure', credentials);
        const sqlIssue = resources.find(r => r.technicalId === 'RDS_PUBLIC');
        expect(sqlIssue).toBeDefined();
        expect(sqlIssue.severity).toBe('warning');
    });

    it('should detect insecure recovery vault settings', async () => {
        const { resources } = await runScan('azure', credentials);
        const lrsIssue = resources.find(r => r.issue === 'Vault uses Locally Redundant Storage (LRS)');
        const softDeleteIssue = resources.find(r => r.issue === 'Soft delete for backups is disabled');
        expect(lrsIssue).toBeDefined();
        expect(softDeleteIssue).toBeDefined();
    });
});
