import { describe, it, expect, beforeEach } from 'vitest';
import { loadClients, saveClient, getClient } from '../../core/registry.js';
import tenantsHandler from '../../api/tenants.js';

describe('Phase 1 — Multi-Tenant Organization Isolation Engine', () => {

    beforeEach(async () => {
        // Reset and seed data across 2 distinct organizations
        await saveClient({
            id: 'tenant_alpha_aws_01',
            name: 'Alpha AWS Production',
            provider: 'aws',
            roleArn: 'arn:aws:iam::111111111111:role/AlphaRole',
            email: 'dev@alpha-corp.io',
            autoRemediate: true,
            status: 'active'
        }, 'org_alpha');

        await saveClient({
            id: 'tenant_alpha_azure_01',
            name: 'Alpha Azure Staging',
            provider: 'azure',
            apiToken: 'alpha-token-secret',
            email: 'dev@alpha-corp.io',
            autoRemediate: false,
            status: 'active'
        }, 'org_alpha');

        await saveClient({
            id: 'tenant_beta_gcp_01',
            name: 'Beta GCP Analytics',
            provider: 'gcp',
            apiToken: 'beta-token-secret',
            email: 'admin@beta-fintech.com',
            autoRemediate: true,
            status: 'active'
        }, 'org_beta');
    });

    describe('Registry Org-Scoped Queries', () => {
        it('loadClients(orgId) must ONLY return tenants owned by that organization', async () => {
            const alphaTenants = await loadClients('org_alpha');
            expect(alphaTenants.length).toBe(2);
            expect(alphaTenants.every(t => t.orgId === 'org_alpha')).toBe(true);

            const betaTenants = await loadClients('org_beta');
            expect(betaTenants.length).toBe(1);
            expect(betaTenants[0].id).toBe('tenant_beta_gcp_01');
            expect(betaTenants[0].orgId === 'org_beta').toBe(true);
        });

        it('loadClients() without org filter should return all tenants (for internal sweep workers)', async () => {
            const allTenants = await loadClients(null);
            expect(allTenants.length).toBeGreaterThanOrEqual(3);
        });

        it('getClient(id, orgId) must return tenant if org matches, and null if accessed by different org', async () => {
            // Authorized read by owning org
            const tenantAlpha = await getClient('tenant_alpha_aws_01', 'org_alpha');
            expect(tenantAlpha).not.toBeNull();
            expect(tenantAlpha.name).toBe('Alpha AWS Production');

            // Unauthorized read by different org (Org Beta trying to access Org Alpha's cloud credentials)
            const unauthorizedAccess = await getClient('tenant_alpha_aws_01', 'org_beta');
            expect(unauthorizedAccess).toBeNull();
        });
    });

    describe('API Tenants Handler Org-Isolation Enforcement', () => {
        function createMockRes() {
            const res = {
                statusCode: 200,
                headers: {},
                body: null,
                setHeader(k, v) { res.headers[k] = v; return res; },
                status(code) { res.statusCode = code; return res; },
                json(data) { res.body = data; return res; },
                end() { return res; }
            };
            return res;
        }

        it('GET /api/tenants should isolate results to req.user.orgId', async () => {
            const req = {
                method: 'GET',
                user: { orgId: 'org_beta', role: 'ADMIN', email: 'admin@beta-fintech.com' }
            };
            const res = createMockRes();

            await tenantsHandler(req, res);

            expect(res.statusCode).toBe(200);
            expect(res.body.orgId).toBe('org_beta');
            expect(res.body.tenants.length).toBe(1);
            expect(res.body.tenants[0].name).toBe('Beta GCP Analytics');
        });

        it('POST /api/tenants should automatically bind newly created tenants to req.user.orgId', async () => {
            const req = {
                method: 'POST',
                user: { orgId: 'org_gamma', role: 'ADMIN', email: 'lead@gamma-enterprise.org' },
                body: {
                    name: 'Gamma Hetzner Cluster',
                    provider: 'hetzner',
                    apiToken: 'hcloud-secret-token'
                }
            };
            const res = createMockRes();

            await tenantsHandler(req, res);

            expect(res.statusCode).toBe(201);
            expect(res.body.tenant.orgId).toBe('org_gamma');
            expect(res.body.tenant.name).toBe('Gamma Hetzner Cluster');

            // Verify org_beta cannot see Gamma's new tenant
            const betaView = await loadClients('org_beta');
            expect(betaView.some(t => t.name === 'Gamma Hetzner Cluster')).toBe(false);
        });

        it('PATCH /api/tenants should reject attempts by Org Beta to modify Org Alpha tenants with 404', async () => {
            const req = {
                method: 'PATCH',
                user: { orgId: 'org_beta', role: 'ADMIN', email: 'attacker@beta.com' },
                body: {
                    id: 'tenant_alpha_aws_01',
                    autoRemediate: false
                }
            };
            const res = createMockRes();

            await tenantsHandler(req, res);

            expect(res.statusCode).toBe(404);
            expect(res.body.error).toContain('Tenant not found or does not belong to your organization');
        });
    });
});
