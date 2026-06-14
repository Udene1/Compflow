import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runScan } from '../../core/providers/hetzner.js';
import { runRemediation } from '../../core/providers/hetzner_remediator.js';

// Mock global fetch
global.fetch = vi.fn();

describe('Hetzner Provider - Deep Scan Logic', () => {
    const mockCredentials = { apiToken: 'fake-hetzner-token' };

    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('should detect an exposed server (no firewall)', async () => {
        fetch.mockImplementation((url) => {
            if (url.includes('/servers')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    json: async () => ({
                        servers: [{
                            name: 'exposed-node',
                            status: 'running',
                            public_net: { ipv4: { ip: '5.6.7.8' }, firewalls: [] },
                            datacenter: { location: { name: 'nbg1' } }
                        }],
                        meta: { pagination: { last_page: 1 } }
                    })
                });
            }
            return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
        });

        const { resources } = await runScan('hetzner', mockCredentials);
        const exposedFinding = resources.find(r => r.technicalId === 'HETZNER_SERVER_EXPOSED');
        expect(exposedFinding).toBeDefined();
        expect(exposedFinding.severity).toBe('critical');
    });

    it('should detect rescue mode active', async () => {
        fetch.mockImplementation((url) => {
            if (url.includes('/servers')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    json: async () => ({
                        servers: [{
                            name: 'rescue-node',
                            rescue_enabled: true,
                            public_net: { firewalls: [{ id: 1 }] }
                        }]
                    })
                });
            }
            return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
        });

        const { resources } = await runScan('hetzner', mockCredentials);
        const rescueFinding = resources.find(r => r.technicalId === 'HETZNER_RESCUE_MODE_ACTIVE');
        expect(rescueFinding).toBeDefined();
        expect(rescueFinding.severity).toBe('critical');
    });

    it('should detect missing backups on servers', async () => {
        fetch.mockImplementation((url) => {
            if (url.includes('/servers')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    json: async () => ({
                        servers: [{
                            name: 'prod-db',
                            backup_window: null,
                            public_net: { firewalls: [{ id: 1 }] }
                        }]
                    })
                });
            }
            return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
        });

        const { resources } = await runScan('hetzner', mockCredentials);
        const backupFinding = resources.find(r => r.technicalId === 'HETZNER_BACKUP_DISABLED');
        expect(backupFinding).toBeDefined();
        expect(backupFinding.severity).toBe('critical');
    });
});

describe('Hetzner Remediator - Safety Logic', () => {
    it('should handle dryRun mode correctly', async () => {
        const result = await runRemediation('hetzner', { apiToken: 'token' }, 'Hetzner Server', 'test-node', 'backups disabled', true);
        expect(result.success).toBe(true);
        expect(result.message).toContain('[DRY-RUN]');
    });

    it('should enforce auto-delete on Primary IPs', async () => {
        const result = await runRemediation('hetzner', { apiToken: 'token' }, 'Hetzner Primary IP', '1.2.3.4', 'Auto-delete disabled', false);
        expect(result.success).toBe(true);
        expect(result.message).toContain('Auto-delete enabled');
    });
});
