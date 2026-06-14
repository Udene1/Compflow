import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runScan } from '../../core/providers/digitalocean.js';
import { runRemediation } from '../../core/providers/digitalocean_remediator.js';

// Mock the global fetch function
global.fetch = vi.fn();

describe('DigitalOcean Provider - Deep Scan Logic', () => {
    const mockCredentials = { apiToken: 'fake-do-token' };

    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('should detect a droplet without backups enabled', async () => {
        fetch.mockImplementation((url) => {
            if (url.includes('/droplets')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    json: async () => ({
                        droplets: [{
                            name: 'prod-web-01',
                            region: { slug: 'nyc3' },
                            features: ['monitoring'],
                            networks: { v4: [{ type: 'public', ip_address: '1.2.3.4' }] },
                            tags: ['web']
                        }],
                        links: {}
                    })
                });
            }
            return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
        });

        const { resources } = await runScan('digitalocean', mockCredentials);
        const backupFinding = resources.find(r => r.technicalId === 'DO_DROPLET_BACKUP');
        expect(backupFinding).toBeDefined();
        expect(backupFinding.severity).toBe('warning');
    });

    it('should detect a public Space bucket', async () => {
        fetch.mockImplementation((url) => {
            if (url.includes('/spaces')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    json: async () => ({
                        spaces: [{ name: 'insecure-bucket', region: 'ams3', is_public: true }]
                    })
                });
            }
            return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
        });

        const { resources } = await runScan('digitalocean', mockCredentials);
        const spaceFinding = resources.find(r => r.technicalId === 'S3_PUBLIC_BUCKET');
        expect(spaceFinding).toBeDefined();
        expect(spaceFinding.severity).toBe('critical');
    });

    it('should detect app platform insecurities', async () => {
        fetch.mockImplementation((url) => {
            if (url.includes('/apps')) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    json: async () => ({
                        apps: [{
                            spec: {
                                name: 'hack-app',
                                services: [{
                                    envs: [{ key: 'DB_PASSWORD', value: 'secret', type: 'GENERAL' }]
                                }]
                            }
                        }]
                    })
                });
            }
            return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
        });

        const { resources } = await runScan('digitalocean', mockCredentials);
        const appFinding = resources.find(r => r.technicalId === 'DO_APP_INSECURE_ENV');
        expect(appFinding).toBeDefined();
        expect(appFinding.severity).toBe('critical');
    });
});

describe('DigitalOcean Remediator - Safety Logic', () => {
    it('should handle dryRun mode correctly', async () => {
        const result = await runRemediation('digitalocean', { apiToken: 'token' }, 'DO Droplet', 'test-vm', 'backups disabled', true);
        expect(result.success).toBe(true);
        expect(result.message).toContain('[DRY-RUN]');
    });

    it('should suggest advisory for non-whitelisted fixes', async () => {
        const result = await runRemediation('digitalocean', { apiToken: 'token' }, 'DO Firewall', 'fw-01', 'SSH (22) open', false);
        expect(result.success).toBe(true);
        expect(result.advisory).toBe(true);
        expect(result.message).toContain('ADVISORY');
    });

    it('should execute whitelisted fixes', async () => {
        const result = await runRemediation('digitalocean', { apiToken: 'token' }, 'DO Droplet', 'web-01', 'backups disabled', false);
        expect(result.success).toBe(true);
        expect(result.message).toContain('enabled');
    });
});
