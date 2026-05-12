import { readFileSync } from 'fs';
import { join } from 'path';

// Use process.cwd() which works correctly in Vercel Serverless Functions
const VAULT_PATH = join(process.cwd(), 'clients.json');

/**
 * Client Vault — In-memory registry backed by clients.json.
 * 
 * Future upgrade path:
 *   - Swap to Vercel KV: import { kv } from '@vercel/kv'; 
 *   - Swap to Postgres:  import { sql } from '@vercel/postgres';
 * 
 * Schema per client:
 *   {
 *     id: string,
 *     name: string,
 *     email: string,
 *     roleArn: string,            // AWS IAM Role ARN for cross-account access
 *     frameworks: string[],       // ['soc2', 'hipaa', 'gdpr', 'iso27001']
 *     autoRemediate: boolean      // Whether the agent can auto-fix findings
 *   }
 */

let _cache = null;

function loadVault() {
    if (_cache) return _cache;

    try {
        const raw = readFileSync(VAULT_PATH, 'utf-8');
        _cache = JSON.parse(raw);
        console.log(`[VAULT] Loaded ${_cache.length} client(s) from registry.`);
        return _cache;
    } catch (err) {
        console.error(`[VAULT] Failed to load clients.json:`, err.message);
        return [];
    }
}

/**
 * Returns all registered clients.
 */
export function getAllClients() {
    return loadVault();
}

/**
 * Returns a single client by ID, or null if not found.
 */
export function getClientById(id) {
    return loadVault().find(c => c.id === id) || null;
}

/**
 * Invalidate the in-memory cache (e.g. after adding a new client).
 */
export function refreshVault() {
    _cache = null;
    return loadVault();
}
