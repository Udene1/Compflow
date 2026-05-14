import { loadClients, saveClient } from './core/registry.js';
import fs from 'fs';
import path from 'path';

const CLIENTS_JSON_PATH = path.resolve('clients.json');

async function migrate() {
    console.log("🚀 MIGRATION: JSON -> DynamoDB Registry...");

    if (!fs.existsSync(CLIENTS_JSON_PATH)) {
        console.error("❌ clients.json not found. Nothing to migrate.");
        return;
    }

    try {
        const clients = JSON.parse(fs.readFileSync(CLIENTS_JSON_PATH, 'utf8'));
        console.log(`[VAULT] Found ${clients.length} clients in local file.`);

        for (const client of clients) {
            console.log(`➤ Migrating: ${client.name}...`);
            await saveClient(client);
        }

        console.log("\n✨ MIGRATION COMPLETE!");
        console.log("You can now safely remove clients.json (or keep it as backup since it's gitignored).");
        console.log("The agent will now pull data from DynamoDB.");
        
    } catch (e) {
        console.error("❌ MIGRATION FAILED:", e.message);
    }
}

migrate();
