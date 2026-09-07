// ─── ComplianceFlow AI: Standalone Worker Daemon Process ───
import { durableWorkerHandler } from './core/durable_worker.js';
import { listenWorkerQueue } from './core/queue.js';
import { initDb } from './db.js';

console.log('🚀 [WORKER DAEMON] Initializing PostgreSQL database connection & BullMQ worker listener...');

try {
    await initDb();
    listenWorkerQueue(durableWorkerHandler);
    console.log('✨ [WORKER DAEMON] Ready and listening for background scan tasks on BullMQ Redis queue.');
} catch (err) {
    console.error('❌ [WORKER DAEMON] Initialization error:', err);
    process.exit(1);
}
