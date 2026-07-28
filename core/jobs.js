// ─── ComplianceFlow AI: Job Manager (PostgreSQL + EventEmitter) ───

import pool, { initDb } from './db.js';
import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';

export const jobEvents = new EventEmitter();
jobEvents.setMaxListeners(100);

// Initialize DB schema on module load
initDb();

const TTL_DAYS = 7;

/**
 * Creates a new job record in PostgreSQL. Returns the jobId.
 * @param {string} clientId - The tenant/client ID
 * @param {string} scanType - 'on_demand' or 'scheduled'
 * @returns {Promise<string>} jobId
 */
export async function createJob(clientId, scanType = 'on_demand') {
    const jobId = randomUUID();
    const now = new Date();
    const expiresAt = Math.floor(Date.now() / 1000) + (TTL_DAYS * 86400);

    const initialLog = { timestamp: now.toISOString(), level: 'SYSTEM', message: `Job created (${scanType})` };

    const query = `
        INSERT INTO jobs (job_id, client_id, scan_type, status, progress, logs, resources, created_at, updated_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $8, $9)
        RETURNING job_id;
    `;

    await pool.query(query, [
        jobId,
        clientId,
        scanType,
        'queued',
        0,
        JSON.stringify([initialLog]),
        JSON.stringify([]),
        now,
        expiresAt
    ]);

    // Emit initial event for SSE listeners
    jobEvents.emit('update', jobId, {
        jobId,
        status: 'queued',
        progress: 0,
        logs: [initialLog],
        resources: []
    });

    return jobId;
}

/**
 * Updates job progress, status, and appends a log entry in PostgreSQL.
 * @param {string} jobId
 * @param {string} status - 'queued' | 'in_progress' | 'completed' | 'failed'
 * @param {number} progress - 0-100
 * @param {string} level - log level
 * @param {string} message - log message
 */
export async function updateJobProgress(jobId, status, progress, level, message) {
    const now = new Date();
    const logEntry = { timestamp: now.toISOString(), level, message };

    try {
        const query = `
            UPDATE jobs
            SET status = $1,
                progress = $2,
                updated_at = $3,
                logs = logs || $4::jsonb
            WHERE job_id = $5
            RETURNING *;
        `;

        const res = await pool.query(query, [
            status,
            progress,
            now,
            JSON.stringify([logEntry]),
            jobId
        ]);

        const updatedJob = res.rows[0];
        if (updatedJob) {
            // Broadcast live update to SSE subscribers
            jobEvents.emit('update', jobId, {
                jobId,
                status: updatedJob.status,
                progress: updatedJob.progress,
                newLog: logEntry,
                logs: updatedJob.logs
            });
        }
    } catch (e) {
        console.error(`[JOBS] Failed to update job ${jobId}:`, e.message);
    }
}

/**
 * Marks a job as completed or failed, stores final resources in PostgreSQL.
 * @param {string} jobId
 * @param {'completed'|'failed'} status
 * @param {Array} resources - scan results (only on completed)
 * @param {string} [errorMessage] - error message (only on failed)
 */
export async function completeJob(jobId, status, resources = [], errorMessage = null) {
    const now = new Date();
    const finalLog = {
        timestamp: now.toISOString(),
        level: status === 'completed' ? 'OUTPUT' : 'INSIGHT',
        message: status === 'completed'
            ? `Scan completed. ${resources.length} resources found.`
            : `Scan failed: ${errorMessage}`
    };

    const finalProgress = status === 'completed' ? 100 : -1;

    try {
        const query = `
            UPDATE jobs
            SET status = $1,
                progress = $2,
                updated_at = $3,
                completed_at = $3,
                logs = logs || $4::jsonb,
                resources = $5::jsonb,
                error_message = $6
            WHERE job_id = $7
            RETURNING *;
        `;

        const res = await pool.query(query, [
            status,
            finalProgress,
            now,
            JSON.stringify([finalLog]),
            JSON.stringify(resources),
            errorMessage,
            jobId
        ]);

        const updatedJob = res.rows[0];
        if (updatedJob) {
            jobEvents.emit('update', jobId, {
                jobId,
                status: updatedJob.status,
                progress: updatedJob.progress,
                newLog: finalLog,
                logs: updatedJob.logs,
                resources: updatedJob.resources,
                errorMessage: updatedJob.error_message,
                completedAt: updatedJob.completed_at
            });
        }
    } catch (e) {
        console.error(`[JOBS] Failed to complete job ${jobId}:`, e.message);
    }
}

/**
 * Reads the current state of a job from PostgreSQL.
 * @param {string} jobId
 * @returns {Promise<Object|null>}
 */
export async function getJob(jobId) {
    try {
        const res = await pool.query('SELECT * FROM jobs WHERE job_id = $1', [jobId]);
        if (res.rows.length === 0) return null;

        const row = res.rows[0];
        return {
            jobId: row.job_id,
            clientId: row.client_id,
            scanType: row.scan_type,
            status: row.status,
            progress: row.progress,
            logs: row.logs || [],
            resources: row.resources || [],
            errorMessage: row.error_message || null,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
            completedAt: row.completed_at
        };
    } catch (e) {
        console.error(`[JOBS] Failed to get job ${jobId}:`, e.message);
        return null;
    }
}

/**
 * Retrieves recent job history for a client.
 * @param {string} clientId
 * @param {number} limit
 * @returns {Promise<Array>}
 */
export async function getJobHistory(clientId, limit = 5) {
    try {
        const res = await pool.query(
            'SELECT * FROM jobs WHERE client_id = $1 ORDER BY created_at DESC LIMIT $2',
            [clientId, limit]
        );
        return res.rows.map(row => ({
            jobId: row.job_id,
            clientId: row.client_id,
            scanType: row.scan_type,
            status: row.status,
            progress: row.progress,
            logs: row.logs || [],
            resources: row.resources || [],
            errorMessage: row.error_message || null,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
            completedAt: row.completed_at
        }));
    } catch (e) {
        console.error(`[JOBS] Failed to fetch history for ${clientId}:`, e.message);
        return [];
    }
}
