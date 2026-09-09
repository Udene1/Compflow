// ─── ComplianceFlow AI: Job Manager (PostgreSQL + EventEmitter) ───

import pool, { initDb } from './db.js';
import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';

export const jobEvents = new EventEmitter();
jobEvents.setMaxListeners(100);

initDb();

const TTL_DAYS = 7;

export async function createJob(clientId, scanType = 'on_demand', organizationId = null) {
    const jobId = randomUUID();
    const now = new Date();
    const expiresAt = Math.floor(Date.now() / 1000) + (TTL_DAYS * 86400);
    const initialLog = { timestamp: now.toISOString(), level: 'SYSTEM', message: `Job created (${scanType})` };

    await pool.query(`
        INSERT INTO jobs (job_id, client_id, org_id, scan_type, status, progress, logs, resources, created_at, updated_at, expires_at)
        VALUES ($1, $2, $3, $4, 'queued', 0, $5::jsonb, $6::jsonb, $7, $7, $8)
        RETURNING job_id
    `, [jobId, clientId, organizationId, scanType, JSON.stringify([initialLog]), JSON.stringify([]), now, expiresAt]);

    jobEvents.emit('update', jobId, { jobId, status: 'queued', progress: 0, logs: [initialLog], resources: [] });
    return jobId;
}

export async function updateJobProgress(jobId, status, progress, level, message) {
    const now = new Date();
    const logEntry = { timestamp: now.toISOString(), level, message };
    try {
        const res = await pool.query(`
            UPDATE jobs SET status = $1, progress = $2, updated_at = $3, logs = logs || $4::jsonb
            WHERE job_id = $5 RETURNING *
        `, [status, progress, now, JSON.stringify([logEntry]), jobId]);
        const updatedJob = res.rows[0];
        if (updatedJob) jobEvents.emit('update', jobId, {
            jobId, status: updatedJob.status, progress: updatedJob.progress,
            newLog: logEntry, logs: updatedJob.logs
        });
    } catch (e) {
        console.error(`[JOBS] Failed to update job ${jobId}:`, e.message);
    }
}

export async function completeJob(jobId, status, resources = [], errorMessage = null) {
    const now = new Date();
    const finalLog = {
        timestamp: now.toISOString(),
        level: status === 'completed' ? 'OUTPUT' : 'INSIGHT',
        message: status === 'completed' ? `Scan completed. ${resources.length} resources found.` : `Scan failed: ${errorMessage}`
    };
    const finalProgress = status === 'completed' ? 100 : -1;
    try {
        const res = await pool.query(`
            UPDATE jobs SET status = $1, progress = $2, updated_at = $3, completed_at = $3,
                logs = logs || $4::jsonb, resources = $5::jsonb, error_message = $6
            WHERE job_id = $7 RETURNING *
        `, [status, finalProgress, now, JSON.stringify([finalLog]), JSON.stringify(resources), errorMessage, jobId]);
        const updatedJob = res.rows[0];
        if (updatedJob) jobEvents.emit('update', jobId, {
            jobId, status: updatedJob.status, progress: updatedJob.progress,
            newLog: finalLog, logs: updatedJob.logs, resources: updatedJob.resources,
            errorMessage: updatedJob.error_message, completedAt: updatedJob.completed_at
        });
    } catch (e) {
        console.error(`[JOBS] Failed to complete job ${jobId}:`, e.message);
    }
}

export async function getJob(jobId, organizationId = null) {
    try {
        const params = [jobId];
        let query = 'SELECT * FROM jobs WHERE job_id = $1';
        if (organizationId) { query += ' AND org_id = $2'; params.push(organizationId); }
        const res = await pool.query(query, params);
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
            jobId: row.job_id, clientId: row.client_id, organizationId: row.org_id,
            scanType: row.scan_type, status: row.status, progress: row.progress,
            logs: row.logs || [], resources: row.resources || [],
            errorMessage: row.error_message || null, createdAt: row.created_at,
            updatedAt: row.updated_at, completedAt: row.completed_at
        };
    } catch (e) {
        console.error(`[JOBS] Failed to get job ${jobId}:`, e.message);
        return null;
    }
}

export async function getJobHistory(clientId, limit = 5, organizationId = null) {
    try {
        const params = [clientId, limit];
        let query = 'SELECT * FROM jobs WHERE client_id = $1';
        if (organizationId) { query += ' AND org_id = $3'; params.push(organizationId); }
        query += ' ORDER BY created_at DESC LIMIT $2';
        const res = await pool.query(query, params);
        return res.rows.map(row => ({
            jobId: row.job_id, clientId: row.client_id, organizationId: row.org_id,
            scanType: row.scan_type, status: row.status, progress: row.progress,
            logs: row.logs || [], resources: row.resources || [],
            errorMessage: row.error_message || null, createdAt: row.created_at,
            updatedAt: row.updated_at, completedAt: row.completed_at
        }));
    } catch (e) {
        console.error(`[JOBS] Failed to fetch history for ${clientId}:`, e.message);
        return [];
    }
}
