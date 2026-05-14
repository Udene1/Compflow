import { saveAuditLog } from './audit.js';

/**
 * ComplianceFlow Centralized Audit Logger
 * Streams events to console and (optionally) to a persistent audit store.
 */
export class Logger {
    constructor(context = {}) {
        this.context = context; // { clientId, executionId, tenantName }
    }

    info(message, data = null) {
        this._log('INFO', message, data);
    }

    warn(message, data = null) {
        this._log('WARN', message, data);
    }

    error(message, error = null) {
        this._log('ERROR', message, error instanceof Error ? { message: error.message, stack: error.stack } : error);
    }

    audit(action, target, status, details = {}) {
        this._log('AUDIT', `${action} on ${target}: ${status}`, details);
    }

    _log(level, message, data) {
        const timestamp = new Date().toISOString();
        const prefix = `[${level}] [${this.context.clientId || 'SYSTEM'}]`;
        
        console.log(`${timestamp} ${prefix} ${message}`);
        
        // Persist to DynamoDB in the background
        if (this.context.clientId) {
            saveAuditLog(this.context.clientId, level, message, data).catch(() => {});
        }

        if (data && level !== 'AUDIT') {
            try {
                console.log(JSON.stringify(data, null, 2));
            } catch (e) {
                console.log("[DATA]", data);
            }
        }
    }
}

export const log = new Logger();
