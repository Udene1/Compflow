import { Router } from 'express';
import crypto from 'crypto';
import pool from '../core/db.js';
import { defaultSecretStore as SecretStore } from '../core/secret_store.js';
import { recordAuditEvent } from '../core/audit_events.js';
import { cloudVerifier } from '../core/cloud_verifier.js';
import { enqueueJob } from '../core/queue.js';
import { formatAssessmentSummary, getFrameworkDisplayName, getFrameworkTotalControls } from '../core/compliance_truth.js';
import { ControlMatrix } from '../core/controls.js';
import { log } from '../core/logger.js';

const router = Router();

// ─────────────────────────────────────────────────────────────────────────────
// Onboarding State Hierarchy Order
// AUTHENTICATED → ORGANIZATION_CREATED → OBJECTIVES_SELECTED → CLOUD_CONNECTED → ONBOARDING_COMPLETED
// ─────────────────────────────────────────────────────────────────────────────
const STATE_RANK = {
    AUTHENTICATED: 1,
    ORGANIZATION_CREATED: 2,
    OBJECTIVES_SELECTED: 3,
    CLOUD_CONNECTED: 4,
    ONBOARDING_COMPLETED: 5
};

function advanceState(currentState, nextState) {
    const currentRank = STATE_RANK[currentState] || 1;
    const nextRank = STATE_RANK[nextState] || 1;
    // Cannot regress completed states
    return nextRank > currentRank ? nextState : currentState;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. GET /api/onboarding/status
// ─────────────────────────────────────────────────────────────────────────────
router.get('/status', async (req, res) => {
    const orgId = req.user.orgId;

    try {
        // Fetch current onboarding state
        const stateRes = await pool.query('SELECT * FROM onboarding_state WHERE org_id = $1;', [orgId]);
        const onboardingState = stateRes.rows?.[0]?.status || 'AUTHENTICATED';

        // Fetch organization details
        const orgRes = await pool.query('SELECT * FROM organizations WHERE id = $1;', [orgId]);
        const org = orgRes.rows?.[0] || {};

        // Fetch selected frameworks
        const fwRes = await pool.query('SELECT framework_id, status, selected_at FROM organization_frameworks WHERE org_id = $1;', [orgId]);
        const frameworks = (fwRes.rows || []).map(r => r.framework_id);

        // Fetch active cloud connections
        const connRes = await pool.query(
            'SELECT id, provider, display_name, status, account_identifier, region, last_verified_at, error_message FROM cloud_connections WHERE organization_id = $1;',
            [orgId]
        );
        const connections = connRes.rows || [];

        res.json({
            onboardingStatus: onboardingState,
            organization: {
                id: org.id,
                name: org.name,
                domain: org.domain,
                website: org.website || null,
                industry: org.industry || null,
                companySize: org.company_size || null
            },
            frameworks,
            connections,
            complianceGuidance: 'Compflow will use these objectives to prioritize relevant controls and evidence.'
        });
    } catch (err) {
        log.error(`[ONBOARDING] Error fetching status for org ${orgId}:`, err.message);
        res.status(500).json({ error: 'Failed to retrieve onboarding status' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. POST /api/onboarding/organization
// ─────────────────────────────────────────────────────────────────────────────
router.post('/organization', async (req, res) => {
    const orgId = req.user.orgId;
    const { name, website, industry, companySize } = req.body || {};

    if (!name || typeof name !== 'string') {
        return res.status(400).json({ error: 'Validation Error', message: 'Organization name is required.' });
    }

    try {
        await pool.query(
            `UPDATE organizations 
             SET name = $1, website = $2, industry = $3, company_size = $4, updated_at = CURRENT_TIMESTAMP 
             WHERE id = $5;`,
            [name.trim(), website || null, industry || null, companySize || null, orgId]
        );

        // Advance state to ORGANIZATION_CREATED
        const stateRes = await pool.query('SELECT status FROM onboarding_state WHERE org_id = $1;', [orgId]);
        const current = stateRes.rows?.[0]?.status || 'AUTHENTICATED';
        const next = advanceState(current, 'ORGANIZATION_CREATED');

        await pool.query(
            `INSERT INTO onboarding_state (org_id, status) VALUES ($1, $2)
             ON CONFLICT (org_id) DO UPDATE SET status = $2, updated_at = CURRENT_TIMESTAMP;`,
            [orgId, next]
        );

        await recordAuditEvent(
            orgId,
            req.user.userId,
            'organization_updated',
            'organization',
            orgId,
            { name, industry, companySize, result: 'success' },
            req
        ).catch(() => {});

        res.json({
            success: true,
            status: next,
            organization: { id: orgId, name, website, industry, companySize }
        });
    } catch (err) {
        log.error(`[ONBOARDING] Failed to update organization:`, err.message);
        res.status(500).json({ error: 'Failed to update organization' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. POST /api/onboarding/objectives
// ─────────────────────────────────────────────────────────────────────────────
router.post('/objectives', async (req, res) => {
    const orgId = req.user.orgId;
    const { frameworks } = req.body || {};

    if (!Array.isArray(frameworks) || frameworks.length === 0) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Please select at least one compliance framework.'
        });
    }

    try {
        for (const frameworkId of frameworks) {
            const id = 'fw_' + crypto.randomUUID();
            await pool.query(
                `INSERT INTO organization_frameworks (id, org_id, framework_id, status, selected_by)
                 VALUES ($1, $2, $3, 'selected', $4)
                 ON CONFLICT (org_id, framework_id) DO NOTHING;`,
                [id, orgId, frameworkId.toLowerCase().trim(), req.user.userId]
            );

            await recordAuditEvent(
                orgId,
                req.user.userId,
                'framework_selected',
                'framework',
                frameworkId,
                { result: 'success' },
                req
            ).catch(() => {});
        }

        const stateRes = await pool.query('SELECT status FROM onboarding_state WHERE org_id = $1;', [orgId]);
        const current = stateRes.rows?.[0]?.status || 'AUTHENTICATED';
        const next = advanceState(current, 'OBJECTIVES_SELECTED');

        await pool.query(
            `INSERT INTO onboarding_state (org_id, status) VALUES ($1, $2)
             ON CONFLICT (org_id) DO UPDATE SET status = $2, updated_at = CURRENT_TIMESTAMP;`,
            [orgId, next]
        );

        res.json({
            success: true,
            status: next,
            selectedFrameworks: frameworks,
            guidance: 'Compflow will use these objectives to prioritize relevant controls and evidence.'
        });
    } catch (err) {
        log.error(`[ONBOARDING] Failed to save frameworks:`, err.message);
        res.status(500).json({ error: 'Failed to record objectives' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. POST /api/onboarding/cloud-connection
// ─────────────────────────────────────────────────────────────────────────────
router.post('/cloud-connection', async (req, res) => {
    const orgId = req.user.orgId;
    const { provider, displayName, accountIdentifier, region, credentials } = req.body || {};

    if (!provider) {
        return res.status(400).json({ error: 'Validation Error', message: 'Cloud provider is required.' });
    }

    const validProviders = ['aws', 'azure', 'gcp', 'digitalocean', 'hetzner'];
    if (!validProviders.includes(provider.toLowerCase())) {
        return res.status(400).json({
            error: 'Validation Error',
            message: `Unsupported provider "${provider}". Supported providers: ${validProviders.join(', ')}`
        });
    }

    const connId = 'conn_' + crypto.randomUUID().replace(/-/g, '').substring(0, 16);
    const credRef = 'sec_ref_' + connId;

    try {
        // Save encrypted credentials to SecretStore (Amendment 7)
        if (credentials) {
            await SecretStore.saveSecret(orgId, connId, credentials, req.user.userId);
        }

        // Save connection record with PENDING state (Amendment 10)
        await pool.query(
            `INSERT INTO cloud_connections (
                id, organization_id, provider, display_name, status, 
                account_identifier, region, credential_reference, created_by
            ) VALUES ($1, $2, $3, $4, 'PENDING', $5, $6, $7, $8);`,
            [
                connId,
                orgId,
                provider.toLowerCase(),
                displayName || `${provider.toUpperCase()} Connection`,
                accountIdentifier || null,
                region || 'us-east-1',
                credRef,
                req.user.userId
            ]
        );

        await recordAuditEvent(
            orgId,
            req.user.userId,
            'cloud_connection_created',
            'cloud_connection',
            connId,
            { provider: provider.toLowerCase(), region: region || 'us-east-1', result: 'success' },
            req
        ).catch(() => {});

        // Return connection metadata only — NEVER return credentials! (Amendment 8)
        res.status(201).json({
            success: true,
            connectionId: connId,
            provider: provider.toLowerCase(),
            status: 'PENDING',
            displayName: displayName || `${provider.toUpperCase()} Connection`
        });
    } catch (err) {
        log.error(`[ONBOARDING] Cloud connection creation failed:`, err.message);
        res.status(500).json({ error: 'Failed to create cloud connection' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. POST /api/onboarding/cloud-connection/:id/verify
// ─────────────────────────────────────────────────────────────────────────────
router.post('/cloud-connection/:id/verify', async (req, res) => {
    const orgId = req.user.orgId;
    const connId = req.params.id;

    try {
        const connRes = await pool.query(
            'SELECT * FROM cloud_connections WHERE id = $1 AND organization_id = $2;',
            [connId, orgId]
        );

        if (!connRes.rows || connRes.rows.length === 0) {
            return res.status(404).json({ error: 'Not Found', message: 'Cloud connection not found.' });
        }

        const conn = connRes.rows[0];

        // Connection state transition: PENDING → VERIFYING (Amendment 5)
        await pool.query('UPDATE cloud_connections SET status = $1 WHERE id = $2;', ['VERIFYING', connId]);

        // Retrieve secret via SecretStore to perform real provider verification
        const secret = await SecretStore.getSecret(orgId, connId, 'connection_verification', req.user.userId, req);

        if (!secret) {
            await pool.query(
                'UPDATE cloud_connections SET status = $1, error_code = $2, error_message = $3 WHERE id = $4;',
                ['FAILED', 'CLOUD_AUTHENTICATION_FAILED', 'No stored credentials found for connection.', connId]
            );

            await recordAuditEvent(
                orgId,
                req.user.userId,
                'cloud_connection_failed',
                'cloud_connection',
                connId,
                { provider: conn.provider, result: 'failed', errorCode: 'CLOUD_AUTHENTICATION_FAILED' },
                req
            ).catch(() => {});

            return res.status(400).json({
                verified: false,
                status: 'FAILED',
                errorCode: 'CLOUD_AUTHENTICATION_FAILED',
                message: 'No stored credentials found for connection. You can retry or update credentials.',
                retryable: true
            });
        }

        // Real Provider Verification with provenance capture (Amendment 2, 3, 4)
        const verifyResult = await cloudVerifier.verify(conn.provider, secret);

        if (verifyResult.verified) {
            // Save provenance in connection record: principal, accountIdentifier, verificationMethod
            await pool.query(
                `UPDATE cloud_connections 
                 SET status = 'VERIFIED',
                     account_identifier = $1,
                     principal = $2,
                     verification_method = $3,
                     last_verified_at = CURRENT_TIMESTAMP,
                     error_code = NULL,
                     error_message = NULL 
                 WHERE id = $4;`,
                [
                    verifyResult.accountIdentifier || null,
                    verifyResult.principal || null,
                    verifyResult.verificationMethod || `${conn.provider}:api_verification`,
                    connId
                ]
            );

            // Advance onboarding state to CLOUD_CONNECTED
            const stateRes = await pool.query('SELECT status FROM onboarding_state WHERE org_id = $1;', [orgId]);
            const current = stateRes.rows?.[0]?.status || 'AUTHENTICATED';
            const next = advanceState(current, 'CLOUD_CONNECTED');

            await pool.query(
                `INSERT INTO onboarding_state (org_id, status) VALUES ($1, $2)
                 ON CONFLICT (org_id) DO UPDATE SET status = $2, updated_at = CURRENT_TIMESTAMP;`,
                [orgId, next]
            );

            await recordAuditEvent(
                orgId,
                req.user.userId,
                'cloud_connection_verified',
                'cloud_connection',
                connId,
                {
                    provider: conn.provider,
                    accountIdentifier: verifyResult.accountIdentifier,
                    principal: verifyResult.principal,
                    verificationMethod: verifyResult.verificationMethod,
                    result: 'success'
                },
                req
            ).catch(() => {});

            // Create authoritative Scan Entity in `scans` table (Amendment 2)
            const scanId = 'scan_' + crypto.randomUUID().replace(/-/g, '').substring(0, 16);

            await pool.query(
                `INSERT INTO scans (id, organization_id, connection_id, scan_type, status)
                 VALUES ($1, $2, $3, 'initial_onboarding_scan', 'QUEUED');`,
                [scanId, orgId, connId]
            );

            // Actually enqueue BullMQ job via enqueueJob() with references ONLY (Amendment 1)
            const scanJobPayload = {
                jobId: scanId,
                scanId,
                organizationId: orgId,
                connectionId: connId,
                provider: conn.provider,
                scanType: 'initial_onboarding_scan',
                enqueuedAt: new Date().toISOString()
            };

            let finalScanStatus = 'QUEUED';
            try {
                await enqueueJob(scanJobPayload);
                log.info(`[ONBOARDING] Cloud verified. Scan ${scanId} queued for org ${orgId}`);
            } catch (queueErr) {
                // Queue failure: scan stays in DB but is marked FAILED (fail-closed)
                finalScanStatus = 'FAILED';
                await pool.query('UPDATE scans SET status = $1 WHERE id = $2;', ['FAILED', scanId]);
                log.error(`[ONBOARDING] Scan ${scanId} enqueue failed: ${queueErr.message}`);
            }

            return res.json({
                verified: true,
                status: 'VERIFIED',
                scanId,
                scanStatus: finalScanStatus,
                onboardingStatus: next,
                provenance: {
                    accountIdentifier: verifyResult.accountIdentifier,
                    principal: verifyResult.principal,
                    verificationMethod: verifyResult.verificationMethod
                },
                message: finalScanStatus === 'QUEUED'
                    ? 'Your environment is connected and verified. Compflow has queued your initial compliance scan.'
                    : 'Your environment is connected and verified, but the initial scan could not be queued. Please retry or contact support.'
            });
        } else {
            // Authentication failed — sanitized error code (Amendment 5)
            const errorCode = verifyResult.errorCode || 'CLOUD_AUTHENTICATION_FAILED';
            const errorMessage = verifyResult.errorMessage || 'Cloud connection verification failed.';

            await pool.query(
                'UPDATE cloud_connections SET status = $1, error_code = $2, error_message = $3 WHERE id = $4;',
                ['FAILED', errorCode, errorMessage, connId]
            );

            await recordAuditEvent(
                orgId,
                req.user.userId,
                'cloud_connection_failed',
                'cloud_connection',
                connId,
                { provider: conn.provider, errorCode, result: 'failed' },
                req
            ).catch(() => {});

            return res.status(400).json({
                verified: false,
                status: 'FAILED',
                errorCode,
                message: errorMessage,
                retryable: true
            });
        }
    } catch (err) {
        log.error(`[ONBOARDING] Connection verification error:`, err.message);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. POST /api/onboarding/complete
// ─────────────────────────────────────────────────────────────────────────────
router.post('/complete', async (req, res) => {
    const orgId = req.user.orgId;

    try {
        // Prerequisite validation: Organization exists
        const orgRes = await pool.query('SELECT id, name FROM organizations WHERE id = $1;', [orgId]);
        if (!orgRes.rows || orgRes.rows.length === 0) {
            return res.status(400).json({
                error: 'Prerequisite Failed',
                message: 'Organization profile must be set before completing onboarding.'
            });
        }

        // Prerequisite validation: Objectives selected
        const fwRes = await pool.query('SELECT framework_id FROM organization_frameworks WHERE org_id = $1;', [orgId]);
        if (!fwRes.rows || fwRes.rows.length === 0) {
            return res.status(400).json({
                error: 'Prerequisite Failed',
                message: 'At least one compliance framework objective must be selected before completing onboarding.'
            });
        }

        // Prerequisite validation: Cloud Connection exists and is VERIFIED
        const connRes = await pool.query('SELECT id, status FROM cloud_connections WHERE organization_id = $1;', [orgId]);
        const verifiedConn = (connRes.rows || []).find(c => c.status === 'VERIFIED');
        if (!verifiedConn) {
            return res.status(400).json({
                error: 'Prerequisite Failed',
                message: 'At least one verified cloud connection is required before completing onboarding.'
            });
        }

        // Prerequisite validation: Initial scan is QUEUED, RUNNING, or COMPLETED
        const scanRes = await pool.query('SELECT id, status FROM scans WHERE organization_id = $1;', [orgId]);
        const activeScan = (scanRes.rows || []).find(s => ['QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL'].includes(s.status));
        if (!activeScan) {
            return res.status(400).json({
                error: 'Prerequisite Failed',
                message: 'An initial compliance scan must be queued or completed before completing onboarding.'
            });
        }

        await pool.query(
            `INSERT INTO onboarding_state (org_id, status, completed_at, updated_at)
             VALUES ($1, 'ONBOARDING_COMPLETED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
             ON CONFLICT (org_id) DO UPDATE SET 
                status = 'ONBOARDING_COMPLETED',
                completed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP;`,
            [orgId]
        );

        await pool.query(
            `UPDATE organizations 
             SET onboarding_status = 'ONBOARDING_COMPLETED', updated_at = CURRENT_TIMESTAMP 
             WHERE id = $1;`,
            [orgId]
        );

        await recordAuditEvent(
            orgId,
            req.user.userId,
            'onboarding_completed',
            'organization',
            orgId,
            { result: 'success' },
            req
        ).catch(() => {});

        res.json({
            success: true,
            status: 'ONBOARDING_COMPLETED',
            message: 'Onboarding completed successfully. Welcome to Compflow!'
        });
    } catch (err) {
        log.error(`[ONBOARDING] Failed to complete onboarding:`, err.message);
        res.status(500).json({ error: 'Failed to complete onboarding' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. GET /api/onboarding/summary
// ─────────────────────────────────────────────────────────────────────────────
router.get('/summary', async (req, res) => {
    const orgId = req.user.orgId;

    try {
        const connRes = await pool.query(
            'SELECT provider, status, display_name FROM cloud_connections WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1;',
            [orgId]
        );
        const activeConn = connRes.rows?.[0] || { provider: 'NONE', status: 'PENDING' };

        const fwRes = await pool.query(
            'SELECT framework_id FROM organization_frameworks WHERE org_id = $1;',
            [orgId]
        );
        const selectedFws = (fwRes.rows || []).map(r => r.framework_id);

        // Fetch latest authoritative scan for this organization
        const scanRes = await pool.query(
            'SELECT * FROM scans WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1;',
            [orgId]
        );
        const latestScan = scanRes.rows?.[0] || null;

        // Authoritative scan status: QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, or PENDING (Amendment 4 & 5)
        const scanStatus = latestScan ? latestScan.status : 'PENDING';

        // If scan is NOT completed, do not invent numbers! (Amendment 3)
        if (!latestScan || scanStatus !== 'COMPLETED') {
            const frameworkStats = selectedFws.map(fw => ({
                id: fw.toLowerCase(),
                name: getFrameworkDisplayName(fw),
                controlsAssessed: 0,
                controlsPassing: 0,
                controlsNeedingAttention: 0,
                assessmentLabel: formatAssessmentSummary({ assessed: 0, framework: fw })
            }));

            return res.json({
                cloud: {
                    provider: activeConn.provider.toUpperCase(),
                    status: activeConn.status
                },
                scan: {
                    status: scanStatus,
                    resourcesDiscovered: 0
                },
                compliance: {
                    frameworks: frameworkStats,
                    findings: {
                        critical: 0,
                        high: 0,
                        medium: 0,
                        low: 0
                    },
                    evidenceCollected: 0,
                    disclaimer: 'Compflow uses these objective assessments to prioritize relevant controls and evidence. Technical checks currently reflect evaluated cloud configurations.'
                }
            });
        }

        // If scan IS completed, derive strictly from persisted findings (Amendment 6)
        const findingsRes = await pool.query(
            'SELECT severity, COUNT(*) FROM findings WHERE scan_id = $1 GROUP BY severity;',
            [latestScan.id]
        );

        const findingsCount = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const row of findingsRes.rows || []) {
            const sev = (row.severity || '').toLowerCase();
            const count = parseInt(row.count, 10) || 0;
            if (findingsCount[sev] !== undefined) {
                findingsCount[sev] = count;
            }
        }

        // Framework stats derived from persisted findings and control matrix
        const allFindingsRes = await pool.query(
            'SELECT control_id, status FROM findings WHERE scan_id = $1;',
            [latestScan.id]
        );
        const scanFindings = allFindingsRes.rows || [];

        const frameworkStats = selectedFws.map(fw => {
            const fwKey = fw.toLowerCase();
            const name = getFrameworkDisplayName(fw);
            const total = getFrameworkTotalControls(fw);

            // Filter findings that map to this framework
            const matchingFindings = scanFindings.filter(f => {
                if (!f.control_id) return false;
                const matrixEntry = ControlMatrix[f.control_id];
                if (!matrixEntry) return true;
                return Boolean(matrixEntry[fwKey]);
            });

            const controlsNeedingAttention = matchingFindings.filter(f => f.status === 'FAIL').length;
            const controlsPassing = matchingFindings.filter(f => f.status === 'PASS').length;
            const controlsAssessed = controlsPassing + controlsNeedingAttention;

            return {
                id: fwKey,
                name,
                controlsAssessed,
                controlsPassing,
                controlsNeedingAttention,
                assessmentLabel: formatAssessmentSummary({ assessed: controlsAssessed, total, framework: fw })
            };
        });

        res.json({
            cloud: {
                provider: activeConn.provider.toUpperCase(),
                status: activeConn.status
            },
            scan: {
                status: 'COMPLETED',
                resourcesDiscovered: latestScan.resources_discovered || 0
            },
            compliance: {
                frameworks: frameworkStats,
                findings: findingsCount,
                evidenceCollected: latestScan.evidence_count || 0,
                disclaimer: 'Compflow uses these objective assessments to prioritize relevant controls and evidence. Technical checks currently reflect evaluated cloud configurations.'
            }
        });
    } catch (err) {
        log.error(`[ONBOARDING] Summary retrieval error:`, err.message);
        res.status(500).json({ error: 'Failed to retrieve compliance summary' });
    }
});

export default router;
