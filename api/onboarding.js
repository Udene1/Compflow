import { Router } from 'express';
import crypto from 'crypto';
import pool from '../core/db.js';
import { defaultSecretStore as SecretStore } from '../core/secret_store.js';
import { recordAuditEvent } from '../core/audit_events.js';
import { cloudVerifier } from '../core/cloud_verifier.js';
import { enqueueJob } from '../core/queue.js';
import { createJob } from '../core/jobs.js';
import { formatAssessmentSummary, getFrameworkDisplayName, getFrameworkTotalControls } from '../core/compliance_truth.js';
import { ControlMatrix } from '../core/controls.js';
import { log } from '../core/logger.js';

const router = Router();
const STATE_RANK = { AUTHENTICATED: 1, ORGANIZATION_CREATED: 2, OBJECTIVES_SELECTED: 3, CLOUD_CONNECTED: 4, ONBOARDING_COMPLETED: 5 };
function advanceState(currentState, nextState) { const currentRank = STATE_RANK[currentState] || 1; const nextRank = STATE_RANK[nextState] || 1; return nextRank > currentRank ? nextState : currentState; }
function jsonError(res, status, code, message) { return res.status(status).json({ error: code, code, message }); }

router.get('/status', async (req, res) => {
    const orgId = req.user.orgId;
    try {
        const stateRes = await pool.query('SELECT * FROM onboarding_state WHERE org_id = $1;', [orgId]);
        const onboardingState = stateRes.rows?.[0]?.status || 'AUTHENTICATED';
        const orgRes = await pool.query('SELECT * FROM organizations WHERE id = $1;', [orgId]);
        const org = orgRes.rows?.[0] || {};
        const fwRes = await pool.query('SELECT framework_id, status, selected_at FROM organization_frameworks WHERE org_id = $1;', [orgId]);
        const connRes = await pool.query('SELECT id, provider, display_name, status, account_identifier, region, last_verified_at, error_message FROM cloud_connections WHERE organization_id = $1;', [orgId]);
        res.json({ onboardingStatus: onboardingState, organization: { id: org.id, name: org.name, domain: org.domain, website: org.website || null, industry: org.industry || null, companySize: org.company_size || null }, frameworks: (fwRes.rows || []).map(r => r.framework_id), connections: connRes.rows || [], complianceGuidance: 'Compflow will use these objectives to prioritize relevant controls and evidence.' });
    } catch (err) { log.error(`[ONBOARDING] Error fetching status for org ${orgId}:`, err.message); return jsonError(res, 500, 'ONBOARDING_STATUS_FAILED', 'Onboarding status could not be retrieved.'); }
});

router.post('/organization', async (req, res) => {
    const orgId = req.user.orgId; const { name, website, industry, companySize } = req.body || {};
    if (!name || typeof name !== 'string') return jsonError(res, 400, 'ORGANIZATION_NAME_REQUIRED', 'Organization name is required.');
    try {
        await pool.query('UPDATE organizations SET name = $1, website = $2, industry = $3, company_size = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5;', [name.trim(), website || null, industry || null, companySize || null, orgId]);
        const stateRes = await pool.query('SELECT status FROM onboarding_state WHERE org_id = $1;', [orgId]); const next = advanceState(stateRes.rows?.[0]?.status || 'AUTHENTICATED', 'ORGANIZATION_CREATED');
        await pool.query(`INSERT INTO onboarding_state (org_id, status) VALUES ($1, $2) ON CONFLICT (org_id) DO UPDATE SET status = $2, updated_at = CURRENT_TIMESTAMP;`, [orgId, next]);
        await recordAuditEvent(orgId, req.user.userId, 'organization_updated', 'organization', orgId, { name, industry, companySize, result: 'success' }, req).catch(() => {});
        return res.json({ success: true, status: next, organization: { id: orgId, name, website, industry, companySize } });
    } catch (err) { log.error('[ONBOARDING] Failed to update organization:', err.message); return jsonError(res, 500, 'ORGANIZATION_UPDATE_FAILED', 'Organization details could not be saved.'); }
});

router.post('/objectives', async (req, res) => {
    const orgId = req.user.orgId; const { frameworks } = req.body || {};
    if (!Array.isArray(frameworks) || frameworks.length === 0) return jsonError(res, 400, 'FRAMEWORK_REQUIRED', 'Please select at least one compliance framework.');
    try {
        for (const frameworkId of frameworks) {
            const id = 'fw_' + crypto.randomUUID();
            await pool.query(`INSERT INTO organization_frameworks (id, org_id, framework_id, status, selected_by) VALUES ($1, $2, $3, 'selected', $4) ON CONFLICT (org_id, framework_id) DO NOTHING;`, [id, orgId, frameworkId.toLowerCase().trim(), req.user.userId]);
            await recordAuditEvent(orgId, req.user.userId, 'framework_selected', 'framework', frameworkId, { result: 'success' }, req).catch(() => {});
        }
        const stateRes = await pool.query('SELECT status FROM onboarding_state WHERE org_id = $1;', [orgId]); const next = advanceState(stateRes.rows?.[0]?.status || 'AUTHENTICATED', 'OBJECTIVES_SELECTED');
        await pool.query(`INSERT INTO onboarding_state (org_id, status) VALUES ($1, $2) ON CONFLICT (org_id) DO UPDATE SET status = $2, updated_at = CURRENT_TIMESTAMP;`, [orgId, next]);
        return res.json({ success: true, status: next, selectedFrameworks: frameworks, guidance: 'Compflow will use these objectives to prioritize relevant controls and evidence.' });
    } catch (err) { log.error('[ONBOARDING] Failed to save frameworks:', err.message); return jsonError(res, 500, 'OBJECTIVES_SAVE_FAILED', 'Compliance objectives could not be saved.'); }
});

router.post('/cloud-connection', async (req, res) => {
    const orgId = req.user.orgId; const { provider, displayName, accountIdentifier, region, credentials } = req.body || {};
    if (!provider) return jsonError(res, 400, 'PROVIDER_REQUIRED', 'Cloud provider is required.');
    const validProviders = ['aws', 'azure', 'gcp', 'digitalocean', 'hetzner']; const normalizedProvider = String(provider).toLowerCase();
    if (!validProviders.includes(normalizedProvider)) return jsonError(res, 400, 'UNSUPPORTED_PROVIDER', `Unsupported provider "${provider}".`);
    if (!credentials || typeof credentials !== 'object' || Array.isArray(credentials)) return jsonError(res, 400, 'CLOUD_CREDENTIALS_REQUIRED', 'Cloud credentials are required to create a connection.');
    const connId = 'conn_' + crypto.randomUUID().replace(/-/g, '').substring(0, 16); const credRef = 'sec_ref_' + connId;
    try {
        await SecretStore.saveSecret(orgId, connId, credentials, req.user.userId);
        await pool.query(`INSERT INTO cloud_connections (id, organization_id, provider, display_name, status, account_identifier, region, credential_reference, created_by) VALUES ($1, $2, $3, $4, 'PENDING', $5, $6, $7, $8);`, [connId, orgId, normalizedProvider, displayName || `${normalizedProvider.toUpperCase()} Connection`, accountIdentifier || null, region || 'us-east-1', credRef, req.user.userId]);
        await recordAuditEvent(orgId, req.user.userId, 'cloud_connection_created', 'cloud_connection', connId, { provider: normalizedProvider, region: region || 'us-east-1', result: 'success' }, req).catch(() => {});
        return res.status(201).json({ success: true, connectionId: connId, provider: normalizedProvider, status: 'PENDING', displayName: displayName || `${normalizedProvider.toUpperCase()} Connection` });
    } catch (err) { log.error('[ONBOARDING] Cloud connection creation failed:', err.message); return jsonError(res, 500, 'CLOUD_CONNECTION_CREATE_FAILED', 'Cloud connection could not be created.'); }
});

router.post('/cloud-connection/:id/verify', async (req, res) => {
    const orgId = req.user.orgId; const connId = req.params.id;
    try {
        const connRes = await pool.query('SELECT * FROM cloud_connections WHERE id = $1 AND organization_id = $2;', [connId, orgId]);
        if (!connRes.rows?.length) return jsonError(res, 404, 'CLOUD_CONNECTION_NOT_FOUND', 'Cloud connection not found.');
        const conn = connRes.rows[0];
        await pool.query('UPDATE cloud_connections SET status = $1 WHERE id = $2;', ['VERIFYING', connId]);
        const secret = await SecretStore.getSecret(orgId, connId, 'connection_verification', req.user.userId, req);
        if (!secret) {
            await pool.query('UPDATE cloud_connections SET status = $1, error_code = $2, error_message = $3 WHERE id = $4;', ['FAILED', 'CLOUD_AUTHENTICATION_FAILED', 'No stored credentials found for connection.', connId]);
            return res.status(400).json({ verified: false, status: 'FAILED', errorCode: 'CLOUD_AUTHENTICATION_FAILED', code: 'CLOUD_AUTHENTICATION_FAILED', error: 'Cloud verification failed', message: 'No stored credentials found for connection. You can retry or update credentials.', retryable: true });
        }
        const verifyResult = await cloudVerifier.verify(conn.provider, secret);
        if (!verifyResult.verified) {
            const errorCode = verifyResult.errorCode || 'CLOUD_AUTHENTICATION_FAILED'; const errorMessage = verifyResult.errorMessage || 'Cloud connection verification failed.';
            await pool.query('UPDATE cloud_connections SET status = $1, error_code = $2, error_message = $3 WHERE id = $4;', ['FAILED', errorCode, errorMessage, connId]);
            return res.status(400).json({ verified: false, status: 'FAILED', errorCode, code: errorCode, error: 'Cloud verification failed', message: errorMessage, retryable: true });
        }
        await pool.query(`UPDATE cloud_connections SET status='VERIFIED', account_identifier=$1, principal=$2, verification_method=$3, last_verified_at=CURRENT_TIMESTAMP, error_code=NULL, error_message=NULL WHERE id=$4;`, [verifyResult.accountIdentifier || null, verifyResult.principal || null, verifyResult.verificationMethod || `${conn.provider}:api_verification`, connId]);
        const stateRes = await pool.query('SELECT status FROM onboarding_state WHERE org_id = $1;', [orgId]); const next = advanceState(stateRes.rows?.[0]?.status || 'AUTHENTICATED', 'CLOUD_CONNECTED');
        await pool.query(`INSERT INTO onboarding_state (org_id, status) VALUES ($1, $2) ON CONFLICT (org_id) DO UPDATE SET status = $2, updated_at = CURRENT_TIMESTAMP;`, [orgId, next]);
        await recordAuditEvent(orgId, req.user.userId, 'cloud_connection_verified', 'cloud_connection', connId, { provider: conn.provider, accountIdentifier: verifyResult.accountIdentifier, principal: verifyResult.principal, verificationMethod: verifyResult.verificationMethod, result: 'success' }, req).catch(() => {});

        const scanId = 'scan_' + crypto.randomUUID().replace(/-/g, '').substring(0, 16);
        const jobId = await createJob(`onboarding:${orgId}`, 'initial_onboarding_scan', orgId);
        await pool.query(`INSERT INTO scans (id, organization_id, connection_id, job_id, scan_type, status) VALUES ($1, $2, $3, $4, 'initial_onboarding_scan', 'QUEUED');`, [scanId, orgId, connId, jobId]);
        const scanJobPayload = { jobId, scanId, organizationId: orgId, connectionId: connId, provider: conn.provider, scanType: 'initial_onboarding_scan', enqueuedAt: new Date().toISOString() };
        let finalScanStatus = 'QUEUED';
        try { await enqueueJob(scanJobPayload); log.info(`[ONBOARDING] Cloud verified. Scan ${scanId} / Job ${jobId} queued for org ${orgId}`); }
        catch (queueErr) {
            finalScanStatus = 'FAILED';
            await pool.query(`UPDATE scans SET status='FAILED', error_code=$1, error_message=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3`, [queueErr?.code || 'QUEUE_ENQUEUE_FAILED', 'Initial scan could not be queued.', scanId]);
            await pool.query(`UPDATE jobs SET status='failed', progress=-1, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP, error_message=$1 WHERE job_id=$2`, ['Initial scan could not be queued.', jobId]).catch(() => {});
            log.error(`[ONBOARDING] Scan ${scanId} / Job ${jobId} enqueue failed: ${queueErr.message}`);
        }
        if (finalScanStatus === 'FAILED') return res.status(503).json({ verified: true, status: 'VERIFIED', scanId, jobId, scanStatus: finalScanStatus, onboardingStatus: next, code: 'INITIAL_SCAN_QUEUE_UNAVAILABLE', error: 'Initial scan unavailable', message: 'Your environment is verified, but the initial scan could not be queued. Please retry.' });
        return res.json({ verified: true, status: 'VERIFIED', scanId, jobId, scanStatus: finalScanStatus, onboardingStatus: next, provenance: { accountIdentifier: verifyResult.accountIdentifier, principal: verifyResult.principal, verificationMethod: verifyResult.verificationMethod }, message: 'Your environment is connected and verified. Compflow has queued your initial compliance scan.' });
    } catch (err) {
        log.error('[ONBOARDING] Connection verification error:', err.message);
        await pool.query('UPDATE cloud_connections SET status=$1, error_code=$2, error_message=$3 WHERE id=$4', ['FAILED', err?.code || 'CLOUD_VERIFICATION_FAILED', String(err?.message || 'Verification failed').slice(0, 1000), connId]).catch(() => {});
        return jsonError(res, 500, 'CLOUD_VERIFICATION_FAILED', 'Cloud verification could not be completed.');
    }
});

router.post('/complete', async (req, res) => {
    const orgId = req.user.orgId;
    try {
        const orgRes = await pool.query('SELECT id, name FROM organizations WHERE id = $1;', [orgId]); if (!orgRes.rows?.length) return jsonError(res, 400, 'ORGANIZATION_REQUIRED', 'Organization profile must be set before completing onboarding.');
        const fwRes = await pool.query('SELECT framework_id FROM organization_frameworks WHERE org_id = $1;', [orgId]); if (!fwRes.rows?.length) return jsonError(res, 400, 'OBJECTIVES_REQUIRED', 'At least one compliance framework objective must be selected before completing onboarding.');
        const connRes = await pool.query('SELECT id, status FROM cloud_connections WHERE organization_id = $1;', [orgId]); if (!(connRes.rows || []).some(c => c.status === 'VERIFIED')) return jsonError(res, 400, 'VERIFIED_CLOUD_CONNECTION_REQUIRED', 'At least one verified cloud connection is required before completing onboarding.');
        const scanRes = await pool.query('SELECT id, status FROM scans WHERE organization_id = $1;', [orgId]); if (!(scanRes.rows || []).some(s => ['QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL'].includes(s.status))) return jsonError(res, 400, 'INITIAL_SCAN_REQUIRED', 'An initial compliance scan must be queued or completed before completing onboarding.');
        await pool.query(`INSERT INTO onboarding_state (org_id, status, completed_at, updated_at) VALUES ($1, 'ONBOARDING_COMPLETED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (org_id) DO UPDATE SET status='ONBOARDING_COMPLETED', completed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP;`, [orgId]);
        await pool.query(`UPDATE organizations SET onboarding_status='ONBOARDING_COMPLETED', updated_at=CURRENT_TIMESTAMP WHERE id=$1;`, [orgId]);
        await recordAuditEvent(orgId, req.user.userId, 'onboarding_completed', 'organization', orgId, { result: 'success' }, req).catch(() => {});
        return res.json({ success: true, status: 'ONBOARDING_COMPLETED', message: 'Onboarding completed successfully. Welcome to Compflow!' });
    } catch (err) { log.error('[ONBOARDING] Failed to complete onboarding:', err.message); return jsonError(res, 500, 'ONBOARDING_COMPLETION_FAILED', 'Onboarding could not be completed.'); }
});

router.get('/summary', async (req, res) => {
    const orgId = req.user.orgId;
    try {
        const connRes = await pool.query('SELECT provider, status, display_name FROM cloud_connections WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1;', [orgId]);
        const activeConn = connRes.rows?.[0] || { provider: 'NONE', status: 'PENDING' };
        const fwRes = await pool.query('SELECT framework_id FROM organization_frameworks WHERE org_id = $1;', [orgId]); const selectedFws = (fwRes.rows || []).map(r => r.framework_id);
        const scanRes = await pool.query('SELECT * FROM scans WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1;', [orgId]); const latestScan = scanRes.rows?.[0] || null;
        const scanStatus = latestScan ? latestScan.status : 'PENDING';
        if (!latestScan || scanStatus !== 'COMPLETED') {
            const frameworkStats = selectedFws.map(fw => ({ id: fw.toLowerCase(), name: getFrameworkDisplayName(fw), controlsAssessed: 0, controlsPassing: 0, controlsNeedingAttention: 0, assessmentLabel: formatAssessmentSummary({ assessed: 0, framework: fw }) }));
            return res.json({ cloud: { provider: activeConn.provider.toUpperCase(), status: activeConn.status }, scan: { status: scanStatus, resourcesDiscovered: 0 }, compliance: { frameworks: frameworkStats, findings: { critical: 0, high: 0, medium: 0, low: 0 }, evidenceCollected: 0, disclaimer: 'Compflow uses these objective assessments to prioritize relevant controls and evidence. Technical checks currently reflect evaluated cloud configurations.' } });
        }
        const findingsRes = await pool.query('SELECT severity, COUNT(*) FROM findings WHERE scan_id = $1 GROUP BY severity;', [latestScan.id]);
        const findingsCount = { critical: 0, high: 0, medium: 0, low: 0 }; for (const row of findingsRes.rows || []) { const sev = (row.severity || '').toLowerCase(); const count = parseInt(row.count, 10) || 0; if (findingsCount[sev] !== undefined) findingsCount[sev] = count; }
        const allFindingsRes = await pool.query('SELECT control_id, status FROM findings WHERE scan_id = $1;', [latestScan.id]); const scanFindings = allFindingsRes.rows || [];
        const frameworkStats = selectedFws.map(fw => { const fwKey = fw.toLowerCase(); const name = getFrameworkDisplayName(fw); const total = getFrameworkTotalControls(fw); const matchingFindings = scanFindings.filter(f => { if (!f.control_id) return false; const matrixEntry = ControlMatrix[f.control_id]; if (!matrixEntry) return true; return Boolean(matrixEntry[fwKey]); }); const controlsNeedingAttention = matchingFindings.filter(f => f.status === 'FAIL').length; const controlsPassing = matchingFindings.filter(f => f.status === 'PASS').length; const controlsAssessed = controlsPassing + controlsNeedingAttention; return { id: fwKey, name, totalControls: total, controlsAssessed, controlsPassing, controlsNeedingAttention, assessmentLabel: formatAssessmentSummary({ assessed: controlsAssessed, framework: fw }) }; });
        return res.json({ cloud: { provider: activeConn.provider.toUpperCase(), status: activeConn.status }, scan: { status: scanStatus, resourcesDiscovered: latestScan.resources_discovered || 0 }, compliance: { frameworks: frameworkStats, findings: findingsCount, evidenceCollected: latestScan.evidence_count || 0, disclaimer: 'Compflow uses these objective assessments to prioritize relevant controls and evidence. Technical checks currently reflect evaluated cloud configurations.' } });
    } catch (err) { log.error('[ONBOARDING] Failed to retrieve summary:', err.message); return jsonError(res, 500, 'ONBOARDING_SUMMARY_FAILED', 'Onboarding summary could not be retrieved.'); }
});

export default router;
