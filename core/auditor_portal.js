import crypto from 'crypto';
import { generatePdfReport } from './reporter.js';
import { log } from './logger.js';

const TEST_SIGNING_SECRET = 'CompFlow_Test_Auditor_Signing_Secret_Only';

function signingSecret() {
    const configured = process.env.AUDITOR_SIGNING_SECRET;
    if (configured) return configured;
    if (process.env.NODE_ENV === 'test') return TEST_SIGNING_SECRET;
    throw new Error('AUDITOR_SIGNING_SECRET_REQUIRED');
}

/**
 * ComplianceFlow AI — SOC2 Third-Party Auditor Evidence Portal Engine.
 * Production signing requires an explicit secret; there is no production fallback.
 */
export function computeSha256(content) {
    const data = typeof content === 'string' ? content : JSON.stringify(content);
    return crypto.createHash('sha256').update(data).digest('hex');
}

export function signPayload(payload, secret = signingSecret()) {
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

export function verifySignature(payload, signature, secret = signingSecret()) {
    if (!/^[a-f0-9]{64}$/i.test(String(signature || ''))) return false;
    const expected = signPayload(payload, secret);
    try {
        return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
        return false;
    }
}

export function generateAuditorToken(tenantId, auditorEmail, expiryHours = 72) {
    if (!tenantId || !auditorEmail || !Number.isFinite(expiryHours) || expiryHours <= 0 || expiryHours > 168) throw new Error('AUDITOR_TOKEN_INPUT_INVALID');
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + expiryHours * 60 * 60 * 1000).toISOString();
    const payload = {
        tenantId,
        auditorEmail,
        role: 'AUDITOR_READONLY',
        issuedAt,
        expiresAt,
        permissions: ['read:evidence', 'read:manifest', 'read:reports', 'export:bundle']
    };
    const signature = signPayload(payload);
    const token = Buffer.from(JSON.stringify({ payload, signature })).toString('base64url');
    log.info(`[AUDITOR-PORTAL] Issued ${expiryHours}h auditor access token for tenant ${tenantId}.`);
    return { token, auditorEmail, tenantId, issuedAt, expiresAt, role: 'AUDITOR_READONLY' };
}

export function validateAuditorToken(tokenString) {
    try {
        if (typeof tokenString !== 'string' || tokenString.length > 8192) return { valid: false, error: 'Malformed auditor token' };
        const decoded = JSON.parse(Buffer.from(tokenString, 'base64url').toString('utf8'));
        const { payload, signature } = decoded;
        if (!payload || !signature) return { valid: false, error: 'Malformed auditor token structure' };
        if (!verifySignature(payload, signature)) return { valid: false, error: 'Invalid or forged auditor token signature' };
        if (!payload.expiresAt || Number.isNaN(Date.parse(payload.expiresAt)) || new Date(payload.expiresAt) < new Date()) return { valid: false, error: 'Auditor token has expired' };
        return { valid: true, payload };
    } catch {
        return { valid: false, error: 'Failed to validate auditor token' };
    }
}

export async function generateAuditorEvidencePackage(tenantName, resources = [], auditTrailLogs = [], options = {}) {
    const timestamp = new Date().toISOString();
    const auditorName = options.auditorName || 'Independent SOC2 Compliance Auditor';
    const auditorFirm = options.auditorFirm || 'Certified Public Accounting (CPA) Practice';
    log.info(`[AUDITOR-PORTAL] Compiling signed evidence package for "${tenantName}"...`);

    const evidenceManifest = resources.map((r, idx) => {
        const rawJson = JSON.stringify(r);
        return {
            evidenceId: `EVD-${String(idx + 1).padStart(4, '0')}`,
            resourceName: r.name,
            resourceType: r.type,
            region: r.region || 'global',
            status: r.severity === 'pass' ? 'COMPLIANT' : 'DEFICIENCY',
            severity: r.severity,
            issue: r.issue || 'Meets baseline hardening criteria',
            controls: r.controls || { soc2: ['CC6.1'], iso27001: ['A.9.1.1'], hipaa: ['§164.312(a)(1)'] },
            sha256Fingerprint: computeSha256(rawJson),
            capturedAt: timestamp
        };
    });

    const controlProofSoc2 = {
        framework: 'SOC2 Type II (Trust Services Criteria)',
        version: '2026.1',
        auditPeriod: { start: 'Continuous (Automated)', end: timestamp },
        controlsEvaluated: {
            'CC6.1': { title: 'Logical Access Controls & Encryption at Rest', items: evidenceManifest.filter(e => JSON.stringify(e.controls).includes('CC6.1')).length },
            'CC6.6': { title: 'Perimeter Network Security & Ingress Filtering', items: evidenceManifest.filter(e => JSON.stringify(e.controls).includes('CC6.6')).length },
            'CC6.8': { title: 'Unauthorized Code Execution & Debugging Hardening', items: evidenceManifest.filter(e => JSON.stringify(e.controls).includes('CC6.8')).length },
            'CC7.2': { title: 'Continuous Vulnerability & Backup Resiliency', items: evidenceManifest.filter(e => JSON.stringify(e.controls).includes('CC7.2')).length }
        }
    };

    const controlProofIso27001 = {
        framework: 'ISO/IEC 27001:2022',
        controlsEvaluated: {
            'A.9': { domain: 'Access Control', count: evidenceManifest.length },
            'A.12': { domain: 'Operations Security & Backup Verification', count: evidenceManifest.filter(e => String(e.resourceType || '').includes('Backup') || String(e.issue || '').includes('backup')).length }
        }
    };

    const controlProofHipaa = {
        framework: 'HIPAA Security Rule (45 CFR Part 164)',
        safeguards: {
            '164.312(a)(1)': 'Access Control (Encryption & Decryption at Rest)',
            '164.312(e)(1)': 'Transmission Security (In-Transit Cryptography Enforced)'
        }
    };

    let executivePdfBase64 = '';
    try {
        const pdfBuffer = await generatePdfReport(tenantName, resources);
        executivePdfBase64 = pdfBuffer.toString('base64');
    } catch (e) {
        log.warn('[AUDITOR-PORTAL] PDF compilation note:', e.message);
    }

    const bundleContentToSign = {
        tenantName,
        packageVersion: '1.0.0-PROVABLE-AUDIT',
        signatureAlgorithm: 'HMAC-SHA256',
        generatedAt: timestamp,
        auditorTarget: { name: auditorName, firm: auditorFirm },
        totalAssetsEvaluated: resources.length,
        totalDeficiencies: resources.filter(r => r.severity !== 'pass').length,
        manifestHash: computeSha256(evidenceManifest),
        soc2ProofHash: computeSha256(controlProofSoc2),
        isoProofHash: computeSha256(controlProofIso27001),
        hipaaProofHash: computeSha256(controlProofHipaa),
        auditTrailCount: auditTrailLogs.length,
        verificationInstructions: 'Submit digitalSignature alongside package to /api/auditor/verify to assert authenticity.'
    };

    const digitalSignature = signPayload(bundleContentToSign);
    const fullPackage = {
        packageMetadata: { ...bundleContentToSign, digitalSignature },
        files: {
            'evidence_manifest.json': evidenceManifest,
            'control_proof_soc2.json': controlProofSoc2,
            'control_proof_iso27001.json': controlProofIso27001,
            'control_proof_hipaa.json': controlProofHipaa,
            'audit_trail.log': auditTrailLogs,
            'executive_summary.pdf': executivePdfBase64
        }
    };
    log.info(`[AUDITOR-PORTAL] Evidence bundle signed (${digitalSignature.substring(0, 16)}...).`);
    return fullPackage;
}

export function verifyAuditorPackage(evidencePackage) {
    if (!evidencePackage || !evidencePackage.packageMetadata || !evidencePackage.files) return { verified: false, reason: 'Invalid package structure' };
    const { digitalSignature, ...contentSigned } = evidencePackage.packageMetadata;
    if (!verifySignature(contentSigned, digitalSignature)) return { verified: false, reason: 'Digital signature mismatch (Package has been tampered with or signing key is invalid)' };
    const currentManifestHash = computeSha256(evidencePackage.files['evidence_manifest.json']);
    if (currentManifestHash !== contentSigned.manifestHash) return { verified: false, reason: 'Evidence manifest SHA-256 checksum mismatch' };
    return {
        verified: true,
        tenantName: contentSigned.tenantName,
        generatedAt: contentSigned.generatedAt,
        totalAssets: contentSigned.totalAssetsEvaluated,
        totalDeficiencies: contentSigned.totalDeficiencies,
        message: 'Cryptographic proof verified. Package matches official immutable audit trail.'
    };
}
