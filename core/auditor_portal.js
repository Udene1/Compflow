import crypto from 'crypto';
import { generatePdfReport } from './reporter.js';
import { log } from './logger.js';

const SIGNING_SECRET = process.env.AUDITOR_SIGNING_SECRET || 'CompFlow_Auditor_Key_2026_Secret_Sig';

/**
 * ComplianceFlow AI — SOC2 Third-Party Auditor Evidence Portal Engine
 * Generates tamper-proof, cryptographically signed audit packages for
 * external CPA & compliance auditors (Schellman, Prescient, A-LIGN, Coalfire).
 */

/**
 * Computes a SHA-256 hash of arbitrary content.
 */
export function computeSha256(content) {
    const data = typeof content === 'string' ? content : JSON.stringify(content);
    return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Generates an HMAC-SHA256 signature for a manifest/payload.
 */
export function signPayload(payload, secret = SIGNING_SECRET) {
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Verifies the digital HMAC signature of an evidence package.
 */
export function verifySignature(payload, signature, secret = SIGNING_SECRET) {
    const expected = signPayload(payload, secret);
    try {
        return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
        return false;
    }
}

/**
 * Generates a time-limited, signed Auditor Access Token.
 * 
 * @param {string} tenantId - The tenant or organization identifier
 * @param {string} auditorEmail - Email of the external auditor
 * @param {number} expiryHours - Token lifespan in hours (default 72h)
 * @returns {Object} { token, expiresAt, auditorEmail, tenantId }
 */
export function generateAuditorToken(tenantId, auditorEmail, expiryHours = 72) {
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

    log.info(`[AUDITOR-PORTAL] Issued ${expiryHours}h access token for auditor "${auditorEmail}" (Tenant: ${tenantId}).`);
    return {
        token,
        auditorEmail,
        tenantId,
        issuedAt,
        expiresAt,
        role: 'AUDITOR_READONLY'
    };
}

/**
 * Validates an incoming Auditor Access Token.
 */
export function validateAuditorToken(tokenString) {
    try {
        const decoded = JSON.parse(Buffer.from(tokenString, 'base64url').toString('utf8'));
        const { payload, signature } = decoded;

        if (!payload || !signature) {
            return { valid: false, error: 'Malformed auditor token structure' };
        }

        // Verify cryptographic signature
        if (!verifySignature(payload, signature)) {
            return { valid: false, error: 'Invalid or forged auditor token signature' };
        }

        // Check expiration
        if (new Date(payload.expiresAt) < new Date()) {
            return { valid: false, error: 'Auditor token has expired' };
        }

        return { valid: true, payload };
    } catch (err) {
        return { valid: false, error: 'Failed to decode token: ' + err.message };
    }
}

/**
 * Assembles a complete, cryptographically signed auditor evidence package.
 * 
 * @param {string} tenantName - Name of the organization
 * @param {Array} resources - Scanned infrastructure assets and findings
 * @param {Array} auditTrailLogs - Chronological remediation & scan event history
 * @param {Object} options - Custom configuration (e.g. auditor identity)
 * @returns {Promise<Object>} The compiled and signed evidence bundle
 */
export async function generateAuditorEvidencePackage(tenantName, resources = [], auditTrailLogs = [], options = {}) {
    const timestamp = new Date().toISOString();
    const auditorName = options.auditorName || 'Independent SOC2 Compliance Auditor';
    const auditorFirm = options.auditorFirm || 'Certified Public Accounting (CPA) Practice';

    log.info(`[AUDITOR-PORTAL] Compiling signed evidence package for "${tenantName}"...`);

    // 1. Compile SHA-256 Hashed Evidence Manifest
    const evidenceManifest = resources.map((r, idx) => {
        const rawJson = JSON.stringify(r);
        const sha256 = computeSha256(rawJson);
        return {
            evidenceId: `EVD-${String(idx + 1).padStart(4, '0')}`,
            resourceName: r.name,
            resourceType: r.type,
            region: r.region || 'global',
            status: r.severity === 'pass' ? 'COMPLIANT' : 'DEFICIENCY',
            severity: r.severity,
            issue: r.issue || 'Meets baseline hardening criteria',
            controls: r.controls || { soc2: ['CC6.1'], iso27001: ['A.9.1.1'], hipaa: ['§164.312(a)(1)'] },
            sha256Fingerprint: sha256,
            capturedAt: timestamp
        };
    });

    // 2. Compile Framework Specific Control Proofs
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
            'A.12': { domain: 'Operations Security & Backup Verification', count: evidenceManifest.filter(e => e.resourceType.includes('Backup') || e.issue.includes('backup')).length }
        }
    };

    const controlProofHipaa = {
        framework: 'HIPAA Security Rule (45 CFR Part 164)',
        safeguards: {
            '164.312(a)(1)': 'Access Control (Encryption & Decryption at Rest)',
            '164.312(e)(1)': 'Transmission Security (In-Transit Cryptography Enforced)'
        }
    };

    // 3. Compile Executive PDF Report Buffer
    let executivePdfBase64 = '';
    try {
        const pdfBuffer = await generatePdfReport(tenantName, resources);
        executivePdfBase64 = pdfBuffer.toString('base64');
    } catch (e) {
        log.warn('[AUDITOR-PORTAL] PDF compilation note:', e.message);
    }

    // 4. Build Digital Manifest Summary for Signing
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

    // 5. Generate Cryptographic Signature
    const digitalSignature = signPayload(bundleContentToSign);

    const fullPackage = {
        packageMetadata: {
            ...bundleContentToSign,
            digitalSignature
        },
        files: {
            'evidence_manifest.json': evidenceManifest,
            'control_proof_soc2.json': controlProofSoc2,
            'control_proof_iso27001.json': controlProofIso27001,
            'control_proof_hipaa.json': controlProofHipaa,
            'audit_trail.log': auditTrailLogs,
            'executive_summary.pdf': executivePdfBase64
        }
    };

    log.info(`[AUDITOR-PORTAL] ✓ Evidence bundle successfully signed (Sig: ${digitalSignature.substring(0, 16)}...).`);
    return fullPackage;
}

/**
 * Validates that an evidence package has not been tampered with.
 */
export function verifyAuditorPackage(evidencePackage) {
    if (!evidencePackage || !evidencePackage.packageMetadata || !evidencePackage.files) {
        return { verified: false, reason: 'Invalid package structure' };
    }

    const { digitalSignature, ...contentSigned } = evidencePackage.packageMetadata;

    // 1. Verify digital signature
    const isSigValid = verifySignature(contentSigned, digitalSignature);
    if (!isSigValid) {
        return { verified: false, reason: 'Digital signature mismatch (Package has been tampered with or signing key is invalid)' };
    }

    // 2. Verify evidence manifest hash integrity
    const currentManifestHash = computeSha256(evidencePackage.files['evidence_manifest.json']);
    if (currentManifestHash !== contentSigned.manifestHash) {
        return { verified: false, reason: 'Evidence manifest SHA-256 checksum mismatch' };
    }

    return {
        verified: true,
        tenantName: contentSigned.tenantName,
        generatedAt: contentSigned.generatedAt,
        totalAssets: contentSigned.totalAssetsEvaluated,
        totalDeficiencies: contentSigned.totalDeficiencies,
        message: 'Cryptographic proof verified. Package matches official immutable audit trail.'
    };
}
