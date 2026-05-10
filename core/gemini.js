import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "MOCK_KEY");

// Startup validation
if (!process.env.GEMINI_API_KEY && process.env.NODE_ENV === 'production') {
    throw new Error('[GEMINI] GEMINI_API_KEY is required in production. Set it in Vercel environment variables.');
}

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

/**
 * Sleep helper for retry backoff.
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Uses Gemini to evaluate a compliance finding and decide if it's safe to auto-fix.
 * Includes retry-with-exponential-backoff for rate limit and transient errors.
 * @param {Object} finding - The finding object from the scanner.
 * @returns {Promise<Object>} - { action: 'AUTO_FIX' | 'ESCALATE', reason: string, safetyScore: number }
 */
export async function evaluateWithGemini(finding) {
    if (!process.env.GEMINI_API_KEY) {
        console.warn("[GEMINI] No API key found. Falling back to heuristic reasoning.");
        return fallbackReasoning(finding);
    }

    const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro" });

    const prompt = `
        You are a Senior Cloud Security Engineer and Compliance Auditor.
        Evaluate the following compliance finding and decide if it is safe to automatically remediate.
        
        FINDING:
        Type: ${finding.type}
        Resource: ${finding.name}
        Issue: ${finding.issue}
        Severity: ${finding.severity}
        Control: ${finding.control}

        CRITERIA FOR AUTO_FIX:
        - Low blast radius: The fix should not break production workloads (e.g., enabling logs, backups, or non-destructive encryption).
        - High confidence: The remediation path is well-defined and standard.
        - Low risk of lockout: The fix should not lock out legitimate users (e.g., be careful with IAM policy restricted).

        RESPONSE FORMAT (JSON only, no markdown):
        {
            "action": "AUTO_FIX" | "ESCALATE",
            "reason": "Detailed explanation of why this decision was made",
            "safetyScore": 0-1 (confidence in the fix safety)
        }
    `;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        try {
            const result = await model.generateContent(prompt);
            const responseText = result.response.text();
            const cleanedJson = responseText.replace(/```json|```/g, "").trim();
            return JSON.parse(cleanedJson);
        } catch (error) {
            const isRetryable = error.status === 429 || error.status >= 500 || error.message?.includes('rate');
            
            if (isRetryable && attempt < MAX_RETRIES) {
                const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
                console.warn(`[GEMINI] Attempt ${attempt}/${MAX_RETRIES} failed (${error.message}). Retrying in ${delay}ms...`);
                await sleep(delay);
            } else {
                console.error(`[GEMINI] Failed after ${attempt} attempt(s):`, error.message);
                return fallbackReasoning(finding);
            }
        }
    }

    return fallbackReasoning(finding);
}

function fallbackReasoning(finding) {
    // Hardcoded logic for when AI is unavailable
    const safeIssues = [
        'Public access enabled',
        'backups disabled',
        'encryption disabled',
        'Logging disabled',
        'retention < 365',
        'MFA Delete disabled',
        'point-in-time recovery'
    ];

    const isSafe = safeIssues.some(i => finding.issue.toLowerCase().includes(i.toLowerCase()));

    return {
        action: isSafe ? 'AUTO_FIX' : 'ESCALATE',
        reason: isSafe ? "Standard structural fix with low blast radius (Heuristic fallback)" : "Potentially disruptive configuration change (Heuristic fallback)",
        safetyScore: isSafe ? 0.9 : 0.5
    };
}
