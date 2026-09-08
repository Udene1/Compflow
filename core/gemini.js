import { GoogleGenerativeAI } from "@google/generative-ai";

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;
const MODEL = process.env.GEMINI_REMEDIATION_MODEL || process.env.GEMINI_MODEL || "gemini-1.5-flash";

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Uses the real Gemini provider to evaluate whether a finding is safe to auto-remediate.
 * AI unavailability is a hard failure: this function never manufactures a decision.
 */
export async function evaluateWithGemini(finding) {
    if (!process.env.GEMINI_API_KEY) {
        throw new Error("GEMINI_UNAVAILABLE");
    }
    if (!finding || typeof finding !== "object") {
        throw new Error("GEMINI_FINDING_INVALID");
    }

    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: MODEL });
    const prompt = `
You are a Senior Cloud Security Engineer and Compliance Auditor.
Evaluate the supplied compliance finding and decide whether its remediation is safe to automate.
Use only the supplied facts. Do not invent missing evidence, dependencies, blast radius, or verification.
If the evidence is insufficient to establish safe automation, choose ESCALATE.

FINDING:
Type: ${String(finding.type ?? "")}
Resource: ${String(finding.name ?? "")}
Issue: ${String(finding.issue ?? "")}
Severity: ${String(finding.severity ?? "")}
Control: ${String(finding.control ?? "")}

Return JSON only:
{
  "action": "AUTO_FIX" | "ESCALATE",
  "reason": "Detailed evidence-grounded explanation",
  "safetyScore": 0-1
}
`;

    let lastError;
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt += 1) {
        try {
            const result = await model.generateContent(prompt);
            const parsed = JSON.parse(String(result.response.text() || "").replace(/```json|```/g, "").trim());
            if (!parsed || !["AUTO_FIX", "ESCALATE"].includes(parsed.action)) throw new Error("GEMINI_INVALID_ACTION");
            if (typeof parsed.reason !== "string" || !parsed.reason.trim()) throw new Error("GEMINI_INVALID_REASON");
            const safetyScore = Number(parsed.safetyScore);
            if (!Number.isFinite(safetyScore) || safetyScore < 0 || safetyScore > 1) throw new Error("GEMINI_INVALID_SAFETY_SCORE");
            return { action: parsed.action, reason: parsed.reason.slice(0, 4000), safetyScore };
        } catch (error) {
            lastError = error;
            const retryable = error?.status === 429 || error?.status >= 500 || /rate|timeout|temporar/i.test(error?.message || "");
            if (!retryable || attempt === MAX_RETRIES) break;
            await sleep(BASE_DELAY_MS * 2 ** (attempt - 1));
        }
    }
    throw lastError || new Error("GEMINI_FAILED");
}
