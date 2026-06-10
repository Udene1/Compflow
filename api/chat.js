import { GoogleGenerativeAI } from "@google/generative-ai";
import { log } from '../core/logger.js';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "MOCK_KEY");

const SYSTEM_PROMPT = `You are the ComplianceFlow Governance Architect AI — a senior-level cloud security advisor embedded inside the ComplianceFlow AI-Native Governance Platform.

## Your Role
- You are an expert in SOC2 Type II, GDPR, HIPAA, and ISO 27001 compliance frameworks.
- You have **live access** to the user's most recent infrastructure scan results, compliance scores, and remediation history.
- You provide actionable, authoritative, and concise answers.

## Response Guidelines
1. **Always ground answers in the provided scan data.** If asked about a resource, quote the exact finding.
2. **Use framework-specific language.** Reference control IDs (e.g., CC6.1, Art. 32, §164.312).
3. **Recommend remediation steps** when vulnerabilities are identified.
4. **Format responses in clean markdown** with bold headings and bullet points for readability.
5. **Be concise.** Maximum 200 words unless the user explicitly asks for a detailed breakdown.
6. **If no scan data is available**, inform the user they need to run a scan first.
7. **Never fabricate data.** If a resource isn't in the scan context, say so.

## Capabilities
- Analyze resource-level compliance posture across AWS, GCP, Azure, Hetzner, and DigitalOcean.
- Calculate framework-specific maturity percentages.
- Recommend prioritized remediation actions.
- Explain compliance requirements in plain language.
- Compare security posture across cloud providers.`;

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export const handler = async (event) => {
    const isApiGateway = !!event.httpMethod;
    const body = isApiGateway ? JSON.parse(event.body || '{}') : event;
    const { query, context } = body;

    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
    };

    if (isApiGateway && event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'your-gemini-api-key-here') {
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: "Missing or invalid GEMINI_API_KEY in backend environment." })
        };
    }

    if (!query) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing query' }) };
    }

    try {
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.0-flash",
            systemInstruction: {
                role: "system",
                parts: [{ text: SYSTEM_PROMPT }]
            }
        });

        const contextBlock = context ? `
## Current Infrastructure State
- **Provider(s)**: ${context.providers || 'Not connected'}
- **Total Resources Scanned**: ${context.totalResources || 0}
- **Passing**: ${context.passing || 0} | **Warnings**: ${context.warnings || 0} | **Critical**: ${context.critical || 0}
- **Readiness Score**: ${context.readinessScore || 'N/A'}
- **Active Framework**: ${context.activeFramework || 'SOC2 Type II'}

### Maturity Scores
${context.maturityScores || 'No maturity data available.'}

### Resource Findings (Top 20)
\`\`\`json
${JSON.stringify((context.resources || []).slice(0, 20), null, 2)}
\`\`\`
` : '**No scan data available.** The user needs to connect a cloud provider and run a scan first.';

        const userPrompt = `${contextBlock}\n\n---\n**User Question:** ${query}`;

        const chat = model.startChat({
            history: [],
        });

        let responseText = "";
        let success = false;

        for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                const result = await chat.sendMessage(userPrompt);
                responseText = result.response.text();
                success = true;
                break;
            } catch (error) {
                const isRetryable = error.status === 429 || error.status >= 500 || error.message?.includes('rate');
                if (isRetryable && attempt < MAX_RETRIES) {
                    const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
                    await sleep(delay);
                } else {
                    throw error;
                }
            }
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ response: responseText })
        };

    } catch (error) {
        console.error("[CHAT] Error:", error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'AI reasoning failed: ' + error.message })
        };
    }
};
