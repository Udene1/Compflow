import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "MOCK_KEY");

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { query, contextData } = req.body;

    if (!query) {
        return res.status(400).json({ error: 'Missing query' });
    }

    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

        const prompt = `
            You are the ComplianceFlow AI Assistant. 
            Below is the current compliance state of the user's infrastructure:
            ${JSON.stringify(contextData, null, 2)}

            User Question: "${query}"

            Answer the user's question accurately based ONLY on the provided infrastructure data.
            If they ask for technical details or remediation steps, refer to the ComplianceFlow core capabilities 
            (S3 hardening, IAM rotation, RDS encryption, etc.).
            Keep your tone professional, authoritative, and concise.
        `;

        const result = await model.generateContent(prompt);
        const response = result.response.text();

        res.status(200).json({ response });
    } catch (error) {
        console.error("[CHAT] Gemini error:", error);
        res.status(500).json({ error: 'AI reasoning failed. Please try again later.' });
    }
}
