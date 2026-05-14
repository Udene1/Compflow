import { GoogleGenerativeAI } from "@google/generative-ai";
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function list() {
    try {
        // The listModels method is on the genAI instance
        // But wait, it might be in a different place depending on version.
        // Actually, let's just try gemini-1.5-flash with 'models/' prefix
        const model = genAI.getGenerativeModel({ model: "models/gemini-1.5-flash" });
        const result = await model.generateContent("test");
        console.log("Success with models/ prefix!");
    } catch (e) {
        console.log("Failed with models/ prefix:", e.message);
        try {
            const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });
            await model.generateContent("test");
            console.log("Success with gemini-2.0-flash!");
        } catch (e2) {
             console.log("Failed with gemini-2.0-flash:", e2.message);
        }
    }
}
list();
