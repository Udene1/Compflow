import { orchestratorLoop } from '../../agent.js';

export default async function handler(req, res) {
    // Basic auth check for cron triggers (Vercel provides headers)
    const authHeader = req.headers['authorization'];
    if (process.env.NODE_ENV === 'production' && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    console.log("[CRON] Starting Autonomous Audit Loop...");
    
    try {
        // Execute the loop
        await orchestratorLoop();
        
        res.status(200).json({ success: true, message: 'Audit loop completed successfully' });
    } catch (error) {
        console.error("[CRON] Audit Failure:", error);
        res.status(500).json({ error: error.message });
    }
}
