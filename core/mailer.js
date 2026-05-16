import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";
import { log } from "./logger.js";

const ses = new SESClient({ region: process.env.AWS_REGION || "us-east-1" });

/**
 * Mailer Service
 * Dispatches automated compliance reports via AWS SES.
 */
export async function sendComplianceReport(email, frameworkData, scanResults) {
    if (!email) {
        log.warn("Mailer: No recipient email provided. Skipping dispatch.");
        return;
    }

    log.info(`Mailer: Preparing report for ${email}...`);

    try {
        const stats = calculateStats(scanResults);
        const htmlBody = generateHTMLTemplate(email, frameworkData, stats, scanResults);

        const command = new SendEmailCommand({
            Destination: { ToAddresses: [email] },
            Message: {
                Body: {
                    Html: { Data: htmlBody },
                    Text: { Data: `ComplianceFlow Audit Report: ${stats.coverage}% Coverage. Please view in an HTML-capable client.` }
                },
                Subject: { Data: `[AUDIT] ComplianceFlow Governance Report - ${new Date().toLocaleDateString()}` }
            },
            Source: process.env.SES_SENDER_EMAIL || "reports@compflow.ai"
        });

        const response = await ses.send(command);
        log.info(`Mailer: Report sent successfully! MessageId: ${response.MessageId}`);
        return response;
    } catch (e) {
        log.error("Mailer: Failed to send report:", e);
        throw e;
    }
}

function calculateStats(results) {
    const total = results.length;
    const passing = results.filter(r => r.severity === 'pass').length;
    const coverage = total > 0 ? Math.round((passing / total) * 100) : 0;
    return { total, passing, coverage };
}

function generateHTMLTemplate(email, framework, stats, results) {
    return `
    <html>
    <body style="font-family: sans-serif; background: #f9fafb; color: #111827; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; border: 1px solid #e5e7eb; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
            <div style="background: #6366f1; padding: 30px; color: white;">
                <h1 style="margin: 0; font-size: 24px; letter-spacing: -0.5px;">Compliance<span style="opacity: 0.8;">Flow</span></h1>
                <p style="margin: 10px 0 0; opacity: 0.9; font-size: 14px;">Premium Governance & Risk Analysis</p>
            </div>
            
            <div style="padding: 30px;">
                <h2 style="margin-top: 0;">Audit Summary</h2>
                <p style="color: #4b5563;">An automated scan has been completed for your infrastructure. Below is the executive summary for your security posture.</p>
                
                <div style="display: flex; gap: 10px; margin: 25px 0;">
                    <div style="flex: 1; background: #f3f4f6; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: #6366f1;">${stats.coverage}%</div>
                        <div style="font-size: 11px; text-transform: uppercase; color: #6b7280; margin-top: 5px;">Maturity Score</div>
                    </div>
                    <div style="flex: 1; background: #f3f4f6; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: #ef4444;">${stats.total - stats.passing}</div>
                        <div style="font-size: 11px; text-transform: uppercase; color: #6b7280; margin-top: 5px;">Drifts Found</div>
                    </div>
                </div>

                <h3>Key Findings</h3>
                <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
                    <thead>
                        <tr style="border-bottom: 1px solid #e5e7eb; text-align: left;">
                            <th style="padding: 10px 0; font-size: 12px; color: #6b7280;">Resource</th>
                            <th style="padding: 10px 0; font-size: 12px; color: #6b7280; text-align: right;">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.map(r => `
                            <tr style="border-bottom: 1px solid #f3f4f6;">
                                <td style="padding: 12px 0;">
                                    <div style="font-size: 14px; font-weight: 600;">${r.name}</div>
                                    <div style="font-size: 12px; color: #6b7280;">${r.type}</div>
                                </td>
                                <td style="padding: 12px 0; text-align: right;">
                                    <span style="font-size: 11px; font-weight: 700; padding: 4px 8px; border-radius: 100px; ${r.severity === 'pass' ? 'background: #ecfdf5; color: #059669;' : 'background: #fef2f2; color: #dc2626;'}">
                                        ${r.severity.toUpperCase()}
                                    </span>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>

                <div style="margin-top: 30px; padding: 20px; background: #eef2ff; border-radius: 8px; border: 1px solid #c7d2fe;">
                    <p style="margin: 0; font-size: 13px; color: #3730a3; line-height: 1.5;">
                        <strong>Note:</strong> This report was generated automatically. To download a detailed PDF with cryptographic evidence hashes, please visit the <a href="https://compflow.ai/dashboard" style="color: #4f46e5; font-weight: 700;">ComplianceFlow Dashboard</a>.
                    </p>
                </div>
            </div>
            
            <div style="background: #f9fafb; padding: 20px; text-align: center; font-size: 12px; color: #9ca3af; border-top: 1px solid #e5e7eb;">
                &copy; 2026 ComplianceFlow AINS. All rights reserved. <br>
                Classification: Confidential Audit Report.
            </div>
        </div>
    </body>
    </html>
    `;
}
