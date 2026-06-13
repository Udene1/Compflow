import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { ClientSecretCredential } from "@azure/identity";
import { GoogleAuth } from 'google-auth-library';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { provider, credentials } = req.body;

    const XOR_KEY = 'CompFlow_Guard_2026';
    function deobfuscate(encoded) {
        if (!encoded) return '';
        const decoded = atob(encoded);
        let out = "";
        for (let i = 0; i < decoded.length; i++) {
            out += String.fromCharCode(decoded.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
        }
        return out;
    }

    try {
        // ── AWS Validation ──
        if (provider === 'aws') {
            const sts = new STSClient({
                region: credentials.region || 'us-east-1',
                credentials: {
                    accessKeyId: credentials.isObfuscated ? deobfuscate(credentials.accessKeyId) : credentials.accessKeyId,
                    secretAccessKey: credentials.isObfuscated ? deobfuscate(credentials.secretAccessKey) : credentials.secretAccessKey
                }
            });
            const data = await sts.send(new GetCallerIdentityCommand({}));
            return res.status(200).json({ 
                success: true, 
                message: "AWS Identity verified.",
                identity: data.Arn 
            });
        }

        // ── Azure Validation ──
        if (provider === 'azure') {
            const tenantId = credentials.tenantId;
            const clientId = credentials.isObfuscated ? deobfuscate(credentials.accessKeyId) : credentials.accessKeyId;
            const clientSecret = credentials.isObfuscated ? deobfuscate(credentials.secretAccessKey) : credentials.secretAccessKey;
            
            const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            const token = await credential.getToken("https://management.azure.com/.default");
            return res.status(200).json({ 
                success: true, 
                message: "Azure Identity verified (OAuth2 Token obtained).",
                identity: `ClientID: ${clientId.substring(0, 8)}...`
            });
        }

        // ── GCP Validation ──
        if (provider === 'gcp') {
            const jsonKeyStr = credentials.isObfuscated ? deobfuscate(credentials.apiToken) : credentials.apiToken;
            const auth = new GoogleAuth({
                credentials: JSON.parse(jsonKeyStr),
                scopes: 'https://www.googleapis.com/auth/cloud-platform'
            });
            const client = await auth.getClient();
            const projectId = await auth.getProjectId();
            return res.status(200).json({ 
                success: true, 
                message: "GCP Identity verified.",
                identity: `Project: ${projectId}`
            });
        }

        // ── DigitalOcean Validation ──
        if (provider === 'digitalocean' || provider === 'do') {
            const token = credentials.isObfuscated ? deobfuscate(credentials.apiToken) : credentials.apiToken;
            const resp = await fetch('https://api.digitalocean.com/v2/account', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!resp.ok) throw new Error("Invalid DigitalOcean Token");
            const data = await resp.json();
            return res.status(200).json({ 
                success: true, 
                message: "DigitalOcean Identity verified.",
                identity: data.account.email
            });
        }

        // ── Hetzner Validation ──
        if (provider === 'hetzner') {
            const token = credentials.isObfuscated ? deobfuscate(credentials.apiToken) : credentials.apiToken;
            const resp = await fetch('https://api.hetzner.cloud/v1/account', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!resp.ok) throw new Error("Invalid Hetzner Token");
            const data = await resp.json();
            return res.status(200).json({ 
                success: true, 
                message: "Hetzner Identity verified.",
                identity: data.account.email
            });
        }

        throw new Error(`Cloud provider ${provider} validation not implemented.`);

    } catch (e) {
        console.error("Validation Error:", e.message);
        return res.status(401).json({ 
            success: false, 
            error: e.message 
        });
    }
}
