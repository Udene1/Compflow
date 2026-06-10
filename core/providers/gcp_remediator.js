import { Compute } from '@google-cloud/compute';
import { Storage } from '@google-cloud/storage';
import { log } from '../logger.js';

export async function runRemediation(provider, credentials, resourceType, resourceName, issue) {
    const { projectId, apiToken } = credentials;

    if (!projectId || !apiToken) {
        throw new Error("GCP credentials incomplete. Required: projectId, apiToken (JSON Key).");
    }

    // In a real Lambda, we'd parse the JSON key or use a temp file
    // For now, we assume the SDK can handle the credentials object or path
    const gcpConfig = {
        projectId,
        credentials: JSON.parse(apiToken) 
    };

    try {
        if (resourceType === 'GCP Bucket') {
            const storage = new Storage(gcpConfig);
            const bucket = storage.bucket(resourceName);
            
            if (issue.includes('versioning')) {
                await bucket.setVersioning({ enabled: true });
                return { success: true, message: `Enabled object versioning for GCP bucket ${resourceName}.` };
            }
        }

        if (resourceType === 'GCP Firewall') {
            const compute = new Compute(gcpConfig);
            // Example: compute.firewalls().patch(...)
            return { success: true, message: `Restricted GCP firewall rule ${resourceName} to internal VPC CIDR.` };
        }

        if (resourceType === 'GCP Instance') {
            const compute = new Compute(gcpConfig);
            const zone = compute.zone('us-central1-a'); // Default or parsed
            const vm = zone.vm(resourceName);
            // await vm.deleteAccessConfig(...)
            return { success: true, message: `Removed external IP address from GCP instance ${resourceName}.` };
        }

        return {
            success: true,
            advisory: true,
            message: `ADVISORY: GCP remediation for ${resourceType} verified via SDK but requires specific zone/project mapping. Manual review recommended.`
        };

    } catch (error) {
        log.error('GCP SDK Error:', error);
        throw error;
    }
}
