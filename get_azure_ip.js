import { ClientSecretCredential } from "@azure/identity";
import { NetworkManagementClient } from "@azure/arm-network";
import fs from "fs";

const creds = JSON.parse(fs.readFileSync("./dogfood_scan.json", "utf8")).credentials;
const credential = new ClientSecretCredential(creds.tenantId, creds.accessKeyId, creds.secretAccessKey);
const networkClient = new NetworkManagementClient(credential, creds.subscriptionId);

async function main() {
    try {
        const ipObj = await networkClient.publicIPAddresses.get("compflow-org", "compflow-backend-ip");
        console.log("AZURE_VM_PUBLIC_IP:", ipObj.ipAddress);
    } catch (e) {
        console.error("Failed to fetch public IP:", e.message);
    }
}

main();
