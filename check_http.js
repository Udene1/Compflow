import http from 'http';
import https from 'https';

function checkUrl(urlStr) {
    return new Promise((resolve) => {
        const urlObj = new URL(urlStr);
        const client = urlObj.protocol === 'https:' ? https : http;
        
        const req = client.get(urlStr, { timeout: 3000 }, (res) => {
            resolve({ url: urlStr, status: res.statusCode, headers: res.headers });
        });
        
        req.on('error', (err) => {
            resolve({ url: urlStr, error: err.message });
        });
        
        req.on('timeout', () => {
            req.destroy();
            resolve({ url: urlStr, error: 'TIMEOUT' });
        });
    });
}

async function run() {
    const urls = [
        "http://compflow.icu",
        "https://compflow.icu",
        "http://www.compflow.icu",
        "https://www.compflow.icu",
        "http://api.compflow.icu"
    ];
    
    console.log("Checking URLs...");
    const results = await Promise.all(urls.map(checkUrl));
    console.log(JSON.stringify(results, null, 2));
}

run();
