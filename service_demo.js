const terminal = document.getElementById('terminal-output');
const runBtn = document.getElementById('run-autopilot');

const logs = [
    { text: "[System] Connected to AWS Infrastructure (us-east-1)...", color: "#6366f1" },
    { text: "[AI Agent] Scanning 42 cloud resources...", color: "#00ff00" },
    { text: "[Insight] Critical Failure: S3 bucket 'finance-records' is public.", color: "#ef4444" },
    { text: "[AI Agent] Attempting AUTO-REMEDIATION...", color: "#ec4899" },
    { text: "[AI Agent] S3 Bucket Policy Updated. Status: Private.", color: "#10b981" },
    { text: "[Insight] Missing MFA found on 2 admin roles.", color: "#ef4444" },
    { text: "[AI Agent] Enforcing MFA policy across IAM group 'Admins'...", color: "#ec4899" },
    { text: "[AI Agent] Policy enforced. Remediated.", color: "#10b981" },
    { text: "[System] Capturing evidence for Audit Control CC1.1...", color: "#6366f1" },
    { text: "[Output] Outcome Delivered: Readiness score 100%.", color: "#f9fafb" },
    { text: "[System] Task Complete. Certification ready for generation.", color: "#6366f1" }
];

function addLog(message, color) {
    const line = document.createElement('div');
    line.className = 'line';
    line.style.color = color;
    line.innerText = message;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

runBtn.addEventListener('click', () => {
    runBtn.disabled = true;
    runBtn.innerText = "Running...";
    terminal.innerHTML = "";
    
    let delay = 0;
    logs.forEach((log, index) => {
        setTimeout(() => {
            addLog(log.text, log.color);
            if (index === logs.length - 1) {
                runBtn.disabled = false;
                runBtn.innerText = "Run AI Autopilot";
            }
        }, delay);
        delay += 800 + Math.random() * 1000;
    });
});
