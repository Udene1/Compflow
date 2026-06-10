/**
 * Scan History & Terminal Replay Engine
 */
const ScanHistory = {
    API_URL: 'https://0801eyc7vj.execute-api.us-east-1.amazonaws.com/dev/api/jobs',

    async refresh() {
        const list = document.getElementById('scan-history-list');
        list.innerHTML = '<div class="empty-state">Loading history...</div>';

        try {
            const clientId = localStorage.getItem('cf_client_id') || 'default';
            const response = await fetch(this.API_URL, {
                method: 'POST',
                body: JSON.stringify({ action: 'history', clientId })
            });
            const { history } = await response.json();

            if (!history || history.length === 0) {
                list.innerHTML = '<div class="empty-state">No recent sessions found.</div>';
                return;
            }

            list.innerHTML = history.slice(0, 5).map(job => `
                <div class="history-item" onclick="ScanHistory.replay('${job.jobId}')">
                    <div class="meta">
                        <span class="time">${new Date(job.createdAt).toLocaleString()}</span>
                        <span class="job-type">${job.scanType} Scan</span>
                    </div>
                    <span class="status-tag ${job.status}">${job.status}</span>
                </div>
            `).join('');

        } catch (e) {
            console.error("Scan History failed:", e);
            list.innerHTML = '<div class="empty-state">Failed to load history.</div>';
        }
    },

    /**
     * Replays a past session into the Live Terminal
     */
    async replay(jobId) {
        const terminal = document.getElementById('terminal-output');
        const termPanel = document.getElementById('panel-terminal');
        
        // Switch to terminal panel
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.getElementById('nav-terminal').classList.add('active');
        document.querySelectorAll('.content-panel').forEach(p => p.style.display = 'none');
        termPanel.style.display = 'block';

        terminal.innerHTML = '<div class="log-entry system">➤ Initializing historical replay for session ' + jobId + '...</div>';
        
        try {
            const response = await fetch(this.API_URL, {
                method: 'POST',
                body: JSON.stringify({ action: 'details', jobId })
            });
            const { job } = await response.json();

            if (!job || !job.logs) throw new Error("Job not found or has no logs.");

            // Add Replay Badge
            terminal.insertAdjacentHTML('afterbegin', '<div class="replay-badge">REPLAY MODE</div>');

            // Simulate streaming
            for (const entry of job.logs) {
                await new Promise(r => setTimeout(r, 100)); // Smooth replay
                const logDiv = document.createElement('div');
                logDiv.className = `log-entry ${entry.level.toLowerCase()}`;
                logDiv.textContent = `[${new Date(entry.timestamp).toLocaleTimeString()}] ${entry.message}`;
                terminal.appendChild(logDiv);
                terminal.scrollTop = terminal.scrollHeight;
            }

            terminal.insertAdjacentHTML('beforeend', '<div class="log-entry system">--- End of Replay ---</div>');

        } catch (e) {
            console.error("Replay failed:", e);
            terminal.insertAdjacentHTML('beforeend', '<div class="log-entry text-error">Replay Error: ' + e.message + '</div>');
        }
    }
};

// Initial load
document.addEventListener('DOMContentLoaded', () => {
    // Check if on scan panel to load history
    const scanPanel = document.getElementById('panel-scan');
    if (scanPanel && scanPanel.style.display !== 'none') {
        ScanHistory.refresh();
    }
});

// Refresh on panel switch
document.addEventListener('click', (e) => {
    const navItem = e.target.closest('.nav-item');
    if (navItem && navItem.dataset.panel === 'scan') {
        ScanHistory.refresh();
    }
});
