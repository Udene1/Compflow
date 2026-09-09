/**
 * Scan History & Terminal Replay Engine
 */
const ScanHistory = {
    API_URL: window.COMPLIANCE_API_URL + '/api/jobs',

    async refresh() {
        const list = document.getElementById('scan-history-list');
        list.innerHTML = '<div class="empty-state">Loading history...</div>';

        try {
            const clientId = localStorage.getItem('cf_client_id') || 'default';
            const fetchFn = (window.AuthUI && window.AuthUI.authFetch) ? window.AuthUI.authFetch : fetch;
            const response = await fetchFn(this.API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
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
            const fetchFn = (window.AuthUI && window.AuthUI.authFetch) ? window.AuthUI.authFetch : fetch;
            const response = await fetchFn(this.API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
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

// API error boundary: API failures remain JSON/API failures and are surfaced to the
// existing dashboard instead of becoming navigation/fallback-page events. This wrapper
// never changes HTTP status codes, response bodies, redirects, or successful responses.
(() => {
    const nativeFetch = window.fetch.bind(window);
    const apiBase = window.COMPLIANCE_API_URL || '';
    const seen = new Map();
    const toast = (message) => {
        if (typeof window.showToast === 'function') window.showToast(message);
    };

    function isApiRequest(input) {
        try {
            const url = typeof input === 'string' ? input : input?.url;
            if (!url) return false;
            return apiBase && new URL(url, window.location.href).origin === new URL(apiBase, window.location.href).origin;
        } catch {
            return false;
        }
    }

    async function inspectFailure(response) {
        if (response.ok || !isApiRequest(response.url)) return;
        try {
            const data = await response.clone().json();
            const code = data?.code || data?.error || `HTTP_${response.status}`;
            const message = data?.message || 'The request could not be completed.';
            const key = `${response.status}:${code}:${message}`;
            const now = Date.now();
            if (seen.get(key) && now - seen.get(key) < 3000) return;
            seen.set(key, now);

            if (response.status === 401) {
                toast('Your session is no longer valid. Please sign in again.');
            } else if (response.status === 402) {
                toast('Compflow service access is not currently active for this workspace.');
            } else if (response.status === 403) {
                toast('You do not have permission to perform this action.');
            } else if (response.status === 429) {
                toast('Too many requests. Please wait and try again.');
            } else if (response.status >= 500) {
                toast(`Compflow could not complete the request (${code}). Please try again.`);
            }
        } catch {
            // Non-JSON API failures are left to the calling feature; never redirect.
        }
    }

    window.fetch = async (...args) => {
        try {
            const response = await nativeFetch(...args);
            void inspectFailure(response);
            return response;
        } catch (error) {
            if (isApiRequest(args[0])) toast('Unable to reach Compflow API. Please check your connection and try again.');
            throw error;
        }
    };
})();

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
