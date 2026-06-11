/**
 * Health Monitor UI Logic
 */
const HealthMonitor = {
    API_URL: window.COMPLIANCE_API_URL + '/api/monitoring',

    async refresh() {
        try {
            console.log("➤ Refreshing System Health...");
            const response = await fetch(this.API_URL, {
                method: 'POST',
                body: JSON.stringify({ clientId: 'default' })
            });
            const data = await response.json();

            // Update Stats
            document.getElementById('monitor-total-jobs').textContent = data.totalJobs || 0;
            document.getElementById('monitor-success-rate').textContent = data.successRate || '100%';
            document.getElementById('monitor-failed-jobs').textContent = data.failedCount || 0;

            // Update List
            const list = document.getElementById('monitor-failure-list');
            if (data.failures && data.failures.length > 0) {
                list.innerHTML = data.failures.map(f => `
                    <tr>
                        <td>${new Date(f.time).toLocaleTimeString()}</td>
                        <td><span class="badge ${f.provider}">${f.provider.toUpperCase()}</span></td>
                        <td>${f.action}</td>
                        <td class="text-error" style="font-size: 0.8rem">${f.error}</td>
                        <td><span class="status-pill status-fail">${f.status}</span></td>
                    </tr>
                `).join('');
            } else {
                list.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align:center; padding: 2rem; color: var(--text-muted);">
                            No active incidents detected. All clear.
                        </td>
                    </tr>
                `;
            }
        } catch (e) {
            console.error("Health Monitor failed:", e);
        }
    }
};

// Auto-refresh when panel is shown
document.addEventListener('click', (e) => {
    const navItem = e.target.closest('.nav-item');
    if (navItem && navItem.dataset.panel === 'monitoring') {
        HealthMonitor.refresh();
    }
});
