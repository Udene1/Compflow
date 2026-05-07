// ─── ComplianceFlow AI: Live Terminal ───
// Real-time filterable log stream with timestamps

window.LiveTerminal = (() => {
    const terminalEl = () => document.getElementById('live-terminal');
    let activeFilter = 'all';
    let isPaused = false;

    function init() {
        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeFilter = btn.dataset.filter;
                applyFilter();
            });
        });

        // Clear button
        document.getElementById('btn-clear-terminal').addEventListener('click', () => {
            const el = terminalEl();
            el.innerHTML = '';
            log('system', 'Terminal cleared.');
        });

        // Pause scroll on hover
        const el = terminalEl();
        el.addEventListener('mouseenter', () => { isPaused = true; });
        el.addEventListener('mouseleave', () => {
            isPaused = false;
            el.scrollTop = el.scrollHeight;
        });
    }

    function log(level, message) {
        const el = terminalEl();
        if (!el) return;

        const now = new Date();
        const ts = [now.getHours(), now.getMinutes(), now.getSeconds()]
            .map(v => String(v).padStart(2, '0')).join(':');

        const tagMap = {
            system: 'SYSTEM',
            agent: 'AGENT',
            insight: 'INSIGHT',
            action: 'ACTION',
            output: 'OUTPUT'
        };

        const line = document.createElement('div');
        line.className = 'log-line';
        line.dataset.level = level;
        line.innerHTML = `
            <span class="timestamp">${ts}</span>
            <span class="tag tag-${level}">${tagMap[level] || level.toUpperCase()}</span>
            <span class="msg">${escapeHtml(message)}</span>
        `;

        // Respect filter
        if (activeFilter !== 'all' && level !== activeFilter) {
            line.style.display = 'none';
        }

        el.appendChild(line);

        if (!isPaused) {
            el.scrollTop = el.scrollHeight;
        }
    }

    function applyFilter() {
        const el = terminalEl();
        el.querySelectorAll('.log-line').forEach(line => {
            if (activeFilter === 'all' || line.dataset.level === activeFilter) {
                line.style.display = '';
            } else {
                line.style.display = 'none';
            }
        });
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    document.addEventListener('DOMContentLoaded', init);

    return { log };
})();
