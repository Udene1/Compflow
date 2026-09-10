(() => {
    const API_BASE = window.COMPLIANCE_API_URL || 'https://api.compflow.icu';
    let status = null;
    let mounted = false;

    function escapeHtml(value) {
        return String(value || '').replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
    }

    async function fetchStatus() {
        try {
            const response = await fetch(`${API_BASE}/api/owner-auth/status`, { credentials: 'include' });
            if (response.ok) status = await response.json();
        } catch (_) { status = null; }
    }

    function mount() {
        const container = document.getElementById('auth-gate-dynamic-actions');
        if (!container || mounted || !status) return;
        mounted = true;
        const section = document.createElement('div');
        section.id = 'owner-auth-section';
        section.style.cssText = 'margin-top:14px;padding-top:14px;border-top:1px solid rgba(255,255,255,.08);text-align:left';
        const title = status.ownerBootstrap ? 'Owner setup' : 'Owner sign in';
        const subtitle = status.ownerBootstrap
            ? `Create the first ComplianceFlow owner account for ${escapeHtml(status.ownerEmail)}.`
            : 'Sign in with your ComplianceFlow owner email and password.';
        section.innerHTML = `
            <div style="font-size:.78rem;font-weight:700;color:#fff;margin-bottom:4px">${title}</div>
            <div style="font-size:.7rem;color:var(--text-dim);margin-bottom:.7rem">${subtitle}</div>
            <input id="owner-auth-email" type="email" value="${escapeHtml(status.ownerEmail || '')}" autocomplete="username" ${status.ownerBootstrap ? '' : 'readonly'} placeholder="Owner email" style="width:100%;margin-bottom:.55rem;padding:.65rem .7rem;border-radius:7px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.25);color:#fff">
            ${status.ownerBootstrap ? '<input id="owner-auth-name" type="text" value="Kenneth Elioku" autocomplete="name" placeholder="Name" style="width:100%;margin-bottom:.55rem;padding:.65rem .7rem;border-radius:7px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.25);color:#fff">' : ''}
            ${status.ownerBootstrap ? '<input id="owner-auth-bootstrap" type="password" autocomplete="one-time-code" placeholder="One-time owner setup code" style="width:100%;margin-bottom:.55rem;padding:.65rem .7rem;border-radius:7px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.25);color:#fff">' : ''}
            <input id="owner-auth-password" type="password" autocomplete="${status.ownerBootstrap ? 'new-password' : 'current-password'}" placeholder="${status.ownerBootstrap ? 'Create password (12+ characters)' : 'Password'}" style="width:100%;margin-bottom:.65rem;padding:.65rem .7rem;border-radius:7px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.25);color:#fff">
            <div id="owner-auth-error" style="display:none;font-size:.7rem;color:#ef4444;margin-bottom:.5rem"></div>
            <button id="owner-auth-submit" class="btn btn-primary" style="width:100%;padding:.65rem;font-size:.82rem">${status.ownerBootstrap ? 'Create owner account' : 'Sign in as owner'}</button>`;
        container.appendChild(section);
        section.querySelector('#owner-auth-submit').addEventListener('click', submit);
        section.querySelector('#owner-auth-password').addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
    }

    async function submit() {
        const errorEl = document.getElementById('owner-auth-error');
        const button = document.getElementById('owner-auth-submit');
        const email = document.getElementById('owner-auth-email')?.value.trim();
        const password = document.getElementById('owner-auth-password')?.value || '';
        const payload = { email, password };
        if (status.ownerBootstrap) {
            payload.name = document.getElementById('owner-auth-name')?.value.trim();
            payload.bootstrapCode = document.getElementById('owner-auth-bootstrap')?.value || '';
        }
        if (!email || !password) { errorEl.textContent = 'Enter your email and password.'; errorEl.style.display = 'block'; return; }
        button.disabled = true;
        button.textContent = status.ownerBootstrap ? 'Creating…' : 'Signing in…';
        errorEl.style.display = 'none';
        try {
            const endpoint = status.ownerBootstrap ? '/api/owner-auth/bootstrap' : '/api/owner-auth/login';
            const response = await fetch(`${API_BASE}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify(payload) });
            const data = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(data.message || 'Authentication failed.');
            window.location.href = data.redirect || '/app.html?auth=success';
        } catch (error) {
            errorEl.textContent = error.message || 'Authentication failed.';
            errorEl.style.display = 'block';
            button.disabled = false;
            button.textContent = status.ownerBootstrap ? 'Create owner account' : 'Sign in as owner';
        }
    }

    async function init() {
        await fetchStatus();
        const observer = new MutationObserver(() => mount());
        const start = () => {
            const target = document.getElementById('auth-gate-dynamic-actions');
            if (target) observer.observe(target, { childList: true, subtree: true });
            mount();
        };
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true }); else start();
    }
    init();
})();
