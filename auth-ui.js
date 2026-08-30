// ─── ComplianceFlow AI: Authentication & App Mode Controller ───
// Manages honest login gate, session wiring, and Mode A/B enforcement.
// Zero dev controls in production. Every API call uses authFetch.

window.AuthUI = (() => {
    let currentUser = null;
    let authProviders = { google: { enabled: false }, github: { enabled: false }, devLogin: false, pilotAccess: false };
    const API_BASE = window.COMPLIANCE_API_URL || '';

    async function init() {
        await fetchProviders();
        await fetchCurrentUser();
        // handleOAuthCallbackParams() is called inside fetchCurrentUser()
        // after auth state is definitively known — ensures gate close & toast fire in order.
    }

    // ─── Core: Authenticated fetch wrapper ───
    // EVERY API call from the SPA must go through this.
    // Guarantees credentials: 'include' + Bearer token + 401 interception.
    async function authFetch(url, options = {}) {
        const token = localStorage.getItem('cf_auth_token');
        const headers = options.headers ? { ...options.headers } : {};

        if (token && !headers['Authorization']) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        if (!headers['Content-Type'] && !(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
        }

        const fetchOptions = {
            ...options,
            headers,
            credentials: 'include'
        };

        const response = await fetch(url, fetchOptions);

        if (response.status === 401) {
            console.warn('[AUTH] 401 received for', url);
            currentUser = null;
            renderHeaderWidget();
            showAuthGate();
            if (window.showToast) window.showToast('Session expired. Please sign in.');
        }

        return response;
    }

    // ─── Fetch provider config from server (what login methods are available) ───
    async function fetchProviders() {
        try {
            const res = await fetch(`${API_BASE}/api/auth/providers`);
            if (res.ok) authProviders = await res.json();
        } catch (e) {
            console.warn('Providers fetch skipped:', e);
        }
        renderAuthGateContent();
        enforceProductionGuards();
    }

    function handleOAuthCallbackParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const authStatus = urlParams.get('auth');
        const authError = urlParams.get('auth_error');

        if (authError) {
            if (window.showToast) window.showToast(`Authentication Error: ${authError}`);
            showAuthGate();
            window.history.replaceState({}, document.title, window.location.pathname);
            return;
        }

        if (authStatus === 'success') {
            if (window.showToast) window.showToast('Welcome! Signed in successfully.');
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }

    // ─── Session check ───
    async function fetchCurrentUser() {
        try {
            const token = localStorage.getItem('cf_auth_token');
            const headers = { 'Content-Type': 'application/json' };
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const res = await fetch(`${API_BASE}/api/auth/me`, {
                headers,
                credentials: 'include'
            });

            if (res.ok) {
                const data = await res.json();
                currentUser = data.user;
                if (data.token) localStorage.setItem('cf_auth_token', data.token);
                hideAuthGate();
                updateChecklistStep1();
                await evaluateAppMode();
                handleOAuthCallbackParams();
            } else {
                currentUser = null;
                showAuthGate();
                setMode('activation');
                handleOAuthCallbackParams();
            }
        } catch (e) {
            console.warn('Auth check skipped:', e);
            currentUser = null;
            showAuthGate();
            setMode('activation');
            handleOAuthCallbackParams();
        }

        renderHeaderWidget();
        updateStatusStrip();
    }

    // ─── Mode evaluation: Activation (Mode A) vs App (Mode B) ───
    async function evaluateAppMode() {
        if (!currentUser) { setMode('activation'); return; }

        try {
            const tRes = await authFetch(`${API_BASE}/api/tenants`);
            const tData = tRes.ok ? await tRes.json() : { tenants: [] };
            const tenants = tData.tenants || [];
            const hasScanned = (window.Scanner && window.Scanner.getScannedResources && window.Scanner.getScannedResources().length > 0);

            // Consider connected tenants as evidence of prior scan (persists across refresh)
            const hasConnectedTenant = tenants.some(t => t.status === 'active' || t.status === 'connected');

            if (tenants.length > 0 && (hasScanned || hasConnectedTenant)) {
                setMode('app');
            } else {
                setMode('activation');
            }
        } catch (e) {
            setMode('activation');
        }
    }

    // ─── Mode enforcement (the critical part) ───
    function setMode(mode) {
        window.__CF_MODE = mode;

        const body = document.querySelector('.app-layout');
        if (body) {
            body.classList.remove('mode-activation', 'mode-app');
            body.classList.add(`mode-${mode}`);
        }

        // IDs of nav items that MUST be hidden in Mode A
        const modeAHidden = ['nav-policies', 'nav-remediate', 'nav-evidence', 'nav-auditor', 'nav-reports', 'nav-monitoring', 'nav-tenants', 'nav-terminal', 'nav-settings'];
        // IDs of panels that MUST be hidden in Mode A
        const panelAHidden = ['panel-policies', 'panel-tenants', 'panel-remediate', 'panel-evidence', 'panel-auditor', 'panel-reports', 'panel-monitoring', 'panel-terminal'];

        const frameworkSelector = document.querySelector('.framework-selector');
        const checklistCard = document.getElementById('onboarding-checklist-card');
        const sidebarFooter = document.querySelector('.sidebar-footer');

        // Section labels
        const sectionLabels = document.querySelectorAll('.sidebar-nav .nav-section-label');

        if (mode === 'activation') {
            // Hide all advanced nav items
            modeAHidden.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = 'none';
            });
            // Hide all advanced panels
            panelAHidden.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = 'none';
            });
            // Hide section labels except the first
            sectionLabels.forEach((el, i) => { if (i > 0) el.style.display = 'none'; });
            // Hide framework selector and sidebar footer
            if (frameworkSelector) frameworkSelector.style.display = 'none';
            if (sidebarFooter) sidebarFooter.style.display = 'none';
            // Show checklist
            if (checklistCard) checklistCard.style.display = 'block';
            // Force connect panel
            if (window.switchPanel) window.switchPanel('connect');
        } else {
            // Mode B: unlock everything
            modeAHidden.forEach(id => {
                const el = document.getElementById(id);
                if (el) {
                    if (id === 'nav-auditor') {
                        el.style.display = hasPermission('ADMIN') ? 'flex' : 'none';
                    } else {
                        el.style.display = 'flex';
                    }
                }
            });
            panelAHidden.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = '';
            });
            sectionLabels.forEach(el => { el.style.display = ''; });
            if (frameworkSelector) frameworkSelector.style.display = '';
            if (sidebarFooter) sidebarFooter.style.display = '';
            if (checklistCard) checklistCard.style.display = 'none';
        }
    }

    // ─── Auth gate overlay ───
    function showAuthGate() {
        const gate = document.getElementById('auth-gate-overlay');
        if (gate) gate.classList.add('active');
    }

    function hideAuthGate() {
        const gate = document.getElementById('auth-gate-overlay');
        if (gate) gate.classList.remove('active');
    }

    // ─── Dynamic auth gate content (only shows what actually works) ───
    function renderAuthGateContent() {
        const container = document.getElementById('auth-gate-dynamic-actions');
        if (!container) return;

        let html = '';
        let hasAnyProvider = false;

        // Real SSO buttons — only when the server confirms they're configured
        if (authProviders.google?.enabled) {
            hasAnyProvider = true;
            html += `
                <button class="btn btn-sso-google" onclick="AuthUI.signInWithGoogle()" style="width:100%; display:flex; align-items:center; justify-content:center; gap:10px; padding:0.8rem 1.2rem; background:#fff; color:#333; border:1px solid #ddd; border-radius:8px; font-size:0.9rem; font-weight:600; cursor:pointer; transition:all 0.2s ease;">
                    <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>
                    <span>Continue with Google</span>
                </button>
            `;
        }

        if (authProviders.github?.enabled) {
            hasAnyProvider = true;
            html += `
                <button class="btn btn-sso-github" onclick="AuthUI.signInWithGitHub()" style="width:100%; display:flex; align-items:center; justify-content:center; gap:10px; padding:0.8rem 1.2rem; background:#24292e; color:#fff; border:1px solid #444; border-radius:8px; font-size:0.9rem; font-weight:600; cursor:pointer; margin-top:0.5rem; transition:all 0.2s ease;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="#fff"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                    <span>Continue with GitHub</span>
                </button>
            `;
        }

        // Pilot access code form — honest gated login when no SSO
        if (authProviders.pilotAccess) {
            if (hasAnyProvider) {
                html += `<div style="display:flex; align-items:center; gap:0.75rem; margin:1rem 0; color:var(--text-dim); font-size:0.75rem;">
                    <div style="flex:1; height:1px; background:rgba(255,255,255,0.08);"></div>
                    <span>or use pilot code</span>
                    <div style="flex:1; height:1px; background:rgba(255,255,255,0.08);"></div>
                </div>`;
            }
            html += `
                <div class="pilot-login-form" id="pilot-login-form" style="text-align:left;">
                    <div style="margin-bottom:0.6rem;">
                        <label style="font-size:0.78rem; font-weight:600; color:var(--text-muted); display:block; margin-bottom:4px;">Work email</label>
                        <input type="email" id="pilot-email" placeholder="you@company.com" style="width:100%; padding:0.6rem 0.8rem; background:rgba(0,0,0,0.3); border:1px solid rgba(255,255,255,0.12); border-radius:6px; color:#fff; font-size:0.85rem;">
                    </div>
                    <div style="margin-bottom:0.8rem;">
                        <label style="font-size:0.78rem; font-weight:600; color:var(--text-muted); display:block; margin-bottom:4px;">Pilot access code</label>
                        <input type="password" id="pilot-code" placeholder="Enter access code" style="width:100%; padding:0.6rem 0.8rem; background:rgba(0,0,0,0.3); border:1px solid rgba(255,255,255,0.12); border-radius:6px; color:#fff; font-size:0.85rem;">
                    </div>
                    <div id="pilot-login-error" style="display:none; font-size:0.78rem; color:#ef4444; margin-bottom:0.5rem;"></div>
                    <button class="btn btn-primary" onclick="AuthUI.pilotLogin()" style="width:100%; padding:0.7rem; font-size:0.9rem; font-weight:600;">
                        Sign in
                    </button>
                </div>
            `;
        }

        // Dev login — development ONLY, collapsed
        if (authProviders.devLogin) {
            html += `
                <details style="margin-top:1rem; text-align:left; border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:0.5rem 0.6rem;">
                    <summary style="font-size:0.72rem; color:var(--text-dim); cursor:pointer;">Developer options (local only)</summary>
                    <div style="display:flex; gap:0.4rem; margin-top:0.5rem;">
                        <button class="btn btn-dev-role" onclick="AuthUI.quickDevLogin('ADMIN')" style="flex:1; padding:0.4rem; font-size:0.72rem;">Admin</button>
                        <button class="btn btn-dev-role" onclick="AuthUI.quickDevLogin('ENGINEER')" style="flex:1; padding:0.4rem; font-size:0.72rem;">Engineer</button>
                        <button class="btn btn-dev-role" onclick="AuthUI.quickDevLogin('AUDITOR')" style="flex:1; padding:0.4rem; font-size:0.72rem;">Auditor</button>
                    </div>
                </details>
            `;
        }

        // Nothing works — show honest message
        if (!hasAnyProvider && !authProviders.pilotAccess && !authProviders.devLogin) {
            html += `
                <div style="background:rgba(245,158,11,0.08); border:1px solid rgba(245,158,11,0.25); border-radius:8px; padding:1rem; font-size:0.82rem; color:#f59e0b;">
                    <strong>Sign-in temporarily unavailable</strong>
                    <p style="margin-top:0.3rem; font-size:0.75rem; color:var(--text-muted);">Enterprise SSO is being configured. Contact your administrator for access.</p>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    // ─── Pilot access code login ───
    async function pilotLogin() {
        const email = document.getElementById('pilot-email')?.value?.trim();
        const code = document.getElementById('pilot-code')?.value?.trim();
        const errorEl = document.getElementById('pilot-login-error');

        if (!email || !code) {
            if (errorEl) { errorEl.textContent = 'Please enter your email and access code.'; errorEl.style.display = 'block'; }
            return;
        }

        try {
            if (errorEl) errorEl.style.display = 'none';
            const res = await fetch(`${API_BASE}/api/auth/pilot-login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ code, email })
            });

            const data = await res.json();
            if (!res.ok) {
                if (errorEl) { errorEl.textContent = data.message || 'Login failed.'; errorEl.style.display = 'block'; }
                return;
            }

            if (data.sessionToken) localStorage.setItem('cf_auth_token', data.sessionToken);
            currentUser = data.user;
            renderHeaderWidget();
            hideAuthGate();
            updateStatusStrip();
            await evaluateAppMode();
            if (window.showToast) window.showToast(`Signed in as ${data.user.name || data.user.email}`);
        } catch (e) {
            if (errorEl) { errorEl.textContent = 'Connection error. Please try again.'; errorEl.style.display = 'block'; }
        }
    }

    // ─── Status strip update ───
    function updateStatusStrip() {
        const strip = document.getElementById('org-status-strip');
        if (!strip) return;
        if (currentUser) {
            strip.style.display = 'flex';
            const orgNameEl = document.getElementById('strip-org-name');
            const userRoleEl = document.getElementById('strip-user-role');
            const switchBtn = document.getElementById('btn-switch-workspace');
            if (orgNameEl) orgNameEl.textContent = currentUser.orgName || 'Workspace';
            if (userRoleEl) userRoleEl.textContent = (currentUser.role || 'VIEWER').toUpperCase();
            if (switchBtn) switchBtn.style.display = '';
        } else {
            strip.style.display = 'none';
            const switchBtn = document.getElementById('btn-switch-workspace');
            if (switchBtn) switchBtn.style.display = 'none';
        }
    }

    // ─── Header profile widget ───
    function renderHeaderWidget() {
        const container = document.getElementById('auth-profile-widget');
        if (!container) return;

        if (currentUser) {
            const initials = getInitials(currentUser.name || currentUser.email || 'U');
            container.innerHTML = `
                <div class="user-profile-pill" style="display:flex; align-items:center; gap:0.5rem;">
                    <div class="user-avatar-fallback" style="width:28px; height:28px; border-radius:50%; background:var(--primary); display:flex; align-items:center; justify-content:center; font-size:0.7rem; font-weight:700; color:#fff;">${initials}</div>
                    <span style="font-size:0.8rem; color:#fff; font-weight:500;">${escapeHtml(currentUser.name || currentUser.email)}</span>
                    <span style="font-size:0.65rem; color:var(--text-dim); background:rgba(99,102,241,0.15); padding:2px 6px; border-radius:4px;">${(currentUser.role || 'VIEWER').toUpperCase()}</span>
                    <button onclick="AuthUI.logout(event)" style="background:none; border:1px solid rgba(255,255,255,0.1); color:var(--text-muted); padding:3px 8px; border-radius:4px; font-size:0.7rem; cursor:pointer; margin-left:0.25rem;">Sign out</button>
                </div>
            `;
        } else {
            container.innerHTML = `
                <button class="btn btn-primary btn-sm" onclick="AuthUI.showAuthGate()" style="font-size:0.8rem; padding:6px 12px;">Sign in</button>
            `;
        }
    }

    // ─── SSO redirects (use full URL from providers API) ───
    function signInWithGoogle() {
        const url = authProviders.google?.authUrl || `${API_BASE}/api/auth/google`;
        window.location.href = url;
    }
    function signInWithGitHub() {
        const url = authProviders.github?.authUrl || `${API_BASE}/api/auth/github`;
        window.location.href = url;
    }

    // ─── Dev login (development ONLY) ───
    async function quickDevLogin(role = 'ADMIN') {
        try {
            const res = await fetch(`${API_BASE}/api/auth/dev-login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ role })
            });

            if (!res.ok) throw new Error('Dev login unavailable');
            const data = await res.json();
            if (data.sessionToken) localStorage.setItem('cf_auth_token', data.sessionToken);
            currentUser = data.user;
            renderHeaderWidget();
            hideAuthGate();
            updateStatusStrip();
            await evaluateAppMode();
            if (window.showToast) window.showToast(`Signed in as ${data.user.name} (${role})`);
        } catch (e) {
            if (window.showToast) window.showToast(`Sign-in failed: ${e.message}`);
        }
    }

    // ─── Logout ───
    async function logout(e) {
        if (e) { e.stopPropagation(); e.preventDefault(); }
        try {
            await authFetch(`${API_BASE}/api/auth/logout`, { method: 'POST' });
        } catch (e) { /* best-effort */ }

        localStorage.removeItem('cf_auth_token');
        currentUser = null;
        renderHeaderWidget();
        showAuthGate();
        setMode('activation');
        if (window.showToast) window.showToast('Signed out.');
    }

    // ─── Utilities ───
    function getUser() { return currentUser; }

    function hasPermission(minRole) {
        if (!currentUser) return false;
        const levels = { 'VIEWER': 1, 'AUDITOR': 2, 'ENGINEER': 3, 'ADMIN': 4, 'OWNER': 5 };
        return (levels[currentUser.role] || 1) >= (levels[minRole] || 1);
    }

    function getInitials(name) {
        const parts = name.trim().split(/\s+/);
        return parts.length >= 2 ? (parts[0][0] + parts[1][0]).toUpperCase() : name.slice(0, 2).toUpperCase();
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[m]);
    }

    // ─── Production guard: hide dev-only UI elements ───
    function enforceProductionGuards() {
        const isDevMode = authProviders.devLogin === true;

        // Role-picker modal sections
        const devRoles = document.getElementById('dev-roles-section');
        const prodSection = document.getElementById('prod-account-section');
        if (devRoles) devRoles.style.display = isDevMode ? '' : 'none';
        if (prodSection) prodSection.style.display = isDevMode ? 'none' : '';

        // Switch Workspace button in org status strip
        const switchBtn = document.getElementById('btn-switch-workspace');
        if (switchBtn) {
            if (isDevMode) {
                switchBtn.textContent = 'Switch Role';
                switchBtn.onclick = () => { if (window.AuthUI.openAccountModal) window.AuthUI.openAccountModal(); };
            } else {
                switchBtn.textContent = 'Sign out';
                switchBtn.onclick = (e) => logout(e);
            }
        }
    }

    // ─── Account modal open/close (renamed from modal-auth to avoid ID conflict with cloud settings modal) ───
    function openAccountModal() {
        const modal = document.getElementById('modal-account');
        if (modal) modal.classList.add('active');
    }
    function closeAccountModal() {
        const modal = document.getElementById('modal-account');
        if (modal) modal.classList.remove('active');
    }

    // ─── Update checklist step 1 with actual provider/email ───
    function updateChecklistStep1() {
        const desc = document.getElementById('step-auth-desc');
        if (!desc || !currentUser) return;
        const providerMap = { google: 'Google', github: 'GitHub', pilot_code: 'Pilot Code', dev_portal: 'Dev Portal' };
        const providerLabel = providerMap[currentUser.provider] || (currentUser.provider || 'SSO');
        const displayName = currentUser.name || currentUser.email || 'unknown';
        desc.textContent = `Signed in via ${providerLabel} — ${escapeHtml(displayName)}`;
    }

    document.addEventListener('DOMContentLoaded', init);

    return {
        init, authFetch, fetchCurrentUser, getUser, hasPermission,
        showAuthGate, hideAuthGate,
        signInWithGoogle, signInWithGitHub,
        pilotLogin, quickDevLogin, logout,
        evaluateAppMode, setMode,
        openAuthModal: openAccountModal, closeAuthModal: closeAccountModal,  // legacy aliases
        openAccountModal, closeAccountModal
    };
})();
