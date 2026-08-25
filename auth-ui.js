// ─── ComplianceFlow AI: Team Authentication & Progressive Disclosure Mode Module ───
// Manages user session, honest OAuth SSO gate, and Mode A (Activation) vs Mode B (Activated App)

window.AuthUI = (() => {
    let currentUser = null;
    let authProviders = { google: { enabled: false }, github: { enabled: false }, devLogin: false };
    const API_BASE = window.COMPLIANCE_API_URL || '';

    async function init() {
        renderAuthWidget();
        await fetchProviders();
        await fetchCurrentUser();
        handleOAuthCallbackParams();
    }

    /**
     * Centralized authenticated fetch wrapper that guarantees:
     * - credentials: 'include' (for secure HttpOnly session cookies across origins)
     * - Authorization header with Bearer token if present
     * - Automatic 401 interception to trigger auth gate
     */
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
            console.warn('[AUTH] 401 Unauthorized received for', url);
            currentUser = null;
            renderAuthWidget();
            showAuthGate();
            if (window.showToast) window.showToast('Session expired. Please sign in.');
        }

        return response;
    }

    async function fetchProviders() {
        try {
            const res = await fetch(`${API_BASE}/api/auth/providers`);
            if (res.ok) {
                authProviders = await res.json();
            }
        } catch (e) {
            console.warn('Providers fetch skipped:', e);
        }
        renderAuthGateContent();
    }

    function handleOAuthCallbackParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const authStatus = urlParams.get('auth');
        const authError = urlParams.get('auth_error');
        const role = urlParams.get('role');

        if (authError) {
            if (window.showToast) window.showToast(`Authentication Error: ${authError}`);
            showAuthGate();
            window.history.replaceState({}, document.title, window.location.pathname);
            return;
        }

        if (authStatus === 'success') {
            if (window.showToast) window.showToast(`✨ Welcome! Signed in successfully${role ? ` (${role})` : ''}.`);
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }

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
                await evaluateAppMode();
            } else {
                currentUser = null;
                showAuthGate();
                setMode('activation');
            }
        } catch (e) {
            console.warn('Auth check skipped:', e);
            currentUser = null;
            showAuthGate();
            setMode('activation');
        }

        renderAuthWidget();
        updateStatusStrip();
    }

    /**
     * Evaluates whether the user is in Mode A (Activation) or Mode B (Activated App)
     * Mode A: 0 tenants or 0 completed scans.
     * Mode B: >=1 tenant and >=1 completed scan.
     */
    async function evaluateAppMode() {
        if (!currentUser) {
            setMode('activation');
            return;
        }

        try {
            const tRes = await authFetch(`${API_BASE}/api/tenants`);
            const tData = tRes.ok ? await tRes.json() : { tenants: [] };
            const tenants = tData.tenants || [];

            const hasScanned = (window.Scanner && window.Scanner.getScannedResources && window.Scanner.getScannedResources().length > 0);

            if (tenants.length > 0 && hasScanned) {
                setMode('app');
            } else {
                setMode('activation');
            }
        } catch (e) {
            setMode('activation');
        }
    }

    function setMode(mode) {
        window.__CF_MODE = mode;
        const appLayout = document.querySelector('.app-layout');
        if (appLayout) {
            appLayout.classList.remove('mode-activation', 'mode-app');
            appLayout.classList.add(`mode-${mode}`);
        }

        // Mode A (Activation): Hide advanced navigation items & clutter
        const advancedNavs = [
            document.getElementById('nav-policies'),
            document.getElementById('nav-remediate'),
            document.getElementById('nav-evidence'),
            document.getElementById('nav-auditor'),
            document.getElementById('nav-reports'),
            document.getElementById('nav-monitoring'),
            document.getElementById('nav-tenants')
        ];

        const frameworkSelector = document.querySelector('.framework-selector');
        const autopilotToggle = document.getElementById('autopilot-toggle')?.closest('.framework-selector');
        const checklistCard = document.getElementById('onboarding-checklist-card');

        if (mode === 'activation') {
            advancedNavs.forEach(el => { if (el) el.style.display = 'none'; });
            if (frameworkSelector) frameworkSelector.style.display = 'none';
            if (autopilotToggle) autopilotToggle.style.display = 'none';
            if (checklistCard) checklistCard.style.display = 'block';

            // Ensure Connect panel is active
            if (window.switchPanel) window.switchPanel('connect');
        } else {
            // Mode B (Activated): Unlock full governance console
            advancedNavs.forEach(el => { 
                if (el) {
                    // Role gate auditor to ADMIN+
                    if (el.id === 'nav-auditor') {
                        el.style.display = hasPermission('ADMIN') ? 'flex' : 'none';
                    } else {
                        el.style.display = 'flex';
                    }
                }
            });
            if (frameworkSelector) frameworkSelector.style.display = 'block';
            if (autopilotToggle) autopilotToggle.style.display = 'block';
            if (checklistCard) checklistCard.style.display = 'none';
        }
    }

    function renderAuthGateContent() {
        const container = document.getElementById('auth-gate-dynamic-actions');
        if (!container) return;

        let html = '';

        if (authProviders.google?.enabled) {
            html += `
                <button class="btn btn-sso-google" onclick="AuthUI.signInWithGoogle()">
                    <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>
                    <span>Continue with Google</span>
                </button>
            `;
        }

        if (authProviders.github?.enabled) {
            html += `
                <button class="btn btn-sso-github" onclick="AuthUI.signInWithGitHub()">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="#fff"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                    <span>Continue with GitHub</span>
                </button>
            `;
        }

        // If in staging/dev mode, show developer options collapsed
        if (authProviders.devLogin) {
            html += `
                <details class="dev-login-details" style="margin-top:1rem; text-align:left; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:0.6rem;">
                    <summary style="font-size:0.75rem; color:var(--text-dim); cursor:pointer; font-weight:600;">Developer / Staging Options</summary>
                    <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:0.4rem; margin-top:0.6rem;">
                        <button class="btn btn-dev-role" onclick="AuthUI.quickDevLogin('ADMIN')">
                            <strong>👑 Admin</strong>
                        </button>
                        <button class="btn btn-dev-role" onclick="AuthUI.quickDevLogin('ENGINEER')">
                            <strong>⚙️ Engineer</strong>
                        </button>
                        <button class="btn btn-dev-role" onclick="AuthUI.quickDevLogin('AUDITOR')">
                            <strong>⚖️ Auditor</strong>
                        </button>
                    </div>
                </details>
            `;
        } else if (!authProviders.google?.enabled && !authProviders.github?.enabled) {
            html += `
                <div style="background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); border-radius:8px; padding:1rem; font-size:0.82rem; color:#f59e0b; margin-bottom:1rem;">
                    <strong>Pilot Onboarding In Progress</strong>
                    <p style="margin-top:0.25rem; font-size:0.75rem; color:var(--text-muted);">Enterprise SSO is currently restricted to pilot participants. Contact your administrator for access.</p>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    function showAuthGate() {
        const gate = document.getElementById('auth-gate-overlay');
        if (gate) gate.classList.add('active');
    }

    function hideAuthGate() {
        const gate = document.getElementById('auth-gate-overlay');
        if (gate) gate.classList.remove('active');
    }

    function updateStatusStrip() {
        const strip = document.getElementById('org-status-strip');
        if (!strip) return;

        if (currentUser) {
            strip.style.display = 'flex';
            const orgNameEl = document.getElementById('strip-org-name');
            const userRoleEl = document.getElementById('strip-user-role');
            if (orgNameEl) orgNameEl.textContent = currentUser.orgName || 'Workspace';
            if (userRoleEl) userRoleEl.textContent = (currentUser.role || 'VIEWER').toUpperCase();
        } else {
            strip.style.display = 'none';
        }
    }

    function renderAuthWidget() {
        const container = document.getElementById('auth-profile-widget');
        if (!container) return;

        if (currentUser) {
            const roleClass = `role-${(currentUser.role || 'viewer').toLowerCase()}`;
            const initials = getInitials(currentUser.name || currentUser.email || 'User');
            
            container.innerHTML = `
                <div class="user-profile-pill" onclick="AuthUI.toggleProfileMenu(event)">
                    <div class="user-avatar-wrap">
                        ${currentUser.avatarUrl ? 
                            `<img src="${currentUser.avatarUrl}" class="user-avatar-img" alt="Avatar">` : 
                            `<div class="user-avatar-fallback">${initials}</div>`
                        }
                        <span class="online-indicator"></span>
                    </div>
                    <div class="user-profile-details">
                        <div class="user-name">${escapeHtml(currentUser.name || currentUser.email)}</div>
                        <div class="user-meta">
                            <span class="user-role-badge ${roleClass}">${(currentUser.role || 'VIEWER').toUpperCase()}</span>
                            <span class="user-org-tag">${escapeHtml(currentUser.orgName || 'Workspace')}</span>
                        </div>
                    </div>
                    <button class="btn btn-secondary btn-xs btn-sign-out" onclick="AuthUI.logout(event)" style="margin-left:0.5rem; padding:3px 8px; font-size:0.7rem;">
                        Sign out
                    </button>
                </div>
            `;
        } else {
            container.innerHTML = `
                <button class="btn btn-primary btn-sm btn-auth-trigger" onclick="AuthUI.showAuthGate()">
                    <span class="icon">🔐</span> Sign In
                </button>
            `;
        }
    }

    function getInitials(name) {
        const parts = name.trim().split(/\s+/);
        if (parts.length >= 2) {
            return (parts[0][0] + parts[1][0]).toUpperCase();
        }
        return name.slice(0, 2).toUpperCase();
    }

    function toggleProfileMenu(e) {
        e.stopPropagation();
    }

    function signInWithGoogle() {
        window.location.href = `${API_BASE}/api/auth/google`;
    }

    function signInWithGitHub() {
        window.location.href = `${API_BASE}/api/auth/github`;
    }

    async function quickDevLogin(role = 'ADMIN') {
        try {
            if (window.showToast) window.showToast(`Authenticating as ${role}...`);
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
            
            renderAuthWidget();
            hideAuthGate();
            updateStatusStrip();
            await evaluateAppMode();

            if (window.showToast) window.showToast(`Signed in as ${data.user.name} (${role})`);
            if (window.LiveTerminal) {
                LiveTerminal.log('system', `Session established: ${data.user.email} [${role}]`);
            }
        } catch (e) {
            if (window.showToast) window.showToast(`Sign-in failed: ${e.message}`);
        }
    }

    async function logout(e) {
        if (e) e.stopPropagation();
        try {
            const token = localStorage.getItem('cf_auth_token');
            const headers = { 'Content-Type': 'application/json' };
            if (token) headers['Authorization'] = `Bearer ${token}`;

            await fetch(`${API_BASE}/api/auth/logout`, {
                method: 'POST',
                headers,
                credentials: 'include'
            });
        } catch (e) {
            console.warn('Logout request note:', e);
        }

        localStorage.removeItem('cf_auth_token');
        currentUser = null;
        renderAuthWidget();
        showAuthGate();
        setMode('activation');
        
        if (window.showToast) window.showToast('Signed out successfully.');
    }

    function getUser() {
        return currentUser;
    }

    function hasPermission(minRole) {
        if (!currentUser) return false;
        const levels = { 'VIEWER': 1, 'AUDITOR': 2, 'ENGINEER': 3, 'ADMIN': 4, 'OWNER': 5 };
        const userLevel = levels[currentUser.role] || 1;
        const reqLevel = levels[minRole] || 1;
        return userLevel >= reqLevel;
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, m => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
        })[m]);
    }

    document.addEventListener('DOMContentLoaded', init);

    return {
        init,
        authFetch,
        fetchCurrentUser,
        getUser,
        hasPermission,
        showAuthGate,
        hideAuthGate,
        signInWithGoogle,
        signInWithGitHub,
        quickDevLogin,
        logout,
        evaluateAppMode,
        setMode
    };
})();
