// ─── ComplianceFlow: Authentication & App Mode Controller ───
// Manages honest login gate, session wiring, and Mode A/B enforcement.
// Production authentication uses real owner/password, SSO, or pilot activation.

window.AuthUI = (() => {
    let currentUser = null;
    let authProviders = { google: { enabled: false }, github: { enabled: false }, pilotAccess: false };
    const API_BASE = window.COMPLIANCE_API_URL || 'https://api.compflow.icu';

    function ensureAuthGateStyles() { if (document.querySelector('link[data-compflow-auth-gate]')) return; const link = document.createElement('link'); link.rel = 'stylesheet'; link.href = 'auth-gate.css'; link.dataset.compflowAuthGate = 'true'; document.head.appendChild(link); }
    function loadOwnerAuthUi() { if (document.querySelector('script[data-compflow-owner-auth]')) return; const script = document.createElement('script'); script.src = 'owner-auth-ui.js'; script.dataset.compflowOwnerAuth = 'true'; document.head.appendChild(script); }
    async function init() { ensureAuthGateStyles(); loadOwnerAuthUi(); await fetchProviders(); await fetchCurrentUser(); }

    async function parseApiError(response) {
        let data = null;
        try { data = await response.clone().json(); } catch (_) {}
        return { status: response.status, code: data?.code || data?.errorCode || (response.status === 401 ? 'AUTHENTICATION_REQUIRED' : `HTTP_${response.status}`), error: data?.error || null, message: data?.message || data?.error || `Request failed (${response.status}).`, data };
    }
    function messageForApiError(failure) {
        const messages = { AUTHENTICATION_REQUIRED: 'Your session is required. Please sign in.', INVALID_SESSION: 'Your session is no longer valid. Please sign in again.', INSUFFICIENT_PERMISSIONS: 'You do not have permission to perform this action.', ENTITLEMENT_REQUIRED: 'Your workspace does not currently have service access.', PILOT_ACCESS_EXPIRED: 'Pilot access has expired. Contact team — kenneth@compflow.icu', CLOUD_CONNECTION_NOT_VERIFIED: 'Verify the cloud connection before starting a scan.', QUEUE_UNAVAILABLE: 'The scan queue is temporarily unavailable. Please try again shortly.' };
        return messages[failure.code] || failure.message || 'The request could not be completed.';
    }
    async function authFetch(url, options = {}) {
        const headers = options.headers ? { ...options.headers } : {};
        if (!headers['Content-Type'] && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
        let response;
        try { response = await fetch(url, { ...options, headers, credentials: 'include' }); }
        catch (error) { const failure = { status: 0, code: 'NETWORK_ERROR', error: 'Network Error', message: 'Compflow could not reach the API. Check your connection and try again.', cause: error }; if (window.showToast) window.showToast(failure.message); throw Object.assign(new Error(failure.message), failure); }
        if (response.status === 401) { const failure = await parseApiError(response); currentUser = null; renderHeaderWidget(); showAuthGate(); if (window.showToast) window.showToast(messageForApiError(failure)); return response; }
        if (response.status >= 400) { const failure = await parseApiError(response); if (window.showToast) window.showToast(messageForApiError(failure)); }
        return response;
    }
    async function fetchProviders() {
        try { const res = await fetch(`${API_BASE}/api/auth/providers`, { credentials: 'include' }); if (res.ok) authProviders = await res.json(); }
        catch (e) { console.warn('Providers fetch skipped:', e); }
        renderAuthGateContent(); enforceProductionGuards();
    }
    function handleOAuthCallbackParams() {
        const urlParams = new URLSearchParams(window.location.search); const authStatus = urlParams.get('auth'); const authError = urlParams.get('auth_error');
        if (authError) { const messages = { account_exists: 'This email is already associated with a Compflow account. Sign in with your existing authentication method.', state_mismatch: 'Security validation failed. Please try signing in again.', domain_restricted: 'Access restricted: your email domain or GitHub organization is not authorized.', oauth_failed: 'Sign-in could not be completed with the identity provider. Please try again.', missing_oauth_params: 'Invalid authorization response from the identity provider.' }; if (window.showToast) window.showToast(messages[authError] || 'Authentication failed. Please try again.'); showAuthGate(); window.history.replaceState({}, document.title, window.location.pathname); return; }
        if (authStatus === 'success') { if (window.showToast) window.showToast('Welcome! Signed in successfully.'); window.history.replaceState({}, document.title, window.location.pathname); }
    }
    async function fetchCurrentUser() {
        try { const res = await fetch(`${API_BASE}/api/auth/me`, { headers: { 'Content-Type': 'application/json' }, credentials: 'include' }); if (res.ok) { const data = await res.json(); currentUser = data.user; hideAuthGate(); updateChecklistStep1(); await evaluateAppMode(); handleOAuthCallbackParams(); } else { currentUser = null; showAuthGate(); setMode('activation'); handleOAuthCallbackParams(); } }
        catch (e) { console.warn('Auth check skipped:', e); currentUser = null; showAuthGate(); setMode('activation'); handleOAuthCallbackParams(); }
        renderHeaderWidget(); updateStatusStrip();
    }
    async function evaluateAppMode() {
        if (!currentUser) { setMode('activation'); return; }
        try { const tRes = await authFetch(`${API_BASE}/api/tenants`); const tData = tRes.ok ? await tRes.json() : { tenants: [] }; const tenants = tData.tenants || []; const hasScanned = window.Scanner && window.Scanner.getScannedResources && window.Scanner.getScannedResources().length > 0; const hasConnectedTenant = tenants.some(t => t.status === 'active' || t.status === 'connected'); setMode(tenants.length > 0 && (hasScanned || hasConnectedTenant) ? 'app' : 'activation'); } catch (e) { setMode('activation'); }
    }
    function setMode(mode) {
        window.__CF_MODE = mode; const body = document.querySelector('.app-layout'); if (body) { body.classList.remove('mode-activation', 'mode-app'); body.classList.add(`mode-${mode}`); }
        const modeAHidden = ['nav-policies', 'nav-remediate', 'nav-evidence', 'nav-auditor', 'nav-reports', 'nav-monitoring', 'nav-tenants', 'nav-terminal', 'nav-settings']; const panelAHidden = ['panel-policies', 'panel-tenants', 'panel-remediate', 'panel-evidence', 'panel-auditor', 'panel-reports', 'panel-monitoring', 'panel-terminal']; const frameworkSelector = document.querySelector('.framework-selector'); const checklistCard = document.getElementById('onboarding-checklist-card'); const sidebarFooter = document.querySelector('.sidebar-footer'); const sectionLabels = document.querySelectorAll('.sidebar-nav .nav-section-label');
        if (mode === 'activation') { modeAHidden.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; }); panelAHidden.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; }); sectionLabels.forEach((el, i) => { if (i > 0) el.style.display = 'none'; }); if (frameworkSelector) frameworkSelector.style.display = 'none'; if (sidebarFooter) sidebarFooter.style.display = 'none'; if (checklistCard) checklistCard.style.display = 'block'; if (window.switchPanel) window.switchPanel('connect'); }
        else { modeAHidden.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = id === 'nav-auditor' ? (hasPermission('ADMIN') ? 'flex' : 'none') : 'flex'; }); panelAHidden.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = ''; }); sectionLabels.forEach(el => { el.style.display = ''; }); if (frameworkSelector) frameworkSelector.style.display = ''; if (sidebarFooter) sidebarFooter.style.display = ''; if (checklistCard) checklistCard.style.display = 'none'; }
    }
    function showAuthGate() { const gate = document.getElementById('auth-gate-overlay'); if (gate) gate.classList.add('active'); }
    function hideAuthGate() { const gate = document.getElementById('auth-gate-overlay'); if (gate) gate.classList.remove('active'); }
    function renderAuthGateContent() {
        const container = document.getElementById('auth-gate-dynamic-actions'); if (!container) return; let html = ''; let hasAnyProvider = false;
        if (authProviders.google?.enabled) { hasAnyProvider = true; html += `<button class="btn btn-sso-google" onclick="AuthUI.signInWithGoogle()"><span>Continue with Google</span></button>`; }
        if (authProviders.github?.enabled) { hasAnyProvider = true; html += `<button class="btn btn-sso-github" onclick="AuthUI.signInWithGitHub()"><span>Continue with GitHub</span></button>`; }
        if (authProviders.pilotAccess) { if (hasAnyProvider) html += `<div style="display:flex;align-items:center;gap:.75rem;margin:10px 0;color:var(--text-dim);font-size:.75rem"><div style="flex:1;height:1px;background:rgba(255,255,255,.08)"></div><span>or use pilot code</span><div style="flex:1;height:1px;background:rgba(255,255,255,.08)"></div></div>`; html += `<div class="pilot-login-form" id="pilot-login-form"><div style="margin-bottom:.7rem"><label style="font-size:.78rem;font-weight:600;color:var(--text-muted);display:block;margin-bottom:5px">Work email</label><input type="email" id="pilot-email" placeholder="you@company.com" autocomplete="email"></div><div style="margin-bottom:.8rem"><label style="font-size:.78rem;font-weight:600;color:var(--text-muted);display:block;margin-bottom:5px">Pilot access code</label><input type="password" id="pilot-code" placeholder="Enter access code" autocomplete="one-time-code"></div><div id="pilot-login-error" style="display:none;font-size:.78rem;color:#ef4444;margin-bottom:.5rem"></div><button class="btn btn-primary" onclick="AuthUI.pilotLogin()" style="width:100%;padding:.7rem;font-size:.9rem;font-weight:600">Sign in</button></div>`; }
        if (!hasAnyProvider && !authProviders.pilotAccess) html += `<div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);border-radius:8px;padding:1rem;font-size:.82rem;color:#f59e0b"><strong>Sign-in temporarily unavailable</strong><p style="margin-top:.3rem;font-size:.75rem;color:var(--text-muted)">Enterprise SSO is being configured. Contact your administrator for access.</p></div>`;
        container.innerHTML = html;
    }
    async function pilotLogin() {
        const email = document.getElementById('pilot-email')?.value?.trim(); const code = document.getElementById('pilot-code')?.value?.trim(); const errorEl = document.getElementById('pilot-login-error');
        if (!email || !code) { if (errorEl) { errorEl.textContent = 'Please enter your email and access code.'; errorEl.style.display = 'block'; } return; }
        try { if (errorEl) errorEl.style.display = 'none'; const res = await authFetch(`${API_BASE}/api/pilot/redeem`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code, email, name: email.split('@')[0] }) }); const data = await res.json().catch(() => ({})); if (!res.ok) { if (errorEl) { errorEl.textContent = messageForApiError({ status: res.status, code: data.code || data.errorCode, message: data.message || data.error }); errorEl.style.display = 'block'; } return; } currentUser = data.user; renderHeaderWidget(); hideAuthGate(); updateStatusStrip(); await evaluateAppMode(); if (window.showToast) window.showToast(`Signed in as ${data.user.name || data.user.email}`); } catch (e) { if (errorEl) { errorEl.textContent = e.message || 'Connection error. Please try again.'; errorEl.style.display = 'block'; } }
    }
    function updateStatusStrip() { const strip = document.getElementById('org-status-strip'); if (!strip) return; if (currentUser) { strip.style.display = 'flex'; const orgNameEl = document.getElementById('strip-org-name'); const userRoleEl = document.getElementById('strip-user-role'); const switchBtn = document.getElementById('btn-switch-workspace'); if (orgNameEl) orgNameEl.textContent = currentUser.orgName || 'Workspace'; if (userRoleEl) userRoleEl.textContent = (currentUser.role || 'VIEWER').toUpperCase(); if (switchBtn) switchBtn.style.display = ''; } else { strip.style.display = 'none'; const switchBtn = document.getElementById('btn-switch-workspace'); if (switchBtn) switchBtn.style.display = 'none'; } }
    function renderHeaderWidget() { const container = document.getElementById('auth-profile-widget'); if (!container) return; if (currentUser) { const initials = getInitials(currentUser.name || currentUser.email || 'U'); container.innerHTML = `<div class="user-profile-pill" style="display:flex;align-items:center;gap:.5rem"><div class="user-avatar-fallback" style="width:28px;height:28px;border-radius:50%;background:var(--primary);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:#fff">${initials}</div><span style="font-size:.8rem;color:#fff;font-weight:500">${escapeHtml(currentUser.name || currentUser.email)}</span><span style="font-size:.65rem;color:var(--text-dim);background:rgba(99,102,241,.15);padding:2px 6px;border-radius:4px">${(currentUser.role || 'VIEWER').toUpperCase()}</span><button onclick="AuthUI.logout(event)" style="background:none;border:1px solid rgba(255,255,255,.1);color:var(--text-muted);padding:3px 8px;border-radius:4px;font-size:.7rem;cursor:pointer;margin-left:.25rem">Sign out</button></div>`; } else container.innerHTML = `<button class="btn btn-primary btn-sm" onclick="AuthUI.showAuthGate()" style="font-size:.8rem;padding:6px 12px">Sign in</button>`; }
    function signInWithGoogle() { window.location.href = authProviders.google?.authUrl || `${API_BASE}/api/auth/google`; }
    function signInWithGitHub() { window.location.href = authProviders.github?.authUrl || `${API_BASE}/api/auth/github`; }
    async function logout(e) { if (e) { e.stopPropagation(); e.preventDefault(); } try { await authFetch(`${API_BASE}/api/auth/logout`, { method: 'POST' }); } catch (e) {} currentUser = null; renderHeaderWidget(); showAuthGate(); setMode('activation'); if (window.showToast) window.showToast('Signed out.'); }
    function getUser() { return currentUser; }
    function hasPermission(minRole) { if (!currentUser) return false; const levels = { VIEWER: 1, AUDITOR: 2, ENGINEER: 3, ADMIN: 4, OWNER: 5 }; return (levels[currentUser.role] || 1) >= (levels[minRole] || 1); }
    function getInitials(name) { const parts = name.trim().split(/\s+/); return parts.length >= 2 ? (parts[0][0] + parts[1][0]).toUpperCase() : name.slice(0, 2).toUpperCase(); }
    function escapeHtml(str) { if (!str) return ''; return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[m]); }
    function enforceProductionGuards() { const prodSection = document.getElementById('prod-account-section'); if (prodSection) prodSection.style.display = ''; const switchBtn = document.getElementById('btn-switch-workspace'); if (switchBtn) { switchBtn.textContent = 'Sign out'; switchBtn.onclick = e => logout(e); } }
    function openAccountModal() { const modal = document.getElementById('modal-account'); if (modal) modal.classList.add('active'); }
    function closeAccountModal() { const modal = document.getElementById('modal-account'); if (modal) modal.classList.remove('active'); }
    function updateChecklistStep1() { const desc = document.getElementById('step-auth-desc'); if (!desc || !currentUser) return; const providerMap = { google: 'Google', github: 'GitHub', pilot_code: 'Pilot Code', password: 'Password' }; const providerLabel = providerMap[currentUser.provider] || (currentUser.provider || 'SSO'); const displayName = currentUser.name || currentUser.email || 'unknown'; desc.textContent = `Signed in via ${providerLabel} — ${displayName}`; }
    document.addEventListener('DOMContentLoaded', init);
    return { init, authFetch, fetchCurrentUser, getUser, hasPermission, showAuthGate, hideAuthGate, signInWithGoogle, signInWithGitHub, pilotLogin, logout, evaluateAppMode, setMode, openAuthModal: openAccountModal, closeAuthModal: closeAccountModal, openAccountModal, closeAccountModal };
})();
