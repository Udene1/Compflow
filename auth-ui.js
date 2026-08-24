// ─── ComplianceFlow AI: Team Authentication & SSO UI Module ───
// Manages user session, OAuth SSO login, Dev Login, and Header Profile Pill

window.AuthUI = (() => {
    let currentUser = null;
    const API_BASE = window.COMPLIANCE_API_URL || '';

    async function init() {
        renderAuthWidget();
        await fetchCurrentUser();
    }

    async function fetchCurrentUser() {
        try {
            // Check session token in localStorage or cookie
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
            } else {
                currentUser = null;
            }
        } catch (e) {
            console.warn('Auth check skipped (offline or not logged in):', e);
            currentUser = null;
        }
        renderAuthWidget();
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
                    <span class="dropdown-chevron">▼</span>
                </div>
                
                <!-- Dropdown Menu -->
                <div class="profile-dropdown-menu" id="profile-dropdown-menu">
                    <div class="dropdown-header">
                        <div class="dropdown-email">${escapeHtml(currentUser.email)}</div>
                        <div class="dropdown-sub">Signed in via ${currentUser.provider || 'SSO'}</div>
                    </div>
                    <div class="dropdown-divider"></div>
                    <button class="dropdown-item" onclick="AuthUI.openAuthModal()">
                        <span class="item-icon">🔄</span> Switch Role / Account
                    </button>
                    <button class="dropdown-item text-danger" onclick="AuthUI.logout()">
                        <span class="item-icon">🚪</span> Sign Out
                    </button>
                </div>
            `;
        } else {
            container.innerHTML = `
                <button class="btn btn-primary btn-sm btn-auth-trigger" onclick="AuthUI.openAuthModal()">
                    <span class="icon">🔐</span> Sign In / SSO
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
        const menu = document.getElementById('profile-dropdown-menu');
        if (menu) menu.classList.toggle('active');
    }

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        const menu = document.getElementById('profile-dropdown-menu');
        if (menu && !e.target.closest('#auth-profile-widget')) {
            menu.classList.remove('active');
        }
    });

    function openAuthModal() {
        const modal = document.getElementById('modal-auth');
        if (modal) modal.classList.add('active');
    }

    function closeAuthModal() {
        const modal = document.getElementById('modal-auth');
        if (modal) modal.classList.remove('active');
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
                body: JSON.stringify({ role })
            });

            if (!res.ok) throw new Error('Dev login failed');
            const data = await res.json();
            
            if (data.token) localStorage.setItem('cf_auth_token', data.token);
            currentUser = data.user;
            
            renderAuthWidget();
            closeAuthModal();

            if (window.showToast) window.showToast(`Signed in as ${data.user.name} (${role})`);
            if (window.LiveTerminal) {
                LiveTerminal.log('system', `Auth session established for ${data.user.email} [${role}]`);
            }
        } catch (e) {
            if (window.showToast) window.showToast(`Login failed: ${e.message}`);
            console.error('Dev Login Error:', e);
        }
    }

    async function logout() {
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
            console.warn('Logout request warning:', e);
        }

        localStorage.removeItem('cf_auth_token');
        currentUser = null;
        renderAuthWidget();
        
        if (window.showToast) window.showToast('Signed out successfully.');
        if (window.LiveTerminal) {
            LiveTerminal.log('system', 'User session terminated. Reverted to anonymous viewer.');
        }
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

    // Auto-init on load
    document.addEventListener('DOMContentLoaded', init);

    return {
        init,
        fetchCurrentUser,
        getUser,
        hasPermission,
        openAuthModal,
        closeAuthModal,
        signInWithGoogle,
        signInWithGitHub,
        quickDevLogin,
        logout,
        toggleProfileMenu
    };
})();
