// Central API/auth controller.
// Authentication redirects are reserved for authentication failures.
window.AuthUI = (() => {
    let currentUser = null;
    let authProviders = { google: { enabled: false }, github: { enabled: false }, devLogin: false, pilotAccess: false };
    const API_BASE = window.COMPLIANCE_API_URL || '';

    function parseApiError(response, data = null) {
        const body = data && typeof data === 'object' ? data : {};
        return {
            status: response?.status || 0,
            code: body.code || body.error || `HTTP_${response?.status || 0}`,
            error: body.error || null,
            message: body.message || body.error || `Request failed (${response?.status || 'network error'}).`,
            retryable: body.retryable === true || [429, 502, 503, 504].includes(response?.status)
        };
    }

    function showApiError(apiError, fallback = 'The request could not be completed.') {
        const message = apiError?.message || fallback;
        if (window.showToast) window.showToast(message);
        return apiError;
    }

    async function authFetch(url, options = {}) {
        const headers = options.headers ? { ...options.headers } : {};
        if (!headers['Content-Type'] && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
        let response;
        try {
            response = await fetch(url, { ...options, headers, credentials: 'include' });
        } catch (error) {
            const apiError = { status: 0, code: 'NETWORK_ERROR', error: 'NETWORK_ERROR', message: 'Unable to reach the Compflow API. Check your connection and try again.', retryable: true, cause: error };
            showApiError(apiError);
            throw Object.assign(new Error(apiError.message), apiError);
        }

        let data = null;
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            try { data = await response.json(); } catch (_) { data = null; }
        }

        if (response.ok) {
            response.compflowData = data;
            return response;
        }

        const apiError = parseApiError(response, data);
        response.compflowError = apiError;

        if (response.status === 401) {
            currentUser = null;
            renderHeaderWidget();
            showAuthGate();
            showApiError(apiError, 'Authentication required. Please sign in.');
        } else {
            // 402/403/409/422/429/5xx and all other API failures remain in-app.
            // Never navigate to the frontend host merely because an API call failed.
            showApiError(apiError);
        }
        return response;
    }

    async function requestJson(url, options = {}) {
        const response = await authFetch(url, options);
        let data = response.compflowData;
        if (data === undefined) {
            const contentType = response.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
                try { data = await response.clone().json(); } catch (_) { data = null; }
            }
        }
        if (!response.ok) throw Object.assign(new Error(response.compflowError?.message || 'Request failed.'), response.compflowError || parseApiError(response, data));
        return data;
    }

    // Remaining UI/auth functions are intentionally kept in the existing controller.
    return { authFetch, requestJson, parseApiError, showApiError };
})();
