(() => {
  const base = String(window.COMPLIANCE_API_URL || '').replace(/\/$/, '');
  async function request(path, options = {}) {
    const response = await fetch(`${base}/api/v1${path}`, {
      credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) { const error = new Error(body.error || 'API_REQUEST_FAILED'); error.status = response.status; error.body = body; throw error; }
    return body;
  }
  function key() { if (window.crypto?.randomUUID) return `ui-${window.crypto.randomUUID()}`; return `ui-${Date.now()}-${Math.random().toString(16).slice(2)}`; }
  window.CompflowExecution = Object.freeze({
    providers: () => request('/providers'),
    create: (executionId, intent, idempotencyKey = key()) => request('/executions', { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify({ executionId, intent }) }),
    get: (executionId, afterSequence = 0) => request(`/executions/${encodeURIComponent(executionId)}?afterSequence=${encodeURIComponent(afterSequence)}`),
    evidence: (executionId) => request(`/executions/${encodeURIComponent(executionId)}/evidence`),
    decisions: (executionId) => request(`/executions/${encodeURIComponent(executionId)}/decisions`),
    action: (executionId, action, body = {}, idempotencyKey = null) => request(`/executions/${encodeURIComponent(executionId)}/actions`, { method: 'POST', ...(idempotencyKey ? { headers: { 'Idempotency-Key': idempotencyKey } } : {}), body: JSON.stringify({ action, ...body }) }),
    stream: (executionId, handlers = {}) => {
      const source = new EventSource(`${base}/api/v1/executions/${encodeURIComponent(executionId)}/stream`, { withCredentials: true });
      for (const name of ['ready', 'execution', 'audit', 'heartbeat', 'error']) source.addEventListener(name, event => {
        try { handlers[name]?.(JSON.parse(event.data)); } catch { handlers[name]?.(event.data); }
      });
      return source;
    }
  });
})();
