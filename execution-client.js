(() => {
  const base = String(window.COMPLIANCE_API_URL || '').replace(/\/$/, '');
  const esc = value => String(value ?? '').replace(/[&<>\"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '\"':'&quot;' }[c]));
  async function request(path, options = {}) {
    const response = await fetch(`${base}/api/v1${path}`, { credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) { const error = new Error(body.error || 'API_REQUEST_FAILED'); error.status = response.status; error.body = body; throw error; }
    return body;
  }
  function key() { if (window.crypto?.randomUUID) return `ui-${window.crypto.randomUUID()}`; return `ui-${Date.now()}-${Math.random().toString(16).slice(2)}`; }
  const api = {
    providers: () => request('/providers'), tenants: () => request('/tenants').catch(error => { if (error.status === 404) return { tenants: [] }; throw error; }),
    list: ({ status, limit = 25 } = {}) => request(`/executions?limit=${encodeURIComponent(limit)}${status ? `&status=${encodeURIComponent(status)}` : ''}`),
    create: (executionId, intent, idempotencyKey = key()) => request('/executions', { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify({ executionId, intent }) }),
    get: (executionId, afterSequence = 0) => request(`/executions/${encodeURIComponent(executionId)}?afterSequence=${encodeURIComponent(afterSequence)}`),
    evidence: (executionId) => request(`/executions/${encodeURIComponent(executionId)}/evidence`), decisions: (executionId) => request(`/executions/${encodeURIComponent(executionId)}/decisions`),
    trace: (executionId, limit = 100) => request(`/executions/${encodeURIComponent(executionId)}/trace?limit=${encodeURIComponent(limit)}`),
    exposurePaths: (executionId, limit = 100) => request(`/executions/${encodeURIComponent(executionId)}/exposure-paths?limit=${encodeURIComponent(limit)}`),
    analyzeExposurePaths: (executionId, idempotencyKey = key()) => request(`/executions/${encodeURIComponent(executionId)}/exposure-paths/analyze`, { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify({}) }),
    action: (executionId, action, body = {}, idempotencyKey = null) => request(`/executions/${encodeURIComponent(executionId)}/actions`, { method: 'POST', ...(idempotencyKey ? { headers: { 'Idempotency-Key': idempotencyKey } } : {}), body: JSON.stringify({ action, ...body }) }),
    stream: (executionId, handlers = {}) => { const source = new EventSource(`${base}/api/v1/executions/${encodeURIComponent(executionId)}/stream`, { withCredentials: true }); for (const name of ['ready', 'execution', 'audit', 'heartbeat', 'error']) source.addEventListener(name, event => { try { handlers[name]?.(JSON.parse(event.data)); } catch { handlers[name]?.(event.data); } }); return source; }
  };
  window.CompflowExecution = Object.freeze(api);

  function makeId(prefix) { return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`; }
  function toast(message) { if (window.showToast) window.showToast(message); else console.info(`[Compflow] ${message}`); }
  function statusClass(value) { return ['SUCCEEDED','FAILED','RUNNING','PENDING','CANCELLED'].includes(value) ? value : 'PENDING'; }

  async function mountWorkspace() {
    const panel = document.getElementById('execution-product-panel'); if (!panel || document.getElementById('execution-workspace')) return;
    const anchor = panel.querySelector('.card.execution-section'); if (!anchor) return;
    const workspace = document.createElement('div'); workspace.id = 'execution-workspace'; workspace.className = 'card execution-section'; workspace.style.marginBottom = '1rem';
    workspace.innerHTML = `
      <div style="display:flex;justify-content:space-between;gap:1rem;align-items:center;flex-wrap:wrap"><div><h3 style="margin:0">Compliance Operations</h3><p style="margin:.35rem 0;color:var(--text-muted);font-size:.82rem">Run a real audit, follow it live, and return to any durable execution.</p></div><div class="execution-toolbar"><select id="execution-status-filter" aria-label="Execution status"><option value="">All runs</option><option>RUNNING</option><option>PENDING</option><option>SUCCEEDED</option><option>FAILED</option><option>CANCELLED</option></select><button class="btn btn-primary btn-sm" id="execution-new-run">+ New compliance run</button></div></div>
      <div id="execution-run-list" class="execution-list" style="margin-top:.8rem;max-height:300px"></div>
      <div id="execution-exposure-panel" style="margin-top:1rem;border-top:1px solid rgba(255,255,255,.08);padding-top:1rem"><div style="display:flex;justify-content:space-between;align-items:center;gap:1rem"><div><h4 style="margin:0">Exposure paths</h4><p style="margin:.3rem 0;color:var(--text-muted);font-size:.78rem">Correlates only observed findings and explicit evidence-backed relationships. Detected does not mean breached.</p></div><button class="btn btn-secondary btn-sm" id="execution-analyze-exposure" disabled>Analyze selected run</button></div><div id="execution-exposure-list" class="execution-list" style="margin-top:.7rem"></div></div>`;
    panel.insertBefore(workspace, anchor);
    document.getElementById('execution-status-filter').addEventListener('change', refreshRuns); document.getElementById('execution-new-run').addEventListener('click', openRunDialog); document.getElementById('execution-analyze-exposure').addEventListener('click', analyzeSelectedExposure);
    await refreshRuns();
  }

  async function refreshRuns() {
    const list = document.getElementById('execution-run-list'); if (!list) return; list.innerHTML = '<div class="execution-empty">Loading durable executions…</div>';
    try { const status = document.getElementById('execution-status-filter')?.value || ''; const data = await api.list({ status, limit: 25 }); const executions = data.executions || [];
      list.innerHTML = executions.length ? executions.map(run => `<button type="button" class="execution-row" data-execution-id="${esc(run.id)}" style="width:100%;text-align:left;background:transparent;color:inherit;cursor:pointer"><span class="execution-dot execution-status ${statusClass(run.status)}"></span><div><strong>${esc(run.metadata?.objective || run.id)}</strong><small>${esc(run.id)} · ${esc(run.created_at || '')}</small></div><span class="execution-status ${statusClass(run.status)}">${esc(run.status)}</span></button>`).join('') : '<div class="execution-empty">No compliance runs yet. Start the first real audit.</div>';
      list.querySelectorAll('[data-execution-id]').forEach(button => button.addEventListener('click', () => selectExecution(button.dataset.executionId)));
    } catch (error) { list.innerHTML = `<div class="execution-empty">Unable to load executions: ${esc(error.message)}</div>`; }
  }

  async function selectExecution(id) {
    const input = document.getElementById('execution-id-input'); if (input) input.value = id;
    const analyzeButton = document.getElementById('execution-analyze-exposure'); if (analyzeButton) { analyzeButton.disabled = false; analyzeButton.dataset.executionId = id; }
    await window.CompflowExecutionUI?.refresh?.(); await refreshExposurePaths(id); toast(`Execution ${id} loaded`);
  }

  async function refreshExposurePaths(id) {
    const list = document.getElementById('execution-exposure-list'); if (!list || !id) return; list.innerHTML = '<div class="execution-empty">Loading exposure analysis…</div>';
    try { const data = await api.exposurePaths(id); const paths = data.paths || [];
      list.innerHTML = paths.length ? paths.map(path => `<div class="execution-row" style="display:block"><div style="display:flex;justify-content:space-between;gap:1rem"><strong>${esc(path.title)}</strong><span class="execution-status ${statusClass(path.status)}">${esc(path.severity)}</span></div><small style="display:block;margin-top:.35rem">${esc(path.summary)}</small><small style="display:block;margin-top:.35rem;color:var(--text-muted)">${esc(path.status)} · confidence ${Math.round(Number(path.confidence || 0) * 100)}% · ${path.evidence_complete ? 'evidence complete' : 'evidence incomplete'}</small><div style="margin-top:.55rem;font-size:.78rem">${(path.nodes || []).map(node => `<span>${esc(node.label)}</span>`).join(' → ')}</div></div>`).join('') : '<div class="execution-empty">No evidence-backed exposure path detected for this execution.</div>';
    } catch (error) { list.innerHTML = `<div class="execution-empty">Exposure analysis unavailable: ${esc(error.message)}</div>`; }
  }

  async function analyzeSelectedExposure() {
    const button = document.getElementById('execution-analyze-exposure'); const id = button?.dataset.executionId; if (!id) return;
    button.disabled = true; button.textContent = 'Analyzing…';
    try { await api.analyzeExposurePaths(id); await refreshExposurePaths(id); toast('Exposure paths refreshed from durable evidence.'); }
    catch (error) { toast(`Exposure analysis failed: ${error.message}`); }
    finally { button.disabled = false; button.textContent = 'Analyze selected run'; }
  }

  async function openRunDialog() {
    if (document.getElementById('execution-run-dialog')) return;
    const dialog = document.createElement('dialog'); dialog.id = 'execution-run-dialog'; dialog.style.cssText = 'max-width:720px;width:calc(100% - 2rem);border:1px solid rgba(255,255,255,.12);border-radius:12px;background:#111;color:inherit;padding:0;box-shadow:0 24px 80px rgba(0,0,0,.45)';
    dialog.innerHTML = `<form method="dialog" id="execution-run-form" style="padding:1.2rem"><div style="display:flex;justify-content:space-between;align-items:center"><div><h3 style="margin:0">Start compliance run</h3><p style="margin:.35rem 0;color:var(--text-muted);font-size:.8rem">This creates a durable intent and immediately dispatches the real execution graph.</p></div><button class="btn btn-secondary btn-sm" value="cancel">Close</button></div><div style="display:grid;gap:.8rem;margin-top:1rem"><label>Cloud environment<select id="run-tenant" required style="width:100%;margin-top:.3rem"></select></label><label>Framework<select id="run-framework" style="width:100%;margin-top:.3rem"><option value="soc2">SOC2</option><option value="iso27001">ISO 27001</option><option value="gdpr">GDPR</option><option value="hipaa">HIPAA</option><option value="pci-dss">PCI-DSS</option></select></label><label>Objective<input id="run-objective" required maxlength="256" value="Audit cloud infrastructure for compliance drift" style="width:100%;margin-top:.3rem"></label><label>Mode<select id="run-mode" style="width:100%;margin-top:.3rem"><option value="AUDIT">Audit only</option><option value="REMEDIATE">Audit + remediation</option></select></label><div id="run-error" style="display:none;padding:.7rem;border:1px solid rgba(255,90,90,.4);border-radius:8px;color:#ff9b9b;font-size:.8rem"></div><button class="btn btn-primary" id="run-submit" value="default">Start real compliance run</button></div></form>`;
    document.body.appendChild(dialog); const tenantSelect = dialog.querySelector('#run-tenant');
    try { const data = await api.tenants(); const tenants = data.tenants || []; tenantSelect.innerHTML = tenants.length ? tenants.map(t => `<option value="${esc(t.id)}" data-provider="${esc(t.provider)}">${esc(t.name || t.provider)} · ${esc(t.provider)}</option>`).join('') : '<option value="">No connected cloud environment</option>'; if (!tenants.length) dialog.querySelector('#run-submit').disabled = true; }
    catch { tenantSelect.innerHTML = '<option value="">Unable to load environments</option>'; dialog.querySelector('#run-submit').disabled = true; }
    dialog.querySelector('#execution-run-form').addEventListener('submit', async event => { event.preventDefault(); const selected = tenantSelect.selectedOptions[0]; const connectionId = selected?.value; const provider = selected?.dataset.provider; const errorEl = dialog.querySelector('#run-error'); const submit = dialog.querySelector('#run-submit'); if (!connectionId || !provider) { errorEl.textContent = 'Connect a cloud environment before starting an execution.'; errorEl.style.display = 'block'; return; } submit.disabled = true; submit.textContent = 'Creating durable execution…'; errorEl.style.display = 'none';
      try { const executionId = makeId('exec'); const intent = { id: makeId('intent'), version: '1', objective: dialog.querySelector('#run-objective').value.trim(), mode: dialog.querySelector('#run-mode').value, frameworks: [dialog.querySelector('#run-framework').value], rules: [], constraints: {}, targets: [{ connectionId, provider, resourceId: null }] }; await api.create(executionId, intent); dialog.close(); dialog.remove(); await refreshRuns(); await selectExecution(executionId); toast('Compliance run started. Execution is durable and can be resumed.'); }
      catch (error) { errorEl.textContent = error.message; errorEl.style.display = 'block'; submit.disabled = false; submit.textContent = 'Start real compliance run'; }
    });
    dialog.addEventListener('close', () => dialog.remove(), { once: true }); dialog.showModal();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountWorkspace, { once: true }); else mountWorkspace();
})();

const trustScript = document.createElement('script');
trustScript.src = 'trust-instrumentation.js?v=1.0';
trustScript.defer = true;
document.head.appendChild(trustScript);
