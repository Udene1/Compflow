(() => {
  const base = String(window.COMPLIANCE_API_URL || '').replace(/\/$/, '');
  const esc = value => String(value ?? '').replace(/[&<>\"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '\"':'&quot;' }[c]));
  const request = async (path, options = {}) => {
    const response = await fetch(`${base}${path}`, { credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) { const error = new Error(body.error || `HTTP_${response.status}`); error.status = response.status; throw error; }
    return body;
  };

  function statusTone(value) {
    const normalized = String(value || '').toUpperCase();
    if (['VERIFIED', 'PROVEN', 'REMEDIATED', 'SUCCEEDED', 'CONTROL_VERIFIED'].includes(normalized)) return 'execution-pass';
    if (['POTENTIAL', 'INCONCLUSIVE', 'VERIFICATION_PENDING', 'REANALYSIS_REQUIRED'].includes(normalized)) return 'execution-unknown';
    if (['FAILED', 'TAMPERED'].includes(normalized)) return 'execution-fail';
    return '';
  }

  function ensurePanel() {
    if (document.getElementById('trust-proof-panel')) return document.getElementById('trust-proof-panel');
    const page = document.querySelector('.page-content');
    if (!page) return null;
    const panel = document.createElement('div');
    panel.id = 'trust-proof-panel';
    panel.className = 'panel';
    panel.innerHTML = `
      <div class="card execution-section">
        <div style="display:flex;justify-content:space-between;gap:1rem;align-items:center;flex-wrap:wrap">
          <div><h3 style="margin:0">Trust &amp; Security Proof</h3><p style="margin:.35rem 0;color:var(--text-muted);font-size:.82rem">A customer-facing view of the evidence chain. Every claim below is derived from the durable execution record.</p></div>
          <div class="execution-toolbar"><input id="trust-execution-id" placeholder="execution ID" aria-label="Trust execution ID"><button class="btn btn-primary btn-sm" id="trust-load">Load proof</button></div>
        </div>
        <div id="trust-proof-status" class="execution-empty" style="margin-top:.8rem">Enter an execution ID to inspect its evidence, exposure paths, remediation state, reanalysis and measurable security effect.</div>
      </div>
      <div id="trust-proof-content" style="display:none">
        <div class="execution-stat-grid" id="trust-proof-stats"></div>
        <div class="execution-grid">
          <div class="card execution-section"><h3 style="margin:0">Evidence state</h3><div id="trust-evidence" class="execution-list" style="margin-top:.8rem"></div></div>
          <div class="card execution-section"><h3 style="margin:0">Security claims</h3><div id="trust-claims" class="execution-list" style="margin-top:.8rem"></div></div>
        </div>
        <div class="card execution-section" style="margin-top:1rem"><h3 style="margin:0">Exposure paths</h3><p style="margin:.35rem 0;color:var(--text-muted);font-size:.78rem">Potential paths remain explicitly distinguished from provider-verified relationships. Detection is not a breach claim.</p><div id="trust-paths" class="execution-list" style="margin-top:.8rem"></div></div>
        <div class="card execution-section" style="margin-top:1rem"><h3 style="margin:0">Remediation → reanalysis → security effect</h3><div id="trust-remediations" class="execution-list" style="margin-top:.8rem"></div></div>
      </div>`;
    page.appendChild(panel);
    const nav = document.querySelector('.sidebar-nav');
    if (nav && !document.getElementById('nav-trust')) {
      const section = document.createElement('div'); section.className = 'nav-section-label'; section.textContent = 'Trust'; nav.appendChild(section);
      const item = document.createElement('a'); item.className = 'nav-item'; item.dataset.panel = 'trust'; item.id = 'nav-trust'; item.innerHTML = '<span class="icon">🔐</span> Trust & Proof'; nav.appendChild(item);
      item.addEventListener('click', () => window.TrustInstrumentation.open());
    }
    document.getElementById('trust-load').addEventListener('click', () => load(document.getElementById('trust-execution-id').value.trim()));
    return panel;
  }

  function stat(label, value) { return `<div class="execution-stat"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`; }
  function evidenceState(row) {
    const freshness = row?.freshness?.state || row?.freshness_state || 'UNKNOWN';
    const integrity = row?.integrityValid === true ? 'VERIFIED' : row?.integrityValid === false ? 'TAMPERED' : 'UNKNOWN';
    return `${freshness} · ${integrity}`;
  }

  async function load(executionId) {
    const panel = ensurePanel();
    const status = document.getElementById('trust-proof-status');
    const content = document.getElementById('trust-proof-content');
    if (!executionId) { if (status) status.textContent = 'Execution ID required.'; return; }
    if (status) status.textContent = 'Loading durable evidence and security proof…';
    if (content) content.style.display = 'none';
    try {
      const [execution, evidence, paths, remediations] = await Promise.all([
        window.CompflowExecution.get(executionId, 0),
        window.CompflowExecution.evidence(executionId),
        window.CompflowExecution.exposurePaths(executionId),
        request(`/api/remediation/executions/${encodeURIComponent(executionId)}/remediations`)
      ]);
      render(executionId, execution, evidence, paths, remediations);
      if (status) status.textContent = `Loaded durable proof record for ${executionId}.`;
      if (content) content.style.display = 'block';
    } catch (error) {
      if (status) status.textContent = `Trust record unavailable: ${error.message}. No security claim is made.`;
    }
  }

  async function loadImpact(executionId, remediationId, target) {
    target.innerHTML = '<div class="execution-empty">Loading deterministic security effect…</div>';
    try {
      const impact = await request(`/api/remediation/executions/${encodeURIComponent(executionId)}/remediations/${encodeURIComponent(remediationId)}/impact`);
      const proof = impact.securityProof || impact.proof || null;
      const reanalysis = impact.reanalysis || null;
      target.innerHTML = `<div class="execution-row" style="display:block"><strong class="${statusTone(proof?.claimSafe ? 'PROVEN' : impact.securityEffect?.status || 'INCONCLUSIVE')}">${esc(proof?.claimSafe ? 'PROVEN SECURITY REDUCTION' : impact.securityEffect?.status || 'INCONCLUSIVE')}</strong><small style="display:block;margin-top:.35rem">${esc(impact.securityEffect?.reason || proof?.reason || 'Security effect cannot be claimed from the available evidence.')}</small><div class="execution-kv" style="margin-top:.6rem"><span>Baseline scan</span><code>${esc(reanalysis?.baselineScanId || proof?.baselineScanId || 'not available')}</code><span>Fresh scan</span><code>${esc(reanalysis?.freshScanId || proof?.freshScanId || 'not available')}</code><span>Risk delta</span><span>${esc(reanalysis?.riskDelta ?? proof?.riskDelta ?? 'not comparable')}</span><span>Paths removed</span><span>${esc(reanalysis?.removedPathCount ?? proof?.removedPathCount ?? 0)}</span></div></div>`;
    } catch (error) { target.innerHTML = `<div class="execution-empty">Security effect unavailable: ${esc(error.message)}. No reduction claim is made.</div>`; }
  }

  function render(executionId, execution, evidence, paths, remediations) {
    const eRows = evidence?.evidence || [];
    const pRows = paths?.paths || [];
    const rRows = remediations?.remediations || [];
    const content = document.getElementById('trust-proof-content');
    document.getElementById('trust-proof-stats').innerHTML = [
      stat('Execution', executionId),
      stat('Execution state', execution?.execution?.status || 'UNKNOWN'),
      stat('Evidence records', eRows.length),
      stat('Exposure paths', pRows.length),
      stat('Remediations', rRows.length)
    ].join('');
    document.getElementById('trust-evidence').innerHTML = eRows.length ? eRows.map(row => `<div class="execution-row"><span class="execution-dot"></span><div><strong>${esc(row.control_id || 'CONTROL')}</strong><small>${esc(row.provider || 'provider')} · ${esc(row.resource_id || 'resource')} · ${esc(row.evidence_id || row.id || '')}</small></div><span class="execution-status ${statusTone(row.integrityValid === true ? 'VERIFIED' : evidenceState(row))}">${esc(evidenceState(row))}</span></div>`).join('') : '<div class="execution-empty">No durable evidence records returned.</div>';
    document.getElementById('trust-claims').innerHTML = [
      `<div class="execution-decision"><h4>Claim boundary</h4><p style="margin:.35rem 0;font-size:.78rem">Observed provider state may support VERIFIED evidence. Correlated or incomplete relationships remain POTENTIAL or INCONCLUSIVE. Compromise is never inferred from correlation.</p></div>`,
      `<div class="execution-decision"><h4>Proof rule</h4><p style="margin:.35rem 0;font-size:.78rem">A remediation can become PROVEN only when control verification, independent fresh reanalysis, complete path comparison, and measurable risk/path reduction are all present.</p></div>`
    ].join('');
    document.getElementById('trust-paths').innerHTML = pRows.length ? pRows.map(path => `<div class="execution-row" style="display:block"><div style="display:flex;justify-content:space-between;gap:1rem"><strong>${esc(path.title || path.id)}</strong><span class="execution-status ${statusTone(path.status)}">${esc(path.status || 'UNKNOWN')}</span></div><small style="display:block;margin-top:.35rem">${esc(path.summary || '')}</small><small style="display:block;margin-top:.35rem;color:var(--text-muted)">${esc(path.severity || 'UNKNOWN')} · confidence ${Math.round(Number(path.confidence || 0) * 100)}% · ${path.evidence_complete ? 'evidence complete' : 'evidence incomplete'}</small><div style="margin-top:.55rem;font-size:.78rem">${(path.nodes || []).map(node => esc(node.label || node.resource_id || node.id)).join(' → ')}</div></div>`).join('') : '<div class="execution-empty">No durable exposure paths detected for this execution.</div>';
    const remediationContainer = document.getElementById('trust-remediations');
    remediationContainer.innerHTML = rRows.length ? rRows.map(row => `<div class="execution-row" style="display:block"><div style="display:flex;justify-content:space-between;gap:1rem"><strong>${esc(row.code || 'REMEDIATION')}</strong><span class="execution-status ${statusTone(row.state)}">${esc(row.state || 'UNKNOWN')}</span></div><small style="display:block;margin-top:.35rem">${esc(row.action || '')}</small><div id="trust-impact-${esc(row.id)}" style="margin-top:.55rem"><button class="btn btn-secondary btn-sm trust-impact-button" data-remediation-id="${esc(row.id)}">Inspect security effect</button></div></div>`).join('') : '<div class="execution-empty">No remediation records for this execution.</div>';
    remediationContainer.querySelectorAll('.trust-impact-button').forEach(button => button.addEventListener('click', () => loadImpact(executionId, button.dataset.remediationId, document.getElementById(`trust-impact-${button.dataset.remediationId}`))));
    if (content) content.dataset.executionId = executionId;
  }

  function open() {
    const panel = ensurePanel();
    document.querySelectorAll('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.panel === 'trust'));
    document.querySelectorAll('.panel').forEach(item => item.classList.toggle('active', item === panel));
    const title = document.getElementById('page-title'); if (title) title.textContent = 'Trust & Security Proof';
  }

  window.TrustInstrumentation = Object.freeze({ open, load });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ensurePanel, { once: true }); else ensurePanel();
})();
