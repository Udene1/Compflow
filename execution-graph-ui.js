(() => {
  const API = (window.COMPLIANCE_API_URL || '').replace(/\/$/, '');
  const $ = id => document.getElementById(id);
  let timer = null;
  let source = null;
  let graph = null;

  const esc = value => String(value ?? '').replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));
  const key = () => window.crypto?.randomUUID ? `ui-${window.crypto.randomUUID()}` : `ui-${Date.now()}-${Math.random().toString(16).slice(2)}`;

  function message(text, error = false) {
    const el = $('graph-message'); el.style.display = text ? 'block' : 'none'; el.textContent = text || '';
    el.style.borderColor = error ? 'rgba(239,68,68,.45)' : 'rgba(99,102,241,.35)'; el.style.color = error ? 'var(--danger)' : 'var(--text)';
  }

  async function request(path, options = {}) {
    const response = await fetch(`${API}/api/v1${path}`, { credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  }

  function layoutNodes(nodes, edges) {
    const incoming = new Map(nodes.map(n => [n.id, 0]));
    edges.forEach(e => incoming.set(e.to_node_id, (incoming.get(e.to_node_id) || 0) + 1));
    const levels = [], remaining = new Set(nodes.map(n => n.id));
    while (remaining.size) {
      const level = nodes.filter(n => remaining.has(n.id) && (incoming.get(n.id) || 0) === 0);
      if (!level.length) { levels.push(nodes.filter(n => remaining.has(n.id))); break; }
      levels.push(level); level.forEach(n => remaining.delete(n.id));
      edges.forEach(e => { if (level.some(n => n.id === e.from_node_id)) incoming.set(e.to_node_id, Math.max(0, (incoming.get(e.to_node_id) || 0) - 1)); });
    }
    return levels;
  }

  function renderGraph(data) {
    graph = data;
    const canvas = $('graph-canvas'); canvas.innerHTML = '';
    const levels = layoutNodes(data.nodes || [], data.edges || []);
    const positions = new Map(); levels.forEach((level, x) => level.forEach((node, y) => positions.set(node.id, { x: 80 + x * 260, y: 50 + y * 105 })));
    const width = Math.max(900, levels.length * 260 + 120), height = Math.max(430, Math.max(...levels.map(l => l.length), 1) * 105 + 90), ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg'); svg.setAttribute('width', width); svg.setAttribute('height', height); svg.setAttribute('viewBox', `0 0 ${width} ${height}`); svg.style.display = 'block';
    const defs = document.createElementNS(ns, 'defs'), marker = document.createElementNS(ns, 'marker'); marker.setAttribute('id','arrow'); marker.setAttribute('markerWidth','8'); marker.setAttribute('markerHeight','8'); marker.setAttribute('refX','7'); marker.setAttribute('refY','4'); marker.setAttribute('orient','auto'); const path=document.createElementNS(ns,'path'); path.setAttribute('d','M0,0 L8,4 L0,8 z'); path.setAttribute('fill','rgba(148,163,184,.65)'); marker.appendChild(path); defs.appendChild(marker); svg.appendChild(defs);
    (data.edges || []).forEach(edge => { const a=positions.get(edge.from_node_id), b=positions.get(edge.to_node_id); if(!a||!b)return; const line=document.createElementNS(ns,'line'); line.setAttribute('x1',a.x+170);line.setAttribute('y1',a.y+28);line.setAttribute('x2',b.x);line.setAttribute('y2',b.y+28);line.setAttribute('stroke','rgba(148,163,184,.45)');line.setAttribute('stroke-width','2');line.setAttribute('marker-end','url(#arrow)');svg.appendChild(line); });
    (data.nodes || []).forEach(node => { const p=positions.get(node.id); const g=document.createElementNS(ns,'g'), rect=document.createElementNS(ns,'rect'); rect.setAttribute('x',p.x);rect.setAttribute('y',p.y);rect.setAttribute('width','170');rect.setAttribute('height','56');rect.setAttribute('rx','9');rect.setAttribute('fill','rgba(13,18,30,.92)');rect.setAttribute('stroke',node.status==='FAILED'?'rgba(239,68,68,.75)':node.status==='SUCCEEDED'?'rgba(16,185,129,.7)':node.status==='RUNNING'?'rgba(99,102,241,.8)':'rgba(255,255,255,.12)');rect.setAttribute('stroke-width','1.5');g.appendChild(rect);const title=document.createElementNS(ns,'text');title.setAttribute('x',p.x+10);title.setAttribute('y',p.y+22);title.setAttribute('fill','#fff');title.setAttribute('font-size','12');title.setAttribute('font-family','Outfit');title.textContent=String(node.label||node.logical_key||node.node_type).slice(0,24);g.appendChild(title);const status=document.createElementNS(ns,'text');status.setAttribute('x',p.x+10);status.setAttribute('y',p.y+42);status.setAttribute('fill','#94a3b8');status.setAttribute('font-size','10');status.setAttribute('font-family','JetBrains Mono');status.textContent=`${node.node_type} · ${node.status}`;g.appendChild(status);svg.appendChild(g); });
    canvas.appendChild(svg);
    $('graph-meta').textContent = `${(data.nodes||[]).length} nodes · ${(data.edges||[]).length} dependencies · ${(data.attempts||[]).length} attempts`;
    renderTimeline(data.timeline || []);
    const terminal = (data.nodes || []).length > 0 && (data.nodes || []).every(n => ['SUCCEEDED','SKIPPED'].includes(n.status)); $('execution-state').textContent = terminal ? 'Complete' : 'Active / Resumable';
    $('resume-execution').disabled = !(data.resumableNodeIds || []).length && !((data.nodes||[]).some(n => !['SUCCEEDED','SKIPPED'].includes(n.status)));
  }

  function renderTimeline(items) {
    const root=$('timeline'); root.innerHTML=''; if(!items.length){root.innerHTML='<div style="color:var(--text-muted);padding:1rem;">No execution attempts recorded.</div>';return;}
    items.slice().reverse().forEach(item=>{const row=document.createElement('div');row.style.cssText='display:grid;grid-template-columns:150px 1fr auto;gap:1rem;align-items:center;padding:.75rem;border:1px solid rgba(255,255,255,.07);border-radius:8px;background:rgba(255,255,255,.02);';row.innerHTML=`<code style="color:var(--text-muted);font-size:.72rem;">${esc(new Date(item.startedAt).toLocaleString())}</code><div><strong>${esc(item.nodeId)}</strong><div style="font-size:.72rem;color:var(--text-muted);">Attempt ${esc(item.attemptNumber)}${item.errorCode ? ` · ${esc(item.errorCode)}` : ''}</div></div><span style="font-family:var(--font-mono);font-size:.72rem;">${esc(item.status)}</span>`;root.appendChild(row);});
  }

  function ensureOutcomePanels() {
    if (!$('domain-results')) { const section=document.createElement('section'); section.id='domain-results'; section.className='card'; section.style.cssText='padding:1rem;margin-top:1rem;display:grid;grid-template-columns:1fr 1fr;gap:1rem;'; section.innerHTML='<div><h3 style="margin-top:0;">Evidence</h3><div id="evidence-results" style="display:grid;gap:.5rem;"></div></div><div><h3 style="margin-top:0;">Decision</h3><div id="decision-results" style="display:grid;gap:.5rem;"></div></div>'; document.querySelector('.page-content').appendChild(section); }
  }

  function renderEvidence(data) { ensureOutcomePanels(); const root=$('evidence-results'); const rows=data.evidence||[]; root.innerHTML=rows.length?rows.slice(0,20).map(r=>`<div style="padding:.65rem;border:1px solid rgba(255,255,255,.07);border-radius:8px;"><strong>${esc(r.control_id||'Evidence')}</strong><div style="font-size:.7rem;color:var(--text-muted);">${esc(r.provider)} · ${esc(r.resource_id||'scope')} · ${esc(r.source_type)} · ${esc(r.evidence_hash)}</div></div>`).join(''):'<div style="color:var(--text-muted);">No durable evidence yet.</div>'; }
  function renderDecision(data) { ensureOutcomePanels(); const root=$('decision-results'); const final=data.final; const controls=data.controls||[]; root.innerHTML=(final?`<div style="padding:.8rem;border:1px solid rgba(99,102,241,.35);border-radius:8px;"><strong>Final: ${esc(final.outcome)}</strong><div style="font-size:.7rem;color:var(--text-muted);">Hash ${esc(final.decision_hash)}</div></div>`:'<div style="color:var(--text-muted);">Final decision not available.</div>')+controls.slice(0,20).map(r=>`<div style="padding:.6rem;border:1px solid rgba(255,255,255,.07);border-radius:8px;"><strong>${esc(r.control_id)}</strong> · ${esc(r.outcome)}<div style="font-size:.7rem;color:var(--text-muted);">${esc(r.scope_key)}</div></div>`).join(''); }

  async function load() {
    const id=$('execution-id').value.trim(); if(!id){message('Enter an execution ID to inspect.');return;}
    try { const data=await request(`/executions/${encodeURIComponent(id)}`); message(''); renderGraph(data.graph ? {...data.graph, execution:data.execution, events:data.events} : data); renderEvidence(await request(`/executions/${encodeURIComponent(id)}/evidence`)); renderDecision(await request(`/executions/${encodeURIComponent(id)}/decisions`)); $('live-indicator').textContent='● Live durable state'; }
    catch(error){message(error.message,true);$('live-indicator').textContent='Live refresh unavailable';}
  }

  async function control(action) {
    const id=$('execution-id').value.trim(); if(!id)return; $('resume-execution').disabled=true;
    try { const body=await request(`/executions/${encodeURIComponent(id)}/actions`,{method:'POST',headers:{'Idempotency-Key':key()},body:JSON.stringify({action})}); message(`${action} accepted${body.jobId?`: ${body.jobId}`:''}`); await load(); }
    catch(error){message(error.message,true);} finally{$('resume-execution').disabled=false;}
  }

  function connectStream() {
    const id=$('execution-id').value.trim(); if(!id)return; source?.close(); source=new EventSource(`${API}/api/v1/executions/${encodeURIComponent(id)}/stream`,{withCredentials:true});
    source.addEventListener('ready',()=>{$('live-indicator').textContent='● Live stream connected';});
    source.addEventListener('execution',event=>{try{const state=JSON.parse(event.data);renderGraph(state);$('live-indicator').textContent='● Live stream connected';}catch{}});
    source.addEventListener('error',()=>{$('live-indicator').textContent='Stream reconnecting…';source?.close();});
  }

  $('refresh-graph').addEventListener('click',load); $('resume-execution').addEventListener('click',()=>control('resume')); $('execution-id').addEventListener('change',()=>{load();connectStream();});
  const params=new URLSearchParams(location.search); if(params.get('executionId'))$('execution-id').value=params.get('executionId');
  if($('execution-id').value.trim()){load();connectStream();} timer=setInterval(load,10000); window.addEventListener('beforeunload',()=>{clearInterval(timer);source?.close();});
})();
