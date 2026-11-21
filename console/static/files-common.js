// File Analyzer-specific rendering — kept separate from the generic shared
// common.js (fmtBytes/fmtDate/scoreClass/escapeHtml/categoryLabel live there).

function renderResultCard(scan, opts = {}) {
  const showDelete = !!opts.showDelete;
  if (scan.error) {
    return `<div class="result-card">
      <div class="result-head">
        <div>
          <div class="fname">${escapeHtml(scan.filename)}</div>
          <div class="meta">${fmtBytes(scan.file_size)} · ${fmtDate(scan.created_at)}</div>
        </div>
      </div>
      <div class="result-error">Analysis failed: ${escapeHtml(scan.error)}</div>
    </div>`;
  }
  if (scan.risk_score == null) {
    return `<div class="result-card">
      <div class="result-head">
        <div>
          <div class="fname">${escapeHtml(scan.filename)}</div>
          <div class="meta">${fmtBytes(scan.file_size)} · analyzing…</div>
        </div>
      </div>
    </div>`;
  }
  const cats = (scan.categories || []).map(c => `<span class="pill cat">${escapeHtml(categoryLabel(c))}</span>`).join('');
  const entities = (scan.related_entities || []).length
    ? `<div class="label">Related entities</div><div class="entities">${scan.related_entities.map(e => `<span>${escapeHtml(e)}</span>`).join(', ')}</div>`
    : '';
  const preview = scan.extracted_text
    ? `<details class="text-preview"><summary>View extracted content${scan.truncated ? ' (truncated)' : ''}</summary><pre>${escapeHtml(scan.extracted_text)}</pre></details>`
    : '';
  const instructions = scan.analyst_instructions
    ? `<div class="label">Instructions given for this scan</div><div>${escapeHtml(scan.analyst_instructions)}</div>`
    : '';
  const companyRelevance = scan.company_relevance_reasoning
    ? `<div class="label">Company relevance</div><div>${escapeHtml(scan.company_relevance_reasoning)}${(scan.company_keywords_found || []).length ? ` <span style="color:var(--muted);">(matched: ${scan.company_keywords_found.map(escapeHtml).join(', ')})</span>` : ''}</div>`
    : '';
  const deleteBtn = showDelete
    ? `<div class="result-actions"><button class="btn secondary" data-delete-scan="${scan.id}">Delete from history</button></div>`
    : '';
  const chatSection = `<div class="chat-section">
    <div class="label">Ask about this file</div>
    <div class="chat-messages" id="chat-msgs-${scan.id}"></div>
    <div class="chat-input-row">
      <input type="text" class="chat-input" id="chat-input-${scan.id}" placeholder="e.g. what SSNs are in this file?">
      <button class="btn secondary" data-chat-send="${scan.id}">Ask</button>
    </div>
  </div>`;
  return `<div class="result-card" data-scan-id="${scan.id}">
    <div class="result-head">
      <div class="score-badge ${scoreClass(scan.risk_score)}">${scan.risk_score}</div>
      <div>
        <div class="fname">${escapeHtml(scan.filename)}</div>
        <div class="meta">${fmtBytes(scan.file_size)} · ${fmtDate(scan.created_at)}${scan.used_vision ? ' · vision-assisted' : ''}${(scan.segment_count || 0) > 1 ? ` · analyzed in ${scan.segment_count} segments (${escapeHtml(scan.analysis_depth || 'thorough')})` : ''}</div>
        <div style="margin-top:8px;">
          <span class="pill action-${scan.recommended_action}">${escapeHtml(scan.recommended_action)}</span>
          ${scan.is_confidential ? '<span class="pill">confidential</span>' : ''}
          ${scan.related_to_company ? '<span class="pill company">related to company</span>' : ''}
          ${cats}
        </div>
      </div>
    </div>
    <div class="result-body">
      <div class="label">Summary</div>
      <div>${escapeHtml(scan.summary)}</div>
      <div class="label">Reasoning</div>
      <div>${escapeHtml(scan.reasoning)}</div>
      ${entities}
      ${companyRelevance}
      ${instructions}
      ${preview}
    </div>
    ${deleteBtn}
    ${chatSection}
  </div>`;
}

function renderChatMsg(m) {
  const who = m.role === 'user' ? 'You' : 'Assistant';
  return `<div class="chat-msg ${escapeHtml(m.role)}"><span class="who">${who}</span>${escapeHtml(m.content)}</div>`;
}

async function initChatUI(scanId) {
  const msgsEl = document.getElementById(`chat-msgs-${scanId}`);
  const inputEl = document.getElementById(`chat-input-${scanId}`);
  const sendBtn = document.querySelector(`[data-chat-send="${scanId}"]`);
  if (!msgsEl || !inputEl || !sendBtn) return;

  async function loadHistory() {
    try {
      const res = await api(`/api/files/history/${scanId}/chat`);
      const data = await res.json();
      msgsEl.innerHTML = data.messages.map(renderChatMsg).join('');
      msgsEl.scrollTop = msgsEl.scrollHeight;
    } catch (e) { /* best-effort */ }
  }

  async function send() {
    const q = inputEl.value.trim();
    if (!q) return;
    inputEl.value = '';
    sendBtn.disabled = true;
    msgsEl.insertAdjacentHTML('beforeend', renderChatMsg({ role: 'user', content: q }));
    const thinkingId = `chat-thinking-${scanId}-${Date.now()}`;
    msgsEl.insertAdjacentHTML('beforeend', `<div class="chat-msg assistant" id="${thinkingId}"><span class="who">Assistant</span><em>thinking…</em></div>`);
    msgsEl.scrollTop = msgsEl.scrollHeight;
    try {
      const res = await api(`/api/files/history/${scanId}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Chat failed');
      const el = document.getElementById(thinkingId);
      if (el) el.outerHTML = renderChatMsg({ role: 'assistant', content: data.answer });
    } catch (e) {
      const el = document.getElementById(thinkingId);
      if (el) el.outerHTML = `<div class="chat-msg assistant error">${escapeHtml(e.message)}</div>`;
    } finally {
      sendBtn.disabled = false;
      msgsEl.scrollTop = msgsEl.scrollHeight;
    }
  }

  sendBtn.onclick = send;
  inputEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });

  loadHistory();
}
