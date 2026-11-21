// Mail Exfil rendering shared between mail.html (schedule-filtered default view)
// and history.html (full unrestricted browse view) — kept here once so both stay
// in sync rather than duplicating ~150 lines of table-rendering logic.

const MATCH_TYPE_LABEL = { personal_domain_match: 'personal address', self_corporate: 'self (corporate)' };
const DLP_STATUS_LABEL = { unchecked: 'not checked', found: 'DLP copy found', found_no_file: 'DLP logged, no file', phone_sent: 'phone sent' };

function exScoreClass(score) {
  if (score == null) return '';
  if (score >= 0.85) return 'high';
  if (score >= 0.65) return 'medium';
  return 'low';
}

function corpTableRows(events) {
  return events.map(e => `<tr>
    <td>${escapeHtml(e.event_time || '')}</td>
    <td>${escapeHtml(e.sender_fullname || e.sender_username || '')}</td>
    <td><span class="pill">${escapeHtml(MATCH_TYPE_LABEL[e.match_type] || e.match_type || '')}</span></td>
    <td>${e.similarity_score != null ? `<span class="score-badge mscore-${exScoreClass(e.similarity_score)}" style="width:38px;height:38px;font-size:12px;">${Number(e.similarity_score).toFixed(2)}</span>` : ''}</td>
    <td class="name-cell" title="${escapeHtml(e.recipient_email||'')}">${escapeHtml(e.recipient_email||'')}</td>
    <td class="name-cell" title="${escapeHtml(e.subject||'')}">${escapeHtml(e.subject||'(no subject)')}</td>
    <td>${escapeHtml(e.ai_summary || '')}${e.error ? `<span style="color:var(--bad)">${escapeHtml(e.error)}</span>` : ''}</td>
    <td>${e.msg_href ? `<a class="btn secondary small" href="/api/mail/events/${e.id}/download">Download</a>` : '<span style="color:var(--muted)">no copy</span>'}</td>
  </tr>`).join('');
}

function renderCorpTable(wrapEl, data) {
  if (!data.events.length) {
    wrapEl.innerHTML = `<div class="empty-state">No flagged mail in this range.</div>`;
    return;
  }
  wrapEl.innerHTML = `<table class="data-table"><thead><tr>
    <th class="sortable" data-sort="time">Time</th><th class="sortable" data-sort="sender">Sender</th>
    <th class="sortable" data-sort="match">Match</th><th class="sortable" data-sort="score">Score</th>
    <th class="sortable" data-sort="recipient">Recipient</th><th class="sortable" data-sort="subject">Subject</th>
    <th class="sortable" data-sort="summary">AI Summary</th><th>File</th>
  </tr></thead><tbody>${corpTableRows(data.events)}</tbody></table>`;
}

function exActionsHtml(e) {
  const label = e.dlp_status === 'found' ? 'Found' : e.dlp_status === 'phone_sent' ? 'Not found' : e.dlp_status === 'found_no_file' ? 'Found, no file' : 'Find in DLP';
  const checkBtn = `<button class="btn secondary small dlp-check-btn" data-id="${e.id}">${escapeHtml(label)}</button>`;
  if (e.dlp_status === 'found') {
    return checkBtn + ` <button class="btn secondary small analyze-btn" data-id="${e.id}">${e.ai_summary ? 'Re-analyze' : 'Analyze'}</button>` +
      ` <a class="btn secondary small" href="/api/exchange/events/${e.id}/download">Download</a>`;
  }
  return checkBtn;
}

function exchangeTableRows(events) {
  return events.map(e => `<tr data-id="${e.id}">
    <td>${escapeHtml(e.event_time || '')}</td>
    <td>${escapeHtml(e.sender_fullname || e.sender_address || '')}</td>
    <td class="name-cell" title="${escapeHtml(e.recipient_address||'')}">${escapeHtml(e.recipient_address||'')}</td>
    <td class="name-cell" title="${escapeHtml(e.subject||'')}">${escapeHtml(e.subject||'(no subject)')}</td>
    <td>${e.similarity_score != null ? `<span class="score-badge mscore-${exScoreClass(e.similarity_score)}" style="width:38px;height:38px;font-size:12px;">${Number(e.similarity_score).toFixed(2)}</span>` : ''}</td>
    <td class="dlp-status-cell"><span class="pill">${escapeHtml(DLP_STATUS_LABEL[e.dlp_status] || e.dlp_status || '')}</span></td>
    <td class="summary-cell">${escapeHtml(e.ai_summary || '')}</td>
    <td class="actions-cell">${exActionsHtml(e)}</td>
  </tr>`).join('');
}

function renderExchangeTable(wrapEl, data) {
  if (!data.events.length) {
    wrapEl.innerHTML = `<div class="empty-state">No flagged mail in this range.</div>`;
    return;
  }
  wrapEl.innerHTML = `<table class="data-table"><thead><tr>
    <th class="sortable" data-sort="time">Time</th><th class="sortable" data-sort="sender">Sender</th>
    <th class="sortable" data-sort="recipient">Recipient</th><th class="sortable" data-sort="subject">Subject</th>
    <th class="sortable" data-sort="score">Score</th><th class="sortable" data-sort="status">DLP Status</th>
    <th class="sortable" data-sort="summary">AI Summary</th><th>Actions</th>
  </tr></thead><tbody>${exchangeTableRows(data.events)}</tbody></table>`;
  wireExchangeActions(wrapEl);
}

function wireExchangeActions(scopeEl) {
  scopeEl.querySelectorAll('.analyze-btn').forEach(btn => {
    btn.onclick = async () => {
      const id = btn.dataset.id;
      const summaryCell = btn.closest('tr').querySelector('.summary-cell');
      btn.disabled = true; btn.textContent = 'Analyzing…';
      try {
        const res = await fetch(`/api/exchange/events/${id}/analyze`, { method: 'POST' });
        const data = await res.json();
        summaryCell.innerHTML = res.ok ? escapeHtml(data.ai_summary) : `<span style="color:var(--bad)">${escapeHtml(data.detail || 'analysis failed')}</span>`;
      } catch (err) {
        summaryCell.innerHTML = `<span style="color:var(--bad)">${escapeHtml(err.message)}</span>`;
      }
      btn.disabled = false; btn.textContent = 'Re-analyze';
    };
  });
  scopeEl.querySelectorAll('.dlp-check-btn').forEach(btn => {
    btn.onclick = async () => {
      const id = btn.dataset.id;
      const row = btn.closest('tr');
      btn.disabled = true; btn.textContent = 'Checking…';
      try {
        const res = await fetch(`/api/exchange/events/${id}/find_in_dlp`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) { btn.disabled = false; btn.textContent = 'Find in DLP'; alert(data.detail || 'DLP lookup failed'); return; }
        row.querySelector('.dlp-status-cell').innerHTML = `<span class="pill">${escapeHtml(DLP_STATUS_LABEL[data.dlp_status] || data.dlp_status)}</span>`;
        row.querySelector('.actions-cell').innerHTML = exActionsHtml({ id, dlp_status: data.dlp_status, ai_summary: row.querySelector('.summary-cell').textContent.trim() });
        wireExchangeActions(scopeEl);
      } catch (err) {
        btn.disabled = false; btn.textContent = 'Find in DLP'; alert(err.message);
      }
    };
  });
}

// Generic click-to-sort wiring for a table's `th.sortable` headers, scoped to
// a container element so multiple independently-sorted tables can coexist.
function wireTableSort(scopeEl, state, reload) {
  scopeEl.querySelectorAll('th.sortable').forEach(th => {
    th.onclick = () => {
      const key = th.dataset.sort;
      if (state.sort === key) state.dir = state.dir === 'asc' ? 'desc' : 'asc';
      else { state.sort = key; state.dir = 'desc'; }
      state.offset = 0;
      reload();
    };
  });
}
