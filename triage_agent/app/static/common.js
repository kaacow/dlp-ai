// Shared across index.html (All Events) and employees.html (By Employee).

const FIRST_DIR = { event_time: 'desc', severity: 'desc', app_desc: 'asc', file_name: 'asc' };
let jobPollTimer = null;
let currentJobId = null;
window.empHost = '';

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (res.status === 401) {
    // session expired/missing mid-use (e.g. a long-running polling call) — bounce
    // to login rather than leaving the page silently broken
    window.location.href = '/login.html?next=' + encodeURIComponent(location.pathname);
    throw new Error('not authenticated');
  }
  if (!res.ok && res.status !== 409) throw new Error(await res.text());
  return res.json();
}

function fmtVerdictLabel(v) { return (v || '').replace(/_/g, ' '); }
function pill(cls, label) { return `<span class="pill ${cls}">${fmtVerdictLabel(label)}</span>`; }
function escapeHtml(s) {
  return (s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// local datetime <-> 'YYYY-MM-DD HH:MM:SS' the API expects. Server and browser are
// assumed to share a timezone (single-office internal tool) — no UTC conversion.
function toApiDt(inputEl) {
  if (!inputEl.value) return '';
  return inputEl.value.replace('T', ' ') + ':00';
}
function setInputToDate(inputEl, date, endOfDay) {
  const pad = n => String(n).padStart(2, '0');
  const d = `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())}`;
  inputEl.value = `${d}T${endOfDay ? '23:59' : '00:00'}`;
}
function yesterday() {
  const d = new Date();
  d.setDate(d.getDate() - 1);
  return d;
}

function sortArrow(col, sortState) {
  if (sortState.orderBy !== col) return '';
  return sortState.orderDir === 'asc' ? '▲' : '▼';
}
function renderSortArrows(scope, sortState) {
  document.querySelectorAll('th.sortable').forEach(th => {
    const thScope = th.dataset.scope || null;
    if (thScope !== scope) return;
    th.querySelector('.arrow').textContent = sortArrow(th.dataset.col, sortState);
  });
}
function handleSortClick(th, state, reload) {
  const col = th.dataset.col;
  if (state.orderBy !== col) {
    state.orderBy = col; state.orderDir = FIRST_DIR[col];
  } else if (state.orderDir === FIRST_DIR[col]) {
    state.orderDir = FIRST_DIR[col] === 'asc' ? 'desc' : 'asc';
  } else {
    state.orderBy = 'event_time'; state.orderDir = 'desc';
  }
  reload();
}
function wireSortableHeaders(scope, state, reload) {
  document.querySelectorAll(`th.sortable[data-scope="${scope || ''}"]`).forEach(th => {
    if ((th.dataset.scope || null) !== scope) return;
    th.addEventListener('click', () => handleSortClick(th, state, reload));
  });
}

// ---------------- detail panel ----------------

function evidenceHtmlFor(e) {
  let html = '';
  const ev = e.screenshots_used || {};
  if (ev.chat_messages) {
    html += `<div class="block"><h3>Chat messages (${ev.chat_messages.length})</h3>` +
      ev.chat_messages.map(m => `<div class="evidence-item"><span class="t">${m.time} · ${m.direction} · ${escapeHtml(m.contact||'')}</span><br>${escapeHtml(m.text||'')}</div>`).join('') + `</div>`;
  }
  if (ev.window_activity) {
    html += `<div class="block"><h3>Window activity (${ev.window_activity.length})</h3>` +
      ev.window_activity.map(w => `<div class="evidence-item"><span class="t">${w.time}</span><br>${escapeHtml(w.window_title||'')}${w.visible_text ? '<br><span style="color:var(--muted)">' + escapeHtml(w.visible_text.slice(0,200)) + '</span>' : ''}</div>`).join('') + `</div>`;
  }
  if (ev.screenshot_descriptions) {
    html += `<div class="block"><h3>Screenshots analyzed (${ev.screenshot_descriptions.length})</h3>` +
      ev.screenshot_descriptions.map(s => `<div class="evidence-item">
        <span class="t">${s.time}${s.window_title ? ' · ' + escapeHtml(s.window_title) : ''}</span>
        ${s.image_file ? `<img class="shot-thumb" src="/api/screenshots/${s.image_file}" onclick="openLightbox('/api/screenshots/${s.image_file}')">` : ''}
        <div style="margin-top:6px;">${escapeHtml(s.description||'')}</div>
      </div>`).join('') + `</div>`;
  }
  if (e.extra_queries && e.extra_queries.length) {
    html += `<div class="block"><h3>AI's own follow-up queries (${e.extra_queries.length})</h3>` +
      e.extra_queries.map(q => `<div class="query-item">${escapeHtml(q.sql)}\n→ ${q.row_count} row(s)</div>`).join('') + `</div>`;
  }
  if (!html) html = `<div class="block"><p style="color:var(--muted)">No evidence recorded — this event may not have reached Track C investigation.</p></div>`;
  return html;
}

function detailHtmlFor(e) {
  const empLine = e.employee
    ? `#${e.user_locator} · ${escapeHtml(e.employee.user_name || '')} · ${escapeHtml(e.employee.full_name || '')}${e.employee.department ? ' · ' + escapeHtml(e.employee.department) : ''}${e.employee.comp_name ? ' · device ' + escapeHtml(e.employee.comp_name) : ''}`
    : `#${e.user_locator} (no directory record on file)`;
  return `
    <button class="close" onclick="closeDetail()">&times;</button>
    <h2>${escapeHtml(e.file_name || '(no filename)')}</h2>
    <div class="meta">${e.event_time} · ${empLine}<br>${escapeHtml(e.app_desc||'')}</div>
    <div class="block">
      <h3>Verdict</h3>
      <p>${pill(e.verdict, e.verdict)} ${e.severity ? `<span class="pill ${e.verdict}">${e.severity}</span>` : ''}</p>
      <p style="margin-top:10px;">${escapeHtml(e.reasoning || '')}</p>
    </div>
    <div class="block">
      <h3>Track B trigger</h3>
      <p style="font-family:var(--mono); font-size:13px;">${escapeHtml(e.matched_rule || '—')} → ${escapeHtml(e.destination_category || '')}</p>
    </div>
    ${evidenceHtmlFor(e)}
    ${e.model_version ? `<div class="block"><h3>Model</h3><p style="font-family:var(--mono); font-size:13px;">${escapeHtml(e.model_version)}</p></div>` : ''}
  `;
}

async function openDetail(id) {
  const e = await api('/api/events/' + id);
  document.getElementById('detail').innerHTML = detailHtmlFor(e);
  document.getElementById('overlay').classList.add('open');
  document.getElementById('detail').classList.add('open');
}
function closeDetail() {
  document.getElementById('overlay').classList.remove('open');
  document.getElementById('detail').classList.remove('open');
}
function openLightbox(src) {
  document.getElementById('lightboxImg').src = src;
  document.getElementById('lightbox').classList.add('open');
}

// ---------------- on-demand "Analyze event" + progress modal, with a REAL stop ----------------
// "Close"/hiding the modal does NOT stop the backend job — only the Stop button
// does (calls /api/jobs/{id}/cancel, which actually aborts the in-flight Ollama
// call so GPU usage drops immediately, not just our interest in the result).
// These are kept as two distinctly-labeled actions on purpose, since the whole
// point of this feature is that "did it actually stop" should never be ambiguous.

async function analyzeEvent(rowAutoIncrement, userLocator, onDone) {
  currentJobId = null;
  document.getElementById('progressMeta').textContent = `row #${rowAutoIncrement} · employee #${userLocator}`;
  document.getElementById('progressStatusLine').textContent = '';
  document.getElementById('progressStatusLine').className = 'status-line';
  document.getElementById('progressSteps').innerHTML = `<div class="step latest">Starting…</div>`;
  document.getElementById('stopBtn').style.display = '';
  document.getElementById('stopBtn').disabled = false;
  document.getElementById('stopBtn').textContent = 'Stop analysis';
  document.getElementById('progressOverlay').classList.add('open');

  const { job_id } = await api('/api/events/analyze', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ row_auto_increment: rowAutoIncrement, user_locator: userLocator }),
  });
  currentJobId = job_id;
  pollJob(job_id, onDone);
}

function pollJob(jobId, onDone) {
  if (jobPollTimer) clearInterval(jobPollTimer);
  jobPollTimer = setInterval(async () => {
    const job = await api('/api/jobs/' + jobId);
    const stepsEl = document.getElementById('progressSteps');
    stepsEl.innerHTML = job.steps.map((s, i) =>
      `<div class="step${i === job.steps.length - 1 ? ' latest' : ''}">[${s.time}] ${escapeHtml(s.step)}</div>`
    ).join('') || '<div class="step">Working…</div>';
    stepsEl.scrollTop = stepsEl.scrollHeight;

    if (job.status === 'done') {
      clearInterval(jobPollTimer); jobPollTimer = null; currentJobId = null;
      const statusLine = document.getElementById('progressStatusLine');
      statusLine.textContent = 'Done.'; statusLine.className = 'status-line done';
      document.getElementById('stopBtn').style.display = 'none';
      if (job.event_verdict_id && onDone) onDone(job.event_verdict_id);
    } else if (job.status === 'failed') {
      clearInterval(jobPollTimer); jobPollTimer = null; currentJobId = null;
      stepsEl.innerHTML += `<div class="step" style="color:var(--bad);">Failed: ${escapeHtml((job.error||'').slice(0,300))}</div>`;
      document.getElementById('stopBtn').style.display = 'none';
    } else if (job.status === 'cancelled') {
      clearInterval(jobPollTimer); jobPollTimer = null; currentJobId = null;
      const statusLine = document.getElementById('progressStatusLine');
      statusLine.textContent = 'Stopped — GPU work has been aborted.'; statusLine.className = 'status-line cancelled';
      document.getElementById('stopBtn').style.display = 'none';
    }
  }, 1500);
}

async function stopAnalysis() {
  if (!currentJobId) return;
  const btn = document.getElementById('stopBtn');
  btn.disabled = true;
  btn.textContent = 'Stopping…';
  await api(`/api/jobs/${currentJobId}/cancel`, { method: 'POST' });
  // leave polling running — it will pick up status:'cancelled' within ~1.5s and
  // update the modal itself, so the user sees confirmation, not just a closed dialog
}

document.addEventListener('DOMContentLoaded', () => {
  const lightbox = document.getElementById('lightbox');
  if (lightbox) lightbox.onclick = () => lightbox.classList.remove('open');
  const overlay = document.getElementById('overlay');
  if (overlay) overlay.onclick = closeDetail;
  const stopBtn = document.getElementById('stopBtn');
  if (stopBtn) stopBtn.onclick = stopAnalysis;
  const hideBtn = document.getElementById('progressHideBtn');
  if (hideBtn) hideBtn.onclick = () => document.getElementById('progressOverlay').classList.remove('open');
  const labelCancelBtn = document.getElementById('labelCancelBtn');
  if (labelCancelBtn) labelCancelBtn.onclick = closeLabelModal;
  const labelSubmitBtn = document.getElementById('labelSubmitBtn');
  if (labelSubmitBtn) labelSubmitBtn.onclick = submitLabel;
  const labelOverlay = document.getElementById('labelOverlay');
  if (labelOverlay) labelOverlay.addEventListener('click', e => { if (e.target === labelOverlay) closeLabelModal(); });
});

async function loadEmpHost() {
  const cfg = await api('/api/config');
  window.empHost = cfg.emp_host;
}

// ---------------- auth: account widget + redirect-to-login ----------------
// Call requireAuth() first thing in every app page's init(). It populates
// window.currentUser and window.isAdmin, and redirects to setup/login before any
// other API call fires if there's no valid session — so a logged-out visitor never
// sees a page full of failed-request errors first.

window.currentUser = null;
window.isAdmin = false;

async function requireAuth() {
  const statusRes = await fetch('/api/auth/status');
  const status = await statusRes.json();
  if (status.setup_required) { window.location.href = '/setup.html'; return false; }

  const meRes = await fetch('/api/auth/me');
  if (!meRes.ok) {
    window.location.href = '/login.html?next=' + encodeURIComponent(location.pathname);
    return false;
  }
  window.currentUser = await meRes.json();
  window.isAdmin = window.currentUser.role === 'admin';
  renderAccountWidget();
  document.querySelectorAll('.admin-only').forEach(el => { el.style.display = window.isAdmin ? '' : 'none'; });
  return true;
}

function renderAccountWidget() {
  const el = document.getElementById('accountWidget');
  if (!el || !window.currentUser) return;
  const me = window.currentUser;
  const avatarHtml = me.profile_picture
    ? `<img class="avatar-img" src="/api/profile-pictures/${me.profile_picture}" alt="">`
    : `<span class="avatar-fallback">${escapeHtml((me.username[0] || '?').toUpperCase())}</span>`;
  el.innerHTML = `
    <label class="avatar-upload" title="Click to change your profile picture">
      ${avatarHtml}
      <input type="file" id="avatarInput" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none;">
    </label>
    <span class="account-name">${escapeHtml(me.username)}</span>
    ${me.role === 'admin' ? '<span class="pill" style="background:var(--accent-soft); color:var(--accent);">admin</span>' : ''}
    ${me.role === 'admin' ? '<a href="/users.html" class="small-btn">Users</a>' : ''}
    <button class="small-btn" id="logoutBtn">Log out</button>
  `;
  document.getElementById('logoutBtn').onclick = async () => {
    await api('/api/auth/logout', { method: 'POST' });
    window.location.href = '/login.html';
  };
  document.getElementById('avatarInput').onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch('/api/me/profile-picture', { method: 'POST', body: fd });
    if (!res.ok) { alert('Upload failed: ' + (await res.text())); return; }
    const data = await res.json();
    window.currentUser.profile_picture = data.profile_picture;
    renderAccountWidget();
  };
}

// ---------------- "Feed to AI" (admin-only) ----------------
// Stores a labeled example — see agent.py's find_similar_precedent() for how this
// actually gets used (few-shot precedent in future investigations' prompts, not
// model fine-tuning).

let labelEventId = null;

function openLabelModal(eventId, fileName, destApp) {
  labelEventId = eventId;
  document.getElementById('labelMeta').textContent = `${fileName} → ${destApp}`;
  document.getElementById('labelNotes').value = '';
  document.getElementById('labelVerdict').value = 'cleared';
  document.getElementById('labelOverlay').classList.add('open');
}
function closeLabelModal() {
  document.getElementById('labelOverlay').classList.remove('open');
}
async function submitLabel() {
  const notes = document.getElementById('labelNotes').value.trim();
  if (!notes) { alert("Write a short reason — that's the part the model actually reads."); return; }
  const btn = document.getElementById('labelSubmitBtn');
  btn.disabled = true;
  try {
    await api('/api/labels', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event_verdict_id: labelEventId,
        label_verdict: document.getElementById('labelVerdict').value,
        label_notes: notes,
      }),
    });
    closeLabelModal();
  } catch (ex) {
    alert('Failed to save: ' + ex.message);
  } finally {
    btn.disabled = false;
  }
}
