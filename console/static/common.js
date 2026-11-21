// ---------- Generic helpers ----------
function fmtBytes(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(1) + ' MB';
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso.includes('Z') || iso.includes('+') ? iso : iso.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

function scoreClass(score) {
  if (score >= 75) return 'score-high';
  if (score >= 40) return 'score-mid';
  return 'score-low';
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function categoryLabel(cat) {
  return String(cat ?? '').replace(/_/g, ' ');
}

// ---------- Scheduled-scan date-range helpers ----------
// Both scanners run on a lag rather than same-day, and neither runs on
// weekends — so each Monday (and, for the secrets scanner, Tuesday too) has to
// catch up the days that piled up since the last run before the weekend gap.
// These compute exactly which calendar day(s) "today's" default view should
// show, so every calendar day gets covered by exactly one day's view, with no
// gaps and no overlap.

function _daysAgo(base, n) {
  const d = new Date(base);
  d.setDate(d.getDate() - n);
  d.setHours(0, 0, 0, 0);
  return d;
}

// Secrets: normal 2-day lag (Wed shows Mon, Thu shows Tue, Fri shows Wed).
// Weekend catch-up splits across Monday (just Thursday) and Tuesday (Friday
// through Sunday) so the Thu/Fri/Sat/Sun backlog left by Friday's run gets
// fully covered without any day being shown twice.
function computeSecretsScheduleRange(today = new Date()) {
  const dow = today.getDay(); // 0=Sun .. 6=Sat
  switch (dow) {
    case 1: return { begin: _daysAgo(today, 4), end: _daysAgo(today, 4) };  // Mon -> Thu
    case 2: return { begin: _daysAgo(today, 4), end: _daysAgo(today, 2) };  // Tue -> Fri-Sun
    case 6: return { begin: _daysAgo(today, 3), end: _daysAgo(today, 3) };  // Sat -> same as Fri's view (Wed)
    case 0: return { begin: _daysAgo(today, 4), end: _daysAgo(today, 4) };  // Sun -> same as Fri's view (Wed)
    default: return { begin: _daysAgo(today, 2), end: _daysAgo(today, 2) }; // Wed/Thu/Fri -> T-2
  }
}

// Mail: normal 1-day lag (yesterday). Weekend catch-up happens in one shot on
// Monday, covering Friday through Sunday.
function computeMailScheduleRange(today = new Date()) {
  const dow = today.getDay();
  if (dow === 1) return { begin: _daysAgo(today, 3), end: _daysAgo(today, 1) }; // Mon -> Fri-Sun
  return { begin: _daysAgo(today, 1), end: _daysAgo(today, 1) };                // every other day -> yesterday
}

function formatScheduleLabel(range) {
  const opts = { weekday: 'short', month: 'short', day: 'numeric' };
  const beginStr = range.begin.toLocaleDateString(undefined, opts);
  if (range.begin.toDateString() === range.end.toDateString()) return beginStr;
  const endStr = range.end.toLocaleDateString(undefined, opts);
  return `${beginStr} – ${endStr}`;
}

// Formats a JS Date as the "YYYY-MM-DD HH:MM:SS" strings the backend's begin/end
// filters expect, spanning the full day (00:00:00 through 23:59:59).
function toApiDateRange(range) {
  const pad = n => String(n).padStart(2, '0');
  const ymd = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  return { begin: `${ymd(range.begin)} 00:00:00`, end: `${ymd(range.end)} 23:59:59` };
}

// Fills a .schedule-badge element with a muted prefix + a bold, prominent date.
function setScheduleLabel(elId, prefix, dateText) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.innerHTML = dateText ? `<span class="sb-prefix">${escapeHtml(prefix)}</span>${escapeHtml(dateText)}` : '';
}

function initials(name) {
  const parts = String(name || '?').trim().split(/\s+/);
  return ((parts[0]?.[0] || '') + (parts[1]?.[0] || '')).toUpperCase() || '?';
}

// ---------- API wrapper: auto-redirect to login on 401 ----------
async function api(path, options = {}) {
  const res = await fetch(path, { ...options, headers: { ...(options.headers || {}) } });
  if (res.status === 401) {
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login.html?next=${next}`;
    throw new Error('not authenticated');
  }
  return res;
}

async function apiJson(path, options = {}) {
  const opts = { ...options };
  if (opts.body && typeof opts.body !== 'string' && !(opts.body instanceof FormData)) {
    opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    opts.body = JSON.stringify(opts.body);
  }
  const res = await api(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `request failed (${res.status})`);
  return data;
}

// ---------- Auth gate + sidebar shell ----------
window.currentUser = null;

async function requireAuth() {
  const statusRes = await fetch('/api/auth/status');
  const status = await statusRes.json();
  if (status.setup_required) {
    window.location.href = '/setup.html';
    throw new Error('setup required');
  }
  const meRes = await fetch('/api/auth/me');
  if (meRes.status === 401) {
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login.html?next=${next}`;
    throw new Error('not authenticated');
  }
  window.currentUser = await meRes.json();
  window.isAdmin = window.currentUser.role === 'admin';
  return window.currentUser;
}

const NAV_ITEMS = [
  { key: 'dashboard', href: '/', icon: '&#9673;', label: 'Dashboard' },
  { key: 'secrets', href: '/secrets.html', icon: '&#128273;', label: 'Secret Scanner' },
  { key: 'mail', href: '/mail.html', icon: '&#9993;', label: 'Mail Exfil' },
  { key: 'files', href: '/files.html', icon: '&#128196;', label: 'File Analyzer' },
  { key: 'history', href: '/history.html', icon: '&#128340;', label: 'History' },
];

function renderSidebar(activeKey) {
  const mount = document.getElementById('sidebarMount');
  if (!mount) return;

  const navLinks = NAV_ITEMS.map(item => `
    <a href="${item.href}" class="${item.key === activeKey ? 'active' : ''}">
      <span class="ico">${item.icon}</span>${item.label}
    </a>
  `).join('');

  const adminLink = window.isAdmin ? `
    <div class="nav-section-label">Admin</div>
    <a href="/users.html" class="${activeKey === 'users' ? 'active' : ''}"><span class="ico">&#128101;</span>Users</a>
  ` : '';

  mount.innerHTML = `
    <div class="sidebar">
      <div class="brand">
        <span class="brand-logo-text">DLP AI</span>
        <span>DLP AI<br>Console</span>
      </div>
      <nav>${navLinks}${adminLink}</nav>
      <div class="nav-spacer"></div>
      <div class="account-widget" id="accountWidget">
        <a href="/account.html" class="account-link">
          <span id="accountAvatar" class="account-avatar"></span>
          <span class="who">
            <span class="name" id="accountName"></span>
            <span class="role" id="accountRole"></span>
          </span>
        </a>
        <button id="logoutBtn" type="button" class="logout-btn">
          <span class="ico">&#8635;</span>Log out
        </button>
      </div>
    </div>
  `;

  const u = window.currentUser;
  const avatarEl = document.getElementById('accountAvatar');
  if (u.profile_picture) {
    avatarEl.innerHTML = `<img src="/api/profile-pictures/${encodeURIComponent(u.profile_picture)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
  } else {
    avatarEl.textContent = initials(u.display_name);
  }
  document.getElementById('accountName').textContent = u.display_name;
  document.getElementById('accountRole').textContent = u.role;

  document.getElementById('logoutBtn').onclick = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.href = '/login.html';
  };
}

async function initPage(activeKey) {
  await requireAuth();
  renderSidebar(activeKey);
}
