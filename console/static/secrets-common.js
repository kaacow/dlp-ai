// Secret Scanner rendering shared between secrets.html (schedule-filtered
// default view) and history.html (full unrestricted browse view).

function secretsTableRows(files) {
  return files.map(f => `
    <tr class="clickable" data-id="${f.id}">
      <td>${escapeHtml(f.event_time || '')}</td>
      <td>${escapeHtml((f.user_locator_raw||'').split('\n')[0])}</td>
      <td class="name-cell" title="${escapeHtml(f.file_name||'')}">${escapeHtml(f.file_name || '(no filename)')}</td>
      <td>${escapeHtml(f.destination_app||'')}</td>
      <td><span class="pill">${escapeHtml((f.scan_status||'').replace(/_/g,' '))}</span></td>
      <td>${f.max_severity ? `<span class="pill ${f.max_severity}">${escapeHtml(f.max_severity)}</span>` : (f.scan_status === 'scanned' ? '<span style="color:var(--muted)">clean</span>' : '')}</td>
      <td>${f.finding_count || ''}</td>
    </tr>
  `).join('');
}

function renderSecretsTable(wrapEl, data, emptyMsg) {
  if (!data.files.length) {
    wrapEl.innerHTML = `<div class="empty-state">${emptyMsg || 'No files in this range.'}</div>`;
    return;
  }
  wrapEl.innerHTML = `<table class="data-table">
    <thead><tr><th>Time</th><th>User</th><th>File</th><th>Destination</th><th>Status</th><th>Severity</th><th>Findings</th></tr></thead>
    <tbody>${secretsTableRows(data.files)}</tbody>
  </table>`;
  wrapEl.querySelectorAll('tr.clickable').forEach(row => {
    row.onclick = () => openSecretsDetail(row.dataset.id);
  });
}

function findingCardHtml(f) {
  return `<div class="card" style="padding:14px; margin-top:10px; ${f.is_placeholder ? 'opacity:.6;' : ''}">
    <div><span class="pill ${f.severity || 'low'}">${escapeHtml(f.severity || 'low')}</span>
      <span style="font-size:12.5px; color:var(--muted);">line ${f.line} · ${escapeHtml(f.type||'')}${f.regex_confirmed ? ' · regex+model' : ' · model only'}${f.is_placeholder ? ' · looks like a placeholder' : ''}</span></div>
    <pre style="white-space:pre-wrap; word-break:break-word; font-size:12px; background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:10px; margin:8px 0 6px;">${escapeHtml(f.snippet||'')}</pre>
    <div style="font-size:13px;">${escapeHtml(f.explanation||'')}</div>
  </div>`;
}

function codeViewHtml(content, findingLines) {
  const flagged = new Set(findingLines);
  return content.split('\n').map((line, i) => {
    const n = i + 1;
    return `<span style="display:block; ${flagged.has(n) ? 'background:color-mix(in srgb, var(--bad) 12%, transparent);' : ''}">${String(n).padStart(4,' ')}  ${escapeHtml(line)}</span>`;
  }).join('');
}

async function openSecretsDetail(id) {
  const f = await (await api('/api/secrets/files/' + id)).json();
  const findings = f.findings || [];
  document.getElementById('detailPanel').innerHTML = `
    <button class="close-btn" id="closeDetailBtn">&times;</button>
    <h2 style="margin-top:0;">${escapeHtml(f.file_name || '(no filename)')}</h2>
    <div style="color:var(--muted); font-size:13px;">${escapeHtml(f.event_time)} · ${escapeHtml((f.user_locator_raw||'').replace(/\n/g,' '))}<br>${escapeHtml(f.destination_app||'')} · ${escapeHtml(f.file_type||'')} · ${f.size_kb||0} KB</div>
    <div class="label" style="margin-top:14px;">Status</div>
    <div><span class="pill">${escapeHtml((f.scan_status||'').replace(/_/g,' '))}</span> ${f.max_severity ? `<span class="pill ${f.max_severity}">${escapeHtml(f.max_severity)}</span>` : ''}${f.truncated ? ' <span style="color:var(--muted); font-size:12.5px;">(content truncated before scanning)</span>' : ''}</div>
    ${f.error ? `<div class="result-error">${escapeHtml(f.error)}</div>` : ''}
    ${findings.length ? `<div class="label">Findings (${findings.length})</div>${findings.map(findingCardHtml).join('')}` : ''}
    ${f.full_content ? `<div class="label">File content</div><pre style="white-space:pre-wrap; word-break:break-word; font-size:11.5px; background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:12px; max-height:400px; overflow-y:auto; font-family:var(--mono);">${codeViewHtml(f.full_content, findings.map(x=>x.line))}</pre>` : ''}
    ${f.model_version ? `<div class="label">Model</div><div style="font-family:var(--mono); font-size:12.5px;">${escapeHtml(f.model_version)}</div>` : ''}
  `;
  document.getElementById('closeDetailBtn').onclick = closeSecretsDetail;
  document.getElementById('overlay').classList.add('open');
}
function closeSecretsDetail() { document.getElementById('overlay').classList.remove('open'); }
