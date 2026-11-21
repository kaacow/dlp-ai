"""Fetches the "Files sent by user" report (ReportId=215) via the EMP report portal web
CGI — same universal-table mechanism emp_sql.run_sql() uses for the SQL-console
report (ReportId=221), just a different report id and a differently shaped payload.

Ported from Track D's content_scan/app/report_filesend.py (proven there since
2026-07-17). The one thing raw SQL against treportfilesnd can NOT give us: when a
per-employee EMP profile setting captures a server-side copy of the sent file,
this report's `File` cell becomes a link
(`<a href="../../../../cgi-report.exe?action=getfile&filepath=...">real\\path</a>`)
— that href only exists in the report engine's rendered HTML, not as a DB column.
Confirmed live against svc_readonly/LocationIds=1001 (2026-08-20): columns are
`User, Time, Size KB, Type, File, Destination, Application/Site, Vocabulary`, and
every one of today's 6 real sends had a link (file-copy capture is on for this
account/profile).

Not every row for a code-type file has a link — the copy-save profile doesn't
capture every single send. Callers must treat a missing href as "no content
available", not an error.
"""
import html as html_module
import json
import re
from datetime import datetime
from urllib.parse import urljoin

REPORT_FILESND = 215

_FILE_CELL_LINK_RE = re.compile(r'<a[^>]*href="([^"]*action=getfile[^"]*)"[^>]*>([^<]*)</a>')


def generate_filesend_report(session, base: str, location_ids: str, begin_dt: datetime, end_dt: datetime):
    """location_ids is passed straight through as EMP's LocationIds form value
    (empty string = whatever the account can see).

    DateTimePickerBegin/End are day-granularity in EMP's own UI (HourSelect/
    MinuteSelect are a separate time-of-day-window filter applied across every day in
    range), so this pulls the full day(s) covering begin_dt..end_dt and leaves precise
    sub-day filtering to the caller.

    Returns the parsed universal-table payload dict (columns + rows)."""
    resp = session.post(
        f"{base}/cgi-report.exe?action=report",
        data={
            "MyHttpURL": f"{base}/boffline/",
            "ReportId": str(REPORT_FILESND),
            "LocationIds": location_ids or "",
            "ScreenWidth": "1920", "ScreenHeight": "1080",
            "DateTimePickerBegin": begin_dt.strftime("%d.%m.%Y"),
            "HourSelectBegin": "0", "MinuteSelectBegin": "0",
            "DateTimePickerEnd": end_dt.strftime("%d.%m.%Y"),
            "HourSelectEnd": "24", "MinuteSelectEnd": "0",
            "EditWorkHours": "8", "HourWorkDayBegin": "9.0", "EditDayBreak": "60",
            "ComboBoxFilterAppSite": "", "ComboBoxFilterText": "",
            "CheckBoxFileLinkURL": "1",
            "NoCleanDir": "1",
        },
        allow_redirects=False,
    )
    if resp.status_code != 302:
        raise RuntimeError(f"Filesend report generation failed: {resp.status_code}: {resp.text[:300]}")

    location = resp.headers["Location"]
    index_url = urljoin(f"{base}/cgi-report.exe", location)
    data_url = index_url.rsplit("/", 1)[0] + "/report_data.js"

    data_resp = session.get(data_url)
    data_resp.raise_for_status()
    # The server sends `Content-Type: text/javascript` with no charset param, so
    # requests falls back to the HTTP-spec default (ISO-8859-1) for text/* without
    # one — but the actual bytes are UTF-8. Confirmed live (2026-08-20): left
    # unfixed, this silently mojibake-corrupts any non-ASCII filename (e.g.
    # a non-ASCII filename like "Təcrübə.doc" became "TÉ™crÃ¼bÉ™.doc"),
    # which in turn broke content_evidence.py's filename matching against
    # event_verdicts (sourced via a different, correctly-decoded path) — a real
    # file with a saved copy was reported as "no saved copy available".
    data_resp.encoding = "utf-8"
    text = data_resp.text
    m = re.search(r"g_UniversalTableReportData\s*=\s*(\{.*\});?\s*$", text, re.S)
    if not m:
        raise RuntimeError(f"Could not parse report_data.js: {text[:500]}")
    return json.loads(m.group(1))


def parse_filesend_rows(payload: dict):
    """Returns a list of dicts: user, event_time, size_kb, file_type, file_display_path,
    file_href (None if no saved copy), destination_url, app_desc, vocabulary."""
    columns = [c.get("title") for c in payload.get("columns", [])]
    idx = {name: i for i, name in enumerate(columns)}
    out = []
    for row in payload.get("rows", []):
        file_cell = row[idx["File"]] or ""
        m = _FILE_CELL_LINK_RE.search(file_cell)
        if m:
            href, display_path = html_module.unescape(m.group(1)), html_module.unescape(m.group(2))
        else:
            href, display_path = None, file_cell
        out.append({
            "user": row[idx["User"]],
            "event_time": row[idx["Time"]],
            "size_kb": row[idx["Size, KB"]],
            "file_type": (row[idx["Type"]] or "").lower(),
            "file_display_path": display_path,
            "file_href": href,
            "destination_url": row[idx["Destination"]],
            "app_desc": row[idx["Application/Site"]],
            "vocabulary": row[idx["Vocabulary"]] if "Vocabulary" in idx else None,
        })
    return out
