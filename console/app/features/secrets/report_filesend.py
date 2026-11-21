"""Track D — fetches the "Files sent by user" report (ReportId=215) via the
EMP report portal web CGI, same universal-table mechanism `emp_sql.run_sql()` uses for
the SQL-console report (ReportId=221), just a different report id and a differently
shaped payload.

Confirmed live (2026-07-17, LocationIds=1001): columns are
`User, Time, Size KB, Type, File, Destination, Application/Site, Vocabulary`. The
`File` cell is plain text UNLESS a server-side copy of the sent file was captured
(a per-employee EMP profile setting, not on by default), in which case it's
`<a href="../../../../cgi-report.exe?action=getfile&filepath=...">real\\path</a>` —
same "pull the href out as an opaque string, don't try to decode/rebuild filepath
yourself" lesson `screenshots.py`'s `_SHOT_RE` already learned (the filepath query
param has its own internal percent-encoding, e.g. dashes as `%2D`).

Not every row for a code-type file has a link — the copy-save profile doesn't
capture every single send (observed two `automation.py` sends four minutes apart,
same user; only the second had a link). Callers must treat a missing href as
"no content available", not an error.
"""
import html as html_module
import json
import re
from datetime import datetime
from urllib.parse import urljoin

from . import emp_sql as k

REPORT_FILESND = 215

_FILE_CELL_LINK_RE = re.compile(r'<a[^>]*href="([^"]*action=getfile[^"]*)"[^>]*>([^<]*)</a>')


def generate_filesend_report(session, location_ids: str, begin_dt: datetime, end_dt: datetime):
    """location_ids is passed straight through as EMP's LocationIds form value
    (empty string = whatever the account can see; comma-separated ids untested against
    this report — verify empirically if used, per the plan's noted open question).

    DateTimePickerBegin/End are day-granularity in EMP's own UI (HourSelect/
    MinuteSelect are a separate time-of-day-window filter applied across every day in
    range, e.g. "only 9am-5pm"), so this pulls the full day(s) covering begin_dt..end_dt
    and leaves precise sub-day filtering to the caller (same division of labor as the
    existing app's fetch_events_in_range) rather than fighting the picker's real
    semantics.

    Returns the parsed universal-table payload dict (columns + rows)."""
    resp = session.post(
        f"{k.BASE}/cgi-report.exe?action=report",
        data={
            "MyHttpURL": f"{k.BASE}/boffline/",
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
    index_url = urljoin(f"{k.BASE}/cgi-report.exe", location)
    data_url = index_url.rsplit("/", 1)[0] + "/report_data.js"

    data_resp = session.get(data_url)
    data_resp.raise_for_status()
    text = data_resp.text
    m = re.search(r"g_UniversalTableReportData\s*=\s*(\{.*\});?\s*$", text, re.S)
    if not m:
        raise RuntimeError(f"Could not parse report_data.js: {text[:500]}")
    return json.loads(m.group(1))


def parse_filesend_rows(payload: dict):
    """Returns a list of dicts: user, event_time, size_kb, file_type, file_display_path,
    file_href (None if no saved copy), destination_url, app_desc, vocabulary.

    Column titles confirmed live (2026-07-17): User, Time, "Size, KB", Type, File,
    Destination, Application/Site, Vocabulary."""
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
