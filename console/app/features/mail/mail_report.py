"""Fetches the "Mails" report (`ReportId=217`) via the EMP report portal web CGI, same
universal-table mechanism `emp_sql.run_sql()`/`report_filesend.py` use for the
SQL-console and filesend reports — just a different report id and payload shape.

Confirmed live (2026-07-20, LocationIds=1001): columns are
`User, Time, I/O, I/O, From/To, File, Size, KB, Subject` — note **"I/O" appears
twice** (one is an HTML `<img>` status icon, the other the actual `incoming`/
`outgoing` text), so column lookup can't just index-by-title for that one; see
`_io_indices` below. `File` is a plain `<a href="...action=getfile&filepath=...">`
link when a copy of the `.msg` was captured (same "use the href verbatim" rule as
`report_filesend.py`/`screenshots.py`), `Subject` is double-UTF8 mojibake on
non-ASCII text (same corruption class as `treportchats.ws_text` per the project
handoff doc — fixed via `.encode('latin1').decode('utf-8')`).
"""
import html as html_module
import json
import re
from datetime import datetime
from urllib.parse import urljoin

from . import emp_sql as k

REPORT_MAIL = 217

_FILE_CELL_LINK_RE = re.compile(r'<a[^>]*href="([^"]*action=getfile[^"]*)"[^>]*>([^<]*)</a>')
_EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
_USER_CELL_RE = re.compile(r'^(?:[^\\]*\\)?([^\r\n]+)\r?\n\(([^)]*)\)\s*$')


def generate_mail_report(session, location_ids: str, begin_dt: datetime, end_dt: datetime):
    """Same day-granularity semantics as `report_filesend.generate_filesend_report` —
    pulls the whole day(s) covering begin_dt..end_dt, caller narrows to the exact
    window. Returns the parsed universal-table payload dict (columns + rows)."""
    resp = session.post(
        f"{k.BASE}/cgi-report.exe?action=report",
        data={
            "MyHttpURL": f"{k.BASE}/boffline/",
            "ReportId": str(REPORT_MAIL),
            "LocationIds": location_ids or "",
            "ScreenWidth": "1920", "ScreenHeight": "1080",
            "DateTimePickerBegin": begin_dt.strftime("%d.%m.%Y"),
            "HourSelectBegin": "0", "MinuteSelectBegin": "0",
            "DateTimePickerEnd": end_dt.strftime("%d.%m.%Y"),
            "HourSelectEnd": "24", "MinuteSelectEnd": "0",
            "EditWorkHours": "8", "HourWorkDayBegin": "9.0", "EditDayBreak": "60",
            "ComboBoxFilterAppSite": "", "ComboBoxFilterText": "",
            "CheckBoxFileLinkURL": "1",
            "GlobalSearchWhere": "0",
            "NoCleanDir": "1",
        },
        allow_redirects=False,
    )
    if resp.status_code != 302:
        raise RuntimeError(f"Mail report generation failed: {resp.status_code}: {resp.text[:300]}")

    location = resp.headers["Location"]
    index_url = urljoin(f"{k.BASE}/cgi-report.exe", location)
    data_url = index_url.rsplit("/", 1)[0] + "/report_data.js"

    data_resp = session.get(data_url)
    if data_resp.status_code == 404:
        # EMP doesn't generate report_data.js at all for a range with zero
        # matching rows — it serves an HTML "nothing was found in base!" page at
        # index_url instead (confirmed live: a day with no mail activity for the
        # scoped user/location). Not an error, just an empty report.
        return {"columns": [], "rows": []}
    data_resp.raise_for_status()
    text = data_resp.text
    m = re.search(r"g_UniversalTableReportData\s*=\s*(\{.*\});?\s*$", text, re.S)
    if not m:
        raise RuntimeError(f"Could not parse report_data.js: {text[:500]}")
    return json.loads(m.group(1))


def _fix_mojibake(s: str) -> str:
    if not s:
        return s
    try:
        return s.encode("latin1").decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return s


def _split_user_cell(cell: str):
    """'CORP\\jdoe\\r\\n(John Doe)' -> ('jdoe', 'John Doe')."""
    m = _USER_CELL_RE.match((cell or "").strip())
    if not m:
        return (cell or "").strip(), ""
    return m.group(1).strip(), m.group(2).strip()


def _split_recipients(cell: str):
    """A From/To cell is one or more 'Name\\r\\nEmail' pairs. No real multi-recipient
    test data exists yet (open question noted in the project plan) — this scans for
    every email address in the cell and takes the text since the previous email (or
    cell start) as that recipient's name, so it degrades gracefully to one recipient
    for the common case and still does something sane if EMP ever concatenates
    more than one into a single cell."""
    cell = html_module.unescape(cell or "")
    matches = list(_EMAIL_RE.finditer(cell))
    out = []
    prev_end = 0
    for m in matches:
        name = cell[prev_end:m.start()].strip(" \r\n\t;,")
        out.append((name, m.group(0).lower()))
        prev_end = m.end()
    return out


def parse_mail_rows(payload: dict):
    """Returns a list of dicts: sender_username, sender_fullname, event_time,
    recipient_name, recipient_email, recipient_count, subject, size_kb,
    msg_href. Only 'outgoing' rows are yielded (this detector doesn't care about
    received mail). A row with multiple recipients in its From/To cell yields
    multiple dicts sharing the same event_time/subject/msg_href;
    recipient_count is the same value (total recipients on that mail) across
    all of them, so detector.py's self_corporate rule can tell a true
    single-recipient self-send from a self-send that was also sent to others."""
    columns = [c.get("title") for c in payload.get("columns", [])]
    io_indices = [i for i, t in enumerate(columns) if t == "I/O"]
    idx = {name: i for i, name in enumerate(columns) if name != "I/O"}

    out = []
    for row in payload.get("rows", []):
        io_text = next(
            (str(row[i]).strip().lower() for i in io_indices if str(row[i]).strip().lower() in ("incoming", "outgoing")),
            None,
        )
        if io_text != "outgoing":
            continue

        sender_username, sender_fullname = _split_user_cell(row[idx["User"]])
        file_cell = row[idx["File"]] or ""
        m = _FILE_CELL_LINK_RE.search(file_cell)
        msg_href = html_module.unescape(m.group(1)) if m else None
        subject = _fix_mojibake(row[idx["Subject"]] or "")

        recipients = _split_recipients(row[idx["From/To"]])
        for recipient_name, recipient_email in recipients:
            out.append({
                "sender_username": sender_username,
                "sender_fullname": sender_fullname,
                "event_time": row[idx["Time"]],
                "recipient_name": _fix_mojibake(recipient_name),
                "recipient_email": recipient_email,
                "recipient_count": len(recipients),
                "subject": subject,
                "size_kb": row[idx["Size, KB"]],
                "msg_href": msg_href,
            })
    return out
