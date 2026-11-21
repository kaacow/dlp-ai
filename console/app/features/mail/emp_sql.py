#!/usr/bin/env python3
"""EMP DLP - SQL-console query helper via EMP report portal web report (ReportId=221).

The svc_readonly EMP report portal account has report id 221 (REPORT_SQLQUERY) in its allowed
report list, which gives arbitrary read SQL against the EMP Postgres DB over
HTTPS, with no need for direct port-5432 access.

Credentials are read from a .env file (EMP_HOST, EMP_USERNAME, EMP_PASSWORD) next
to this script, not hardcoded, since this box is shared with other local users.
"""
import os
import re
import json
import requests
import urllib3
from pathlib import Path
from urllib.parse import urljoin

urllib3.disable_warnings()

REPORT_SQLQUERY = 221


def _load_env():
    env_path = Path(__file__).parent / ".env"
    env = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


_env = _load_env()
HOST = os.environ.get("EMP_HOST", _env.get("EMP_HOST", "https://emp.example.internal"))
USERNAME = os.environ.get("EMP_USERNAME", _env.get("EMP_USERNAME"))
PASSWORD = os.environ.get("EMP_PASSWORD", _env.get("EMP_PASSWORD"))
BASE = f"{HOST}/emp"


def get_session():
    if not USERNAME or not PASSWORD:
        raise RuntimeError("EMP_USERNAME/EMP_PASSWORD not set (env or .env file)")
    s = requests.Session()
    s.verify = False
    resp = s.post(
        f"{BASE}/cgi-report.exe",
        params={"action": "login"},
        data={"username": USERNAME, "userpwd": PASSWORD},
        allow_redirects=True,
    )
    resp.raise_for_status()
    return s


def run_sql(session, query, timebegin="", timeend=""):
    """Submit a SQL query to the SQL-console report and return (columns, rows, payload)."""
    resp = session.post(
        f"{BASE}/cgi-report.exe?action=report",
        data={
            "ReportId": str(REPORT_SQLQUERY),
            "LocationIds": "",
            "DateTimePickerBegin": timebegin,
            "DateTimePickerEnd": timeend,
            "HourSelectBegin": "0",
            "HourSelectEnd": "24",
            "MinuteSelectBegin": "0",
            "MinuteSelectEnd": "0",
            "EditWorkHours": "",
            "HourWorkDayBegin": "",
            "EditDayBreak": "",
            "ComboBoxFilterAppSite": "",
            "CheckBoxExpandText": "1",
            "SQLQueryText": query,
            "MyHttpURL": f"{BASE}/boffline/",
            "NoCleanDir": "1",
        },
        allow_redirects=False,
    )
    if resp.status_code != 302:
        raise RuntimeError(f"Unexpected status {resp.status_code}: {resp.text[:500]}")
    location = resp.headers["Location"]
    index_url = urljoin(f"{BASE}/cgi-report.exe", location)
    data_url = index_url.rsplit("/", 1)[0] + "/report_data.js"

    data_resp = session.get(data_url)
    data_resp.raise_for_status()
    text = data_resp.text
    m = re.search(r"g_UniversalTableReportData\s*=\s*(\{.*\});?\s*$", text, re.S)
    if not m:
        raise RuntimeError(f"Could not parse report_data.js: {text[:1000]}")
    payload = json.loads(m.group(1))

    if "error" in payload or (payload.get("header") or {}).get("error"):
        raise RuntimeError(f"SQL error: {payload}")

    columns = [c["title"] for c in payload.get("columns", [])]
    rows = payload.get("rows", [])
    return columns, rows, payload


def print_table(columns, rows, max_rows=50):
    print(" | ".join(columns))
    print("-" * 80)
    for r in rows[:max_rows]:
        print(" | ".join(str(v) for v in r))
    if len(rows) > max_rows:
        print(f"... ({len(rows)} total rows)")


if __name__ == "__main__":
    import sys
    sess = get_session()
    q = sys.argv[1] if len(sys.argv) > 1 else "SELECT id, name FROM tvocabs ORDER BY id;"
    cols, rows, payload = run_sql(sess, q)
    print_table(cols, rows)
