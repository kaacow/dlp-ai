"""Track D — background job: pull the filesend report for a time range + optional
LocationIds, filter to code-file extensions, fetch content for rows with a saved
copy, scan for hardcoded secrets, persist. Mirrors the existing Track B/C app's
runner.py threading pattern (one job at a time, live progress fields polled by the
UI) but simpler — no classification tiers, just one pass.
"""
import json
import sqlite3
import threading
import traceback
from datetime import datetime
from pathlib import Path

from . import file_fetch
from . import emp_sql as k
from . import scanner
from .report_filesend import generate_filesend_report, parse_filesend_rows

DB_PATH = Path("./data/db/content_scan.sqlite3")  # existing DB, reused for data continuity per the merge plan
SCHEMA_PATH = Path("./data/db/schema.sql")

_run_lock = threading.Lock()
_run_in_progress = False
_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    try:
        conn.executescript(SCHEMA_PATH.read_text())
        conn.commit()
    finally:
        conn.close()


def start_run_if_idle(begin_dt: datetime, end_dt: datetime, location_ids: str):
    global _run_in_progress
    with _run_lock:
        if _run_in_progress:
            return None
        _run_in_progress = True

    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO scan_runs (begin_time, end_time, location_ids) VALUES (?, ?, ?);",
            (begin_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S"), location_ids),
        )
        run_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    threading.Thread(target=_run_job, args=(run_id, begin_dt, end_dt, location_ids), daemon=True).start()
    return run_id


def _max_severity(severities):
    ranked = [s for s in severities if s in _SEVERITY_ORDER]
    return max(ranked, key=lambda s: _SEVERITY_ORDER[s]) if ranked else None


def _store_file(conn, run_id, r, status, findings=None, content=None, truncated=False,
                 model_version=None, max_severity=None, error=None):
    """OR IGNORE relies on idx_scan_files_dedup (user_locator_raw, event_time,
    file_name, destination_app) — re-running an overlapping date range is a very
    normal thing to do (e.g. "today" ranges naturally overlap day to day), and
    without this it silently duplicated every row it saw again. A file already on
    record from an earlier run is left as-is rather than inserted a second time."""
    conn.execute(
        """INSERT OR IGNORE INTO scan_files
             (run_id, user_locator_raw, event_time, file_name, file_type, destination_app,
              size_kb, scan_status, max_severity, findings_json, full_content, truncated,
              model_version, error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
        (run_id, r["user"], r["event_time"], r["file_display_path"], r["file_type"], r["app_desc"],
         r["size_kb"], status, max_severity,
         json.dumps(findings, ensure_ascii=False) if findings is not None else None,
         content, int(truncated), model_version, error),
    )
    conn.commit()


def _run_job(run_id, begin_dt, end_dt, location_ids):
    global _run_in_progress
    conn = get_connection()
    try:
        sess = k.get_session()
        payload = generate_filesend_report(sess, location_ids, begin_dt, end_dt)
        rows = parse_filesend_rows(payload)

        # generate_filesend_report pulls whole day(s) covering the range (EMP's
        # own date picker is day-granularity) — narrow to the exact requested window
        # here, same division of labor as the existing app's fetch_events_in_range.
        rows = [
            r for r in rows
            if begin_dt <= datetime.strptime(r["event_time"], "%Y-%m-%d %H:%M:%S") <= end_dt
        ]

        files_code_type = files_scanned = files_with_findings = 0
        conn.execute("UPDATE scan_runs SET files_seen = ? WHERE id = ?;", (len(rows), run_id))
        conn.commit()

        for r in rows:
            if r["file_type"] not in scanner.CODE_EXTENSIONS:
                _store_file(conn, run_id, r, "skipped_not_code")
                continue

            files_code_type += 1
            conn.execute("UPDATE scan_runs SET files_code_type = ? WHERE id = ?;", (files_code_type, run_id))
            conn.commit()

            if not r["file_href"]:
                _store_file(conn, run_id, r, "skipped_no_copy")
                continue

            try:
                raw_bytes = file_fetch.fetch_file_bytes(sess, r["file_href"])
                content, truncated = file_fetch.decode_and_unwrap(r["file_type"], raw_bytes)
                findings, model_version = scanner.scan_file(content, r["file_display_path"])
            except Exception as e:
                _store_file(conn, run_id, r, "error", error=str(e))
                continue

            files_scanned += 1
            confirmed_severities = [f.get("severity") for f in findings if not f.get("is_placeholder")]
            max_sev = _max_severity(confirmed_severities)
            if findings:
                files_with_findings += 1
            _store_file(conn, run_id, r, "scanned", findings=findings, content=content,
                        truncated=truncated, model_version=model_version, max_severity=max_sev)
            conn.execute(
                "UPDATE scan_runs SET files_scanned=?, files_with_findings=? WHERE id=?;",
                (files_scanned, files_with_findings, run_id),
            )
            conn.commit()

        conn.execute("UPDATE scan_runs SET status='done', finished_at=datetime('now') WHERE id=?;", (run_id,))
        conn.commit()
    except Exception as e:
        conn.execute(
            "UPDATE scan_runs SET status='failed', error=?, finished_at=datetime('now') WHERE id=?;",
            (f"{e}\n{traceback.format_exc()[-2000:]}", run_id),
        )
        conn.commit()
    finally:
        conn.close()
        with _run_lock:
            _run_in_progress = False
