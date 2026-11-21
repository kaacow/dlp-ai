"""Background job: pull the Mails report for a time range + optional LocationIds,
filter to outgoing rows, classify each with detector.py, and for matches fetch the
.msg content + get a small-model verdict. Mirrors track_d_content_scan's
runner.py threading pattern (one job at a time, live-updated run row polled by
the UI) but only persists rows that actually matched a rule — the human only
cares about flagged mail, and volume here is far lower than Track D's
~3,000/day file-sends, so there's no need for its full skip-bookkeeping.
"""
import sqlite3
import threading
import traceback
from datetime import datetime, timedelta
from pathlib import Path

from . import detector
from . import emp_sql as k
from . import msg_fetch
from .analyzer import analyze
from .detector import get_domain
from .mail_report import generate_mail_report, parse_mail_rows

DB_PATH = Path("./data/db/mail_detector.sqlite3")  # existing DB, reused for data continuity per the merge plan
SCHEMA_PATH = Path("./data/db/schema.sql")
AUTO_RUN_DAYS_AGO = 2

_run_lock = threading.Lock()
_run_in_progress = False


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


def start_run_if_idle(begin_dt: datetime, end_dt: datetime, location_ids: str, threshold: float, mode: str = "manual"):
    global _run_in_progress
    with _run_lock:
        if _run_in_progress:
            return None
        _run_in_progress = True

    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO mail_runs (mode, begin_time, end_time, location_ids, threshold) VALUES (?, ?, ?, ?, ?);",
            (mode, begin_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S"), location_ids, threshold),
        )
        run_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    threading.Thread(target=_run_job, args=(run_id, begin_dt, end_dt, location_ids, threshold), daemon=True).start()
    return run_id


def start_auto_run():
    """No-param entry point cron hits daily: T-2 days, full day, all locations this
    account can see."""
    day = (datetime.now() - timedelta(days=AUTO_RUN_DAYS_AGO)).date()
    begin_dt = datetime(day.year, day.month, day.day, 0, 0, 0)
    end_dt = datetime(day.year, day.month, day.day, 23, 59, 59)
    return start_run_if_idle(begin_dt, end_dt, "", detector.DEFAULT_THRESHOLD, mode="auto")


def _store_event(conn, run_id, mail, match, summary=None, model_version=None, error=None):
    conn.execute(
        """INSERT OR IGNORE INTO mail_events
             (run_id, msg_href, sender_username, sender_fullname, event_time, recipient_name,
              recipient_email, recipient_domain, subject, size_kb, match_type, similarity_score,
              ai_summary, model_version, error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
        (run_id, mail["msg_href"], mail["sender_username"], mail["sender_fullname"], mail["event_time"],
         mail["recipient_name"], mail["recipient_email"], get_domain(mail["recipient_email"]), mail["subject"],
         mail["size_kb"], match["match_type"], match["similarity_score"], summary, model_version, error),
    )
    conn.commit()


def _run_job(run_id, begin_dt, end_dt, location_ids, threshold):
    global _run_in_progress
    conn = get_connection()
    try:
        sess = k.get_session()
        payload = generate_mail_report(sess, location_ids, begin_dt, end_dt)
        rows = parse_mail_rows(payload)

        # Report is day-granularity — narrow to the exact requested window here,
        # same division of labor as report_filesend's caller in track_d's runner.py.
        rows = [
            r for r in rows
            if begin_dt <= datetime.strptime(r["event_time"], "%Y-%m-%d %H:%M:%S") <= end_dt
        ]

        mails_seen = len(rows)
        mails_flagged = 0
        conn.execute("UPDATE mail_runs SET mails_seen = ? WHERE id = ?;", (mails_seen, run_id))
        conn.commit()

        for mail in rows:
            match = detector.classify(mail, threshold)
            if not match:
                continue

            summary, model_version, err = None, None, None
            if mail["msg_href"]:
                try:
                    raw = msg_fetch.fetch_mail_bytes(sess, mail["msg_href"])
                    content = msg_fetch.parse_msg(raw)
                    summary, model_version = analyze(mail, match, content)
                except Exception as e:
                    err = str(e)
            else:
                err = "no saved .msg copy for this mail"

            _store_event(conn, run_id, mail, match, summary=summary, model_version=model_version, error=err)
            mails_flagged += 1
            conn.execute("UPDATE mail_runs SET mails_flagged = ? WHERE id = ?;", (mails_flagged, run_id))
            conn.commit()

        conn.execute("UPDATE mail_runs SET status='done', finished_at=datetime('now') WHERE id=?;", (run_id,))
        conn.commit()
    except Exception as e:
        conn.execute(
            "UPDATE mail_runs SET status='failed', error=?, finished_at=datetime('now') WHERE id=?;",
            (f"{e}\n{traceback.format_exc()[-2000:]}", run_id),
        )
        conn.commit()
    finally:
        conn.close()
        with _run_lock:
            _run_in_progress = False
