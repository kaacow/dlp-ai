"""Background job for the Exchange-sourced pages (Gmail / Mail.ru). Mirrors
runner.py's one-job-at-a-time threading pattern (_run_lock, live-polled run
row) but sources rows from exchange_fetch/exchange_csv instead of EMP,
and does an Azure AD name lookup (Exchange trace has no display name).

DLP correlation and AI analysis are BOTH on-demand only now (2026-08-05,
per the user): the run itself just pulls Exchange, detects, and stores —
no per-row EMP round-trip, which is what made the run slow. Each
flagged row starts with dlp_status/msg_href NULL ("unchecked"); the
"Find in DLP" button (main.py's /api/exchange/events/{id}/find_in_dlp) does
the actual DLP lookup only when the user asks for a specific mail, and the
Analyze button (/api/exchange/events/{id}/analyze) only runs once a DLP copy
has been found.
"""
import sqlite3
import threading
import traceback
from datetime import date, timedelta
from pathlib import Path

from . import azure_ad
from . import detector
from . import exchange_csv
from . import exchange_fetch
from . import notify
from .detector import compute_score, extract_email_username, get_domain
from .domains import is_internal_domain
from .errors import ReauthRequiredError

DB_PATH = Path("./data/db/mail_detector.sqlite3")  # existing DB, reused for data continuity per the merge plan
AUTO_RUN_DAYS_AGO = 1
AUTO_RUN_DOMAINS = ["gmail.com", "mail.ru"]

_run_lock = threading.Lock()
_run_in_progress = False


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _create_run(conn, domain: str, day: date, threshold: float, mode: str) -> int:
    cur = conn.execute(
        "INSERT INTO exchange_runs (mode, domain, day, threshold) VALUES (?, ?, ?, ?);",
        (mode, domain, day.strftime("%Y-%m-%d"), threshold),
    )
    conn.commit()
    return cur.lastrowid


def _store_event(conn, run_id, domain, row, sender_fullname, score) -> bool:
    """dlp_status starts 'unchecked' (a real value, not NULL, so the events
    API's dlp_status filter and the UI's status dropdown can match it the
    same way as any other status) — set to found/found_no_file/phone_sent
    later, on demand, by the "Find in DLP" button (main.py's find_in_dlp
    endpoint). Returns True if this actually inserted a new row — an
    overlapping run (e.g. the same mail seen by both a manual re-run and the
    daily auto run) hits the dedup_key UNIQUE constraint and is silently
    ignored, which the caller needs to know so mails_flagged reflects real
    new detections rather than every attempt."""
    dedup_key = f"{row['sender_address']}|{row['recipient_address']}|{row['received']}"
    cur = conn.execute(
        """INSERT OR IGNORE INTO exchange_mail_events
             (run_id, dedup_key, domain, sender_address, sender_fullname, recipient_address,
              event_time, subject, similarity_score, dlp_status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'unchecked');""",
        (run_id, dedup_key, domain, row["sender_address"], sender_fullname, row["recipient_address"],
         row["received"], row["subject"], score),
    )
    conn.commit()
    return cur.rowcount > 0


def _run_job_single(conn, run_id: int, domain: str, day: date, threshold: float, csv_bytes: bytes | None):
    """Does the actual work for one domain-day. Raises ReauthRequiredError on
    an Exchange login/az CLI auth wall; any other exception is caught by the
    caller and stored as a plain 'failed' run."""
    if csv_bytes is None:
        csv_path = exchange_fetch.run_message_trace(domain, day)
        csv_bytes = csv_path.read_bytes()

    df = exchange_csv.load_csv(csv_bytes, fname=f"{domain}_{day}.csv")
    rows = exchange_csv.normalize_rows(df)

    # Defensive filter even though the trace search was already scoped to this
    # recipient domain (matters for the upload-CSV fallback, where the file
    # might not be pre-filtered) — sender must be internal, recipient must be
    # on the target personal domain.
    rows = [
        r for r in rows
        if is_internal_domain(get_domain(r["sender_address"])) and get_domain(r["recipient_address"]) == domain
    ]

    mails_seen = len(rows)
    conn.execute("UPDATE exchange_runs SET mails_seen = ? WHERE id = ?;", (mails_seen, run_id))
    conn.commit()

    senders = [r["sender_address"] for r in rows]
    name_map = azure_ad.build_name_map(senders)  # raises ReauthRequiredError if az login lapsed

    mails_flagged = 0
    for row in rows:
        sender_fullname = name_map.get(row["sender_address"], "")
        if not sender_fullname:
            continue
        score = compute_score(sender_fullname, extract_email_username(row["recipient_address"]))
        if score < threshold:
            continue

        if not _store_event(conn, run_id, domain, row, sender_fullname, round(score, 3)):
            continue  # already recorded by an earlier overlapping run — not a new detection
        mails_flagged += 1
        conn.execute("UPDATE exchange_runs SET mails_flagged = ? WHERE id = ?;", (mails_flagged, run_id))
        conn.commit()

    conn.execute("UPDATE exchange_runs SET status='done', finished_at=datetime('now') WHERE id=?;", (run_id,))
    conn.commit()


def _run_one_domain(conn, domain: str, day: date, threshold: float, mode: str, csv_bytes: bytes | None):
    run_id = _create_run(conn, domain, day, threshold, mode)
    try:
        _run_job_single(conn, run_id, domain, day, threshold, csv_bytes)
    except ReauthRequiredError as e:
        conn.execute(
            "UPDATE exchange_runs SET status='needs_reauth', error=?, finished_at=datetime('now') WHERE id=?;",
            (str(e), run_id),
        )
        conn.commit()
        notify.send_telegram(
            f"Mail detector: {domain} pull for {day} needs manual login — {e}"
        )
    except Exception as e:
        conn.execute(
            "UPDATE exchange_runs SET status='failed', error=?, finished_at=datetime('now') WHERE id=?;",
            (f"{e}\n{traceback.format_exc()[-2000:]}", run_id),
        )
        conn.commit()
    return run_id


def _release_lock():
    global _run_in_progress
    with _run_lock:
        _run_in_progress = False


def start_run_if_idle_exchange(domain: str, day: date, threshold: float, mode: str = "manual", csv_bytes: bytes | None = None):
    """One domain, one day — used by the manual custom-range trigger and the
    upload-CSV fallback. A multi-day range is looped by the caller (one call
    per day), same division of labor as the DLP-based runner.py leaves to its
    caller for multi-day windows."""
    global _run_in_progress
    with _run_lock:
        if _run_in_progress:
            return None
        _run_in_progress = True

    def worker():
        conn = get_connection()
        try:
            _run_one_domain(conn, domain, day, threshold, mode, csv_bytes)
        finally:
            conn.close()
            _release_lock()

    threading.Thread(target=worker, daemon=True).start()
    return True


def ingest_uploaded_csv(domain: str, day: date, csv_bytes: bytes, threshold: float):
    return start_run_if_idle_exchange(domain, day, threshold, mode="upload", csv_bytes=csv_bytes)


def start_range_run_exchange(domain: str, begin_day: date, end_day: date, threshold: float):
    """Multi-day custom-range trigger. Exchange trace is day-granularity, so
    this loops one exchange_runs row per day, sequentially, under a single
    lock hold — calling start_run_if_idle_exchange in a loop from the route
    layer would fail after the first day, since that function returns
    immediately (fire-and-forget thread) while the lock stays held until that
    day's job finishes."""
    global _run_in_progress
    with _run_lock:
        if _run_in_progress:
            return False
        _run_in_progress = True

    def worker():
        conn = get_connection()
        try:
            day = begin_day
            while day <= end_day:
                _run_one_domain(conn, domain, day, threshold, "manual", None)
                day += timedelta(days=1)
        finally:
            conn.close()
            _release_lock()

    threading.Thread(target=worker, daemon=True).start()
    return True


def _auto_run_days() -> list[date]:
    """Normally just T-1. On Monday, nobody was there to review Friday/
    Saturday/Sunday's runs (the user doesn't work weekends), so Monday
    catches up on all three: Friday, Saturday, Sunday, in that order."""
    today = date.today()
    if today.weekday() == 0:  # Monday
        return [today - timedelta(days=n) for n in (3, 2, 1)]  # Fri, Sat, Sun
    return [today - timedelta(days=AUTO_RUN_DAYS_AGO)]


def start_auto_run_exchange():
    """No-param entry point the 07:00 cron hits: T-1 day (or Fri/Sat/Sun on a
    Monday — see _auto_run_days), both watched domains, in sequence under a
    single lock hold, so a manual trigger can't interleave with an
    in-progress auto batch. Each day+domain still gets its own exchange_runs
    row and its own ReauthRequiredError handling — one failure doesn't block
    the rest of the batch from attempting."""
    global _run_in_progress
    with _run_lock:
        if _run_in_progress:
            return False
        _run_in_progress = True

    days = _auto_run_days()

    def worker():
        conn = get_connection()
        try:
            for day in days:
                for domain in AUTO_RUN_DOMAINS:
                    _run_one_domain(conn, domain, day, detector.DEFAULT_THRESHOLD, "auto", None)
        finally:
            conn.close()
            _release_lock()

    threading.Thread(target=worker, daemon=True).start()
    return True
