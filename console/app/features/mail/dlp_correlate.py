"""On-demand DLP lookup for a single flagged Exchange mail — triggered by the
"Find in DLP" button per row, not run automatically for every flagged mail.

Superseded design (2026-08-05): the original `build_day_index()` queried
EMP's Mails report with `LocationIds=""` meaning "all locations" —
**confirmed live this was wrong**: an empty LocationIds returns ZERO rows,
not everyone's. Every automatic correlation therefore silently failed and
showed "phone_sent" even for mail DLP genuinely captured (confirmed live: a
real gmail send from `jdoe` had a real `.msg` file in DLP the whole
time). The user's own workflow — look up the specific user's LocationIds
from `tuserlocations`, then query the Mails report scoped to just those IDs —
is the only approach confirmed to actually return data, and is also much
cheaper (one small per-user query instead of one org-wide query per day).

`tuserlocations` schema (confirmed live via the SQL-console report,
`emp_sql.run_sql`): `id, up_time, comp_loc, comp_name, user_domain,
user_name, report_time, tz_offset`. `user_name` matches the AD-username local
part of the corporate email exactly (e.g. `jdoe`), and one username can
map to multiple `id`s — one per computer they've used (confirmed live:
`jdoe` has ids 1001 and 1002, from two different laptops).
"""
from datetime import datetime, timedelta

from . import emp_sql as k
from . import mail_report

TIME_WINDOW_HOURS = 6  # sanity bound on the closest-match, generous since this is a targeted single-user lookup


def _lookup_location_ids(session, username: str) -> list[str]:
    # emp_sql.run_sql takes a raw SQL string (no bind params, per its existing
    # usage elsewhere in this app) — the username comes from our own DB
    # (Exchange sender address local-part), not user-supplied free text, but
    # still escape single quotes defensively before interpolating.
    safe_username = username.replace("'", "''")
    _, rows, _ = k.run_sql(session, f"SELECT id FROM tuserlocations WHERE user_name = '{safe_username}';")
    return [str(r[0]) for r in rows]


def find_dlp_copy(session, sender_username: str, recipient_email: str, subject: str, approx_time: datetime) -> tuple[str, str | None]:
    """Returns (dlp_status, msg_href):
      ("found", href)         — DLP has a usable .msg copy.
      ("found_no_file", None) — DLP logged the mail but captured no file.
      ("phone_sent", None)    — no matching DLP row at all, or this user has
                                 no known DLP-monitored device — the signal a
                                 phone (or other unmonitored device) sent it.
    """
    location_ids = _lookup_location_ids(session, sender_username)
    if not location_ids:
        return "phone_sent", None

    # Query a window straddling the event day on both sides — Exchange's
    # Received timestamp and EMP's capture time aren't guaranteed to
    # agree on which calendar day a late-night send falls on.
    begin_dt = datetime(approx_time.year, approx_time.month, approx_time.day) - timedelta(days=1)
    end_dt = begin_dt + timedelta(days=3) - timedelta(seconds=1)
    payload = mail_report.generate_mail_report(session, ",".join(location_ids), begin_dt, end_dt)
    rows = mail_report.parse_mail_rows(payload)

    candidates = [r for r in rows if (r["recipient_email"] or "").lower() == (recipient_email or "").lower()]
    if not candidates:
        return "phone_sent", None

    def sort_key(r):
        try:
            ts = datetime.strptime(r["event_time"], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return (1, float("inf"))
        subject_mismatch = 0 if (r["subject"] or "").strip() == (subject or "").strip() else 1
        return (subject_mismatch, abs((ts - approx_time).total_seconds()))

    best = min(candidates, key=sort_key)
    try:
        best_ts = datetime.strptime(best["event_time"], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return "phone_sent", None
    if abs((best_ts - approx_time).total_seconds()) > TIME_WINDOW_HOURS * 3600:
        return "phone_sent", None

    return ("found", best["msg_href"]) if best["msg_href"] else ("found_no_file", None)
