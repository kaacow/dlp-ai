"""Bridges Track C's investigation pipeline to the content-analysis modules
(content_analyze.py / content_scan.py's building blocks) — for an escalated event
with a real saved file copy (found via ReportId=215), download and run the actual
file content through DLP scoring, and hand the result to the reasoning model as
evidence alongside chat/window/screenshot context.

Deliberately gated at the caller (agent.gather_baseline_evidence) to only run for
"escalate" events, not the much larger spot_check bucket — confirmed live
(2026-08-20) the DB has 14,034 spot_check events historically vs. 18 escalate;
spot_check volume (~1,800/day at the ~3k/day event rate) makes full per-file
download+AI-read infeasible (each file takes 1-8 minutes), escalate volume
(~20/day) does not.

Falls back to no evidence (not an error) when no saved copy exists — a genuinely
normal case (the copy-save profile setting doesn't capture every send), same
"missing href isn't an error" rule report_filesend.py's docstring establishes.
"""
import re
import tempfile
from datetime import datetime
from pathlib import Path

import content_analyze
import content_emp
from file_fetch import fetch_file_bytes
from report_filesend import generate_filesend_report, parse_filesend_rows

# EMP appends a hash suffix to some file_path values (e.g.
# "Zaur Sened IT.pdf*F602CB79") — event_verdicts.file_name (sourced from
# treportfilesnd.file_path via runner.store_verdict) keeps that suffix, but
# report_filesend.py's File column (ReportId=215) never has it. Confirmed live
# (2026-08-20): without stripping this, find_file_href silently failed to match a
# file that genuinely had a saved copy, reporting "no saved copy" for every
# suffixed filename — same pattern rule_engine.py's _basename_and_ext already
# strips for its own filename-keyword matching.
_HASH_SUFFIX_RE = re.compile(r"\*[0-9A-Fa-f]{6,}$")


def _strip_hash_suffix(name: str) -> str:
    return _HASH_SUFFIX_RE.sub("", name)

# (date_str, location_id) -> (session, parsed rows) — investigating several escalated
# events from the same day/user (a realistic case: an employee escalates on more than
# one file the same day) shouldn't re-fetch the whole day's report each time.
_report_cache = {}


def _get_day_rows(location_id: str, day: datetime):
    key = (day.strftime("%Y-%m-%d"), location_id)
    if key not in _report_cache:
        session = content_emp.get_session()
        payload = generate_filesend_report(session, content_emp.BASE, location_id, day, day)
        _report_cache[key] = (session, parse_filesend_rows(payload))
    return _report_cache[key]


def find_file_href(user_locator: int, event_time: datetime, file_name: str):
    """Returns (session, href_or_None). location_id is passed as str(user_locator) —
    confirmed live that svc_readonly's LocationIds tree entry for this employee
    (jdoe) equals their user_locator (1001); this assumption needs
    re-verifying once svc_readonly's scope is widened past this one test employee."""
    session, rows = _get_day_rows(str(user_locator), event_time)
    target_time = event_time.strftime("%Y-%m-%d %H:%M:%S")
    target_name = _strip_hash_suffix(file_name)
    for row in rows:
        row_name = Path(row["file_display_path"].replace("\\", "/")).name
        if row["event_time"] == target_time and row_name == target_name:
            return session, row["file_href"]
    return session, None


def get_file_content_evidence(event, on_progress=None):
    """event needs: user_locator, event_time ('YYYY-MM-DD HH:MM:SS'), file_name,
    app_desc, destination_category, size_kb (optional). Returns the content_analyze
    assessment dict, or None if unavailable/not applicable (internal destination, no
    saved copy, or a fetch/analysis error — all non-fatal, investigation continues
    on other evidence)."""
    def emit(msg):
        if on_progress:
            on_progress(msg)

    if event.get("destination_category") in ("internal", "no_check"):
        return None

    clean_name = _strip_hash_suffix(event["file_name"])
    event_time = datetime.strptime(event["event_time"], "%Y-%m-%d %H:%M:%S")
    try:
        session, href = find_file_href(event["user_locator"], event_time, event["file_name"])
    except Exception as e:
        emit(f"Could not check for a saved file copy: {e}")
        return None

    if not href:
        emit("No saved copy of the sent file is available for content analysis.")
        return None

    emit("Found a saved copy of the sent file — downloading for content analysis…")
    try:
        raw_bytes = fetch_file_bytes(session, content_emp.BASE, href)
        with tempfile.NamedTemporaryFile(suffix=Path(clean_name).suffix) as tf:
            tf.write(raw_bytes)
            tf.flush()
            # event_verdicts never stored the raw destination URL (only app_desc) —
            # app_desc is a reasonable stand-in for the prompt's "Sent via: X (Y)"
            # slot (they're near-identical for report-215 rows in practice, e.g.
            # app_desc="web.whatsapp.com" vs the real destination_url
            # "https://web.whatsapp.com") until/unless that column gets added.
            assessment = content_analyze.analyze_sent_file(
                tf.name, clean_name, dest_app=event.get("app_desc", ""),
                dest_url=event.get("app_desc", ""),
                size_kb=event.get("size_kb", 0) or 0,
                on_progress=lambda stage: emit(f"Content analysis: {stage}"),
            )
        emit(f"Content analysis done: risk_score={assessment['risk_score']}, "
             f"recommended_action={assessment['recommended_action']}.")
        return assessment
    except Exception as e:
        emit(f"Content analysis failed: {e}")
        return None
