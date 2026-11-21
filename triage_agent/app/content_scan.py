"""Orchestrates the new content-based DLP pipeline: pull the "Files sent" report
(ReportId=215, via report_filesend.py) for a time range + location scope, skip
destinations already trusted as internal (destinations.py — same table Track B's
rule engine uses, so "internal" here means exactly what it already means everywhere
else in this app), download the actual sent-file bytes for everything else, and run
each through content_analyze.py's AI risk assessment.

This deliberately does NOT restrict to code-file extensions the way Track D
(content_scan/ — hardcoded-secret scanning) does — every file type File Analyzer's
extractor supports is in scope, because the judgment call here is general DLP risk,
not secrets specifically.
"""
import tempfile
import time
import traceback
from datetime import datetime
from pathlib import Path

import content_emp
import content_analyze
from destinations import classify_destination
from file_fetch import fetch_file_bytes
from report_filesend import generate_filesend_report, parse_filesend_rows


def scan_range(begin_dt: datetime, end_dt: datetime, location_ids: str = "", on_event=None):
    """Runs the full pipeline for one time range. Returns a list of per-file result
    dicts (one per row seen in the report, whether skipped/scanned/failed). If given,
    on_event(stage, row) is called as each file starts/finishes for live progress."""
    def report(stage, row=None):
        if on_event:
            on_event(stage, row)

    session = content_emp.get_session()
    report("fetching report 215")
    payload = generate_filesend_report(session, content_emp.BASE, location_ids, begin_dt, end_dt)
    rows = parse_filesend_rows(payload)

    results = []
    for row in rows:
        t0 = time.monotonic()
        dest_category = classify_destination(row["app_desc"], row.get("destination_url", ""))
        entry = {
            "user": row["user"],
            "event_time": row["event_time"],
            "file_display_path": row["file_display_path"],
            "file_name": Path(row["file_display_path"].replace("\\", "/")).name,
            "file_type": row["file_type"],
            "size_kb": row["size_kb"],
            "app_desc": row["app_desc"],
            "destination_url": row.get("destination_url"),
            "destination_category": dest_category,
            "content_fetched": False,
            "elapsed_seconds": None,
            "error": None,
        }

        if dest_category in ("internal", "no_check"):
            entry["status"] = "skipped_internal" if dest_category == "internal" else "skipped_no_check"
            results.append(entry)
            continue

        if not row["file_href"]:
            entry["status"] = "skipped_no_saved_copy"
            results.append(entry)
            continue

        report("downloading", entry)
        try:
            raw_bytes = fetch_file_bytes(session, content_emp.BASE, row["file_href"])
        except Exception as e:
            entry["status"] = "error_download"
            entry["error"] = str(e)
            entry["elapsed_seconds"] = round(time.monotonic() - t0, 1)
            results.append(entry)
            continue

        entry["content_fetched"] = True
        entry["downloaded_bytes"] = len(raw_bytes)

        report("analyzing", entry)
        try:
            with tempfile.NamedTemporaryFile(suffix=entry["file_type"] or "") as tf:
                tf.write(raw_bytes)
                tf.flush()
                assessment = content_analyze.analyze_sent_file(
                    tf.name, entry["file_name"],
                    dest_app=row["app_desc"], dest_url=row.get("destination_url") or "",
                    size_kb=row["size_kb"],
                    on_progress=lambda stage, e=entry: report(f"analyzing: {stage}", e),
                )
            entry["status"] = "analyzed"
            entry["assessment"] = assessment
        except Exception as e:
            entry["status"] = "error_analysis"
            entry["error"] = f"{e}\n{traceback.format_exc()[-1500:]}"

        entry["elapsed_seconds"] = round(time.monotonic() - t0, 1)
        results.append(entry)
        report("done", entry)

    return results
