"""Backfill script for content_labels — pulls doc-type file-send events from the
last 6 days that have real saved content (ReportId=215 href), stratified across
(day, file extension) so the first labeling batch isn't dominated by one day or one
file type, capped at MAX_TOTAL events, and scores each through content_label_seed.py
(content-ONLY judgment, no destination ever passed in).

Resumable by design: source_event_id is UNIQUE in content_labels, and this script
queries existing ids first and excludes them from the candidate pool before doing
any download/AI work — re-running after an interruption picks up where it left off
rather than re-spending GPU time on already-labeled files. Uses svc_reports (via
content_emp.py, switched from svc_readonly on 2026-08-24) so this can pull real content
for ANY employee, not just the one svc_readonly was scoped to.

Run with: venv/bin/python backfill_content_labels.py
"""
import json
import random
import sqlite3
import sys
import tempfile
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path

import content_emp
import content_label_seed
from content_extract import DOC_EXTS, LEGACY_CONVERT_EXTS, SessionExpiredError
from file_fetch import fetch_file_bytes
from report_filesend import generate_filesend_report, parse_filesend_rows

DB_PATH = Path(__file__).parent.parent / "db" / "dlp_ai.sqlite3"
LOOKBACK_DAYS = 6
MAX_TOTAL = 400
RNG_SEED = 42  # reproducible stratified sample, not cherry-picked

DOC_TYPE_EXTS = DOC_EXTS | set(LEGACY_CONVERT_EXTS.keys())  # pdf/docx/xlsx/xls/xlsm/pptx + doc/rtf/odt/ppt

# A ~5.6-hour first run of this script had its single EMP session (created
# once at start) expire partway through — confirmed live 2026-08-25, see
# content_extract.py's SessionExpiredError docstring for the full mechanism. This
# loop now refreshes the session and retries once on that specific error, rather
# than either silently accepting the placeholder as real content or permanently
# failing every remaining row for the rest of a long run.
MAX_DOWNLOAD_ATTEMPTS = 2


def download_and_label(session_holder: dict, href: str, file_type: str, file_name: str):
    """session_holder is a single-key {'session': ...} dict rather than a plain
    variable so a refreshed session (created on retry) is visible to the caller
    without needing `nonlocal`/return-value plumbing through the retry loop."""
    last_error = None
    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        try:
            raw_bytes = fetch_file_bytes(session_holder["session"], content_emp.BASE, href)
            with tempfile.NamedTemporaryFile(suffix=file_type) as tf:
                tf.write(raw_bytes)
                tf.flush()
                return content_label_seed.label_file_content(tf.name, file_name)
        except SessionExpiredError as e:
            last_error = e
            if attempt < MAX_DOWNLOAD_ATTEMPTS:
                print("    EMP session expired mid-run — refreshing and retrying once...", flush=True)
                session_holder["session"] = content_emp.get_session()
    raise last_error


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def make_source_event_id(user: str, event_time: str, file_name: str) -> str:
    return f"{user}|{event_time}|{file_name}"


def fetch_candidates(session):
    """Returns dict[(day_str, ext)] -> list of row dicts, doc-type only, with a
    saved copy, across the last LOOKBACK_DAYS days."""
    today = datetime.now()
    buckets = {}
    for i in range(LOOKBACK_DAYS):
        day = today - timedelta(days=i)
        day_str = day.strftime("%Y-%m-%d")
        payload = generate_filesend_report(session, content_emp.BASE, "", day, day)
        rows = parse_filesend_rows(payload)
        for r in rows:
            if not r["file_href"]:
                continue
            ext = r["file_type"]
            if ext not in DOC_TYPE_EXTS:
                continue
            buckets.setdefault((day_str, ext), []).append(r)
        print(f"  {day_str}: {len(rows)} total rows seen, running doc-type-with-copy bucket count so far: "
              f"{sum(len(v) for k, v in buckets.items() if k[0] == day_str)}")
    return buckets


def stratified_sample(buckets: dict, exclude_ids: set, max_total: int, rng: random.Random):
    """Round-robins across (day, ext) buckets so the sample spreads across both
    dimensions rather than being dominated by whichever bucket is largest — each
    bucket is shuffled once (fixed seed) then consumed one at a time in rotation,
    skipping rows already in content_labels and buckets that run dry."""
    shuffled = {}
    for key, rows in buckets.items():
        fresh = [r for r in rows if make_source_event_id(r["user"], r["event_time"],
                                                           Path(r["file_display_path"].replace("\\", "/")).name) not in exclude_ids]
        rng.shuffle(fresh)
        if fresh:
            shuffled[key] = fresh

    selected = []
    keys = list(shuffled.keys())
    idx = 0
    while keys and len(selected) < max_total:
        key = keys[idx % len(keys)]
        bucket = shuffled[key]
        if bucket:
            selected.append(bucket.pop())
        if not bucket:
            keys.remove(key)
            if not keys:
                break
            idx %= max(len(keys), 1)
            continue
        idx += 1
    return selected[:max_total]


def main():
    conn = get_connection()
    existing = {row["source_event_id"] for row in conn.execute("SELECT source_event_id FROM content_labels;")}
    print(f"Already in content_labels: {len(existing)} rows — these will be skipped.")

    session = content_emp.get_session()

    print(f"Fetching report-215 candidates across the last {LOOKBACK_DAYS} days (all locations, svc_reports)...")
    buckets = fetch_candidates(session)
    total_candidates = sum(len(v) for v in buckets.values())
    print(f"\nTotal doc-type-with-saved-copy candidates found: {total_candidates}, across {len(buckets)} (day, ext) buckets")
    for (day, ext), rows in sorted(buckets.items()):
        print(f"    {day} {ext:8} {len(rows)}")

    rng = random.Random(RNG_SEED)
    sample = stratified_sample(buckets, existing, MAX_TOTAL, rng)
    print(f"\nStratified sample selected: {len(sample)} events (cap {MAX_TOTAL})")
    from collections import Counter
    by_day = Counter(r["event_time"][:10] for r in sample)
    by_ext = Counter(r["file_type"] for r in sample)
    print(f"  by day: {dict(sorted(by_day.items()))}")
    print(f"  by ext: {dict(sorted(by_ext.items()))}")

    ok = failed = 0
    session_holder = {"session": session}
    t_start = time.monotonic()
    for i, row in enumerate(sample, 1):
        file_name = Path(row["file_display_path"].replace("\\", "/")).name
        source_event_id = make_source_event_id(row["user"], row["event_time"], file_name)
        t0 = time.monotonic()
        print(f"\n[{i}/{len(sample)}] {row['event_time']} {file_name} ({row['file_type']}, {row['size_kb']}KB)", flush=True)
        try:
            result = download_and_label(session_holder, row["file_href"], row["file_type"], file_name)

            conn.execute(
                """INSERT OR IGNORE INTO content_labels
                     (source_event_id, file_name, file_path, event_date, extracted_text_ref,
                      is_doc_type, model_is_confidential, model_risk_score, model_categories,
                      model_related_to_company, model_company_relevance_reasoning,
                      model_summary, model_reasoning)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?);""",
                (
                    source_event_id, file_name, row["file_display_path"], row["event_time"][:10],
                    result["extracted_text_full"],
                    int(result["is_confidential"]), result["risk_score"],
                    json.dumps(result["categories"], ensure_ascii=False),
                    int(result["related_to_company"]), result["company_relevance_reasoning"],
                    result["summary"], result["reasoning"],
                ),
            )
            conn.commit()
            ok += 1
            elapsed = time.monotonic() - t0
            print(f"    -> risk_score={result['risk_score']} confidential={result['is_confidential']} "
                  f"related_to_company={result['related_to_company']} ({elapsed:.0f}s)", flush=True)
        except Exception as e:
            failed += 1
            print(f"    ERROR: {e}\n{traceback.format_exc()[-800:]}", flush=True)

        if i % 10 == 0:
            total_elapsed = time.monotonic() - t_start
            print(f"--- progress: {i}/{len(sample)} done ({ok} ok, {failed} failed), "
                  f"{total_elapsed/60:.1f}min elapsed, ~{(total_elapsed/i)*(len(sample)-i)/60:.1f}min remaining ---", flush=True)

    total_elapsed = time.monotonic() - t_start
    print(f"\n=== DONE: {ok} labeled, {failed} failed, {total_elapsed/60:.1f} minutes total ===")
    final_count = conn.execute("SELECT COUNT(*) c FROM content_labels;").fetchone()["c"]
    print(f"content_labels total row count now: {final_count}")
    conn.close()


if __name__ == "__main__":
    main()
