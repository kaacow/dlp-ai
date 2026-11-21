#!/usr/bin/env python3
"""Track B runner — pull treportfilesnd events for a time window, classify them with
the rule engine, and store verdicts in the local dlp_ai SQLite DB.

Usage:
  ./run_triage.py --hours 24        (default: last 24h)
  ./run_triage.py --date 2026-07-13 (a specific full day)
"""
import argparse
import sqlite3
import ntpath
from collections import Counter
from datetime import datetime, timedelta, date, timezone
from pathlib import Path
from urllib.parse import unquote

import emp_sql as k
from rule_engine import classify_event

DB_PATH = Path(__file__).parent.parent / "db" / "dlp_ai.sqlite3"
OLE_EPOCH = datetime(1899, 12, 30)


def to_ole(dt: datetime) -> float:
    return (dt - OLE_EPOCH).total_seconds() / 86400.0


def from_ole(ole: float) -> datetime:
    return OLE_EPOCH + timedelta(days=ole)


def load_baseline_index(conn):
    cur = conn.execute(
        "SELECT id, user_locator, destination, pattern_type, pattern_value FROM baseline_exceptions WHERE active=1;"
    )
    idx = {}
    for row in cur.fetchall():
        bid, user_locator, destination, pattern_type, pattern_value = row
        idx[(user_locator, destination)] = {"id": bid, "pattern_type": pattern_type, "pattern_value": pattern_value}
    return idx


def fetch_events(sess, ole_begin, ole_end):
    query = f"""
        SELECT row_auto_increment, user_locator, op_time, file_path, url, size_kb, app_desc, id_vocab
        FROM treportfilesnd
        WHERE op_time >= {ole_begin} AND op_time < {ole_end}
        ORDER BY op_time;
    """
    cols, rows, _ = k.run_sql(sess, query)
    events = [dict(zip(cols, r)) for r in rows]
    # file_path/url/app_desc are percent-encoded in the DB (unlike op_time, which the
    # report engine pre-formats) — decode once here so both the rule engine and
    # storage work off clean strings.
    for e in events:
        e["file_path"] = unquote(e.get("file_path") or "")
        e["url"] = unquote(e.get("url") or "")
    return events


def store_verdict(conn, event, classification):
    file_path = event.get("file_path") or ""  # already decoded by fetch_events()
    file_name = ntpath.basename(file_path)
    # The report engine already renders op_time as 'YYYY-MM-DD HH:MM:SS' (server-local
    # time) rather than a raw OLE float — use it as-is, no conversion needed here.
    event_dt_str = event["op_time"]
    conn.execute(
        """INSERT INTO event_verdicts
             (source_table, row_auto_increment, user_locator, event_time, file_path, file_name,
              size_kb, app_desc, destination_category, id_vocab, verdict, severity, reasoning, matched_rule)
           VALUES ('treportfilesnd', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(source_table, row_auto_increment) DO UPDATE SET
             destination_category=excluded.destination_category,
             verdict=excluded.verdict,
             severity=excluded.severity,
             reasoning=excluded.reasoning,
             matched_rule=excluded.matched_rule;""",
        (
            event["row_auto_increment"], event["user_locator"], event_dt_str,
            file_path, file_name, event.get("size_kb"), event.get("app_desc"),
            classification["destination_category"], event.get("id_vocab"),
            classification["verdict"], classification["severity"],
            classification["reasoning"], classification["matched_rule"],
        ),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=24, help="lookback window in hours (default 24)")
    ap.add_argument("--date", type=str, default=None, help="specific day YYYY-MM-DD instead of --hours")
    ap.add_argument("--limit-print", type=int, default=15, help="how many escalate examples to print")
    args = ap.parse_args()

    if args.date:
        d = date.fromisoformat(args.date)
        begin_dt = datetime(d.year, d.month, d.day)
        end_dt = begin_dt + timedelta(days=1)
    else:
        end_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        begin_dt = end_dt - timedelta(hours=args.hours)

    ole_begin, ole_end = to_ole(begin_dt), to_ole(end_dt)
    print(f"Fetching treportfilesnd events from {begin_dt} to {end_dt} (UTC, OLE {ole_begin:.4f}-{ole_end:.4f})...")

    sess = k.get_session()
    events = fetch_events(sess, ole_begin, ole_end)
    print(f"Fetched {len(events)} events")

    conn = sqlite3.connect(DB_PATH)
    baseline_index = load_baseline_index(conn)

    counts = Counter()
    dest_counts = Counter()
    escalate_examples = []

    for event in events:
        classification = classify_event(event, baseline_index)
        store_verdict(conn, event, classification)
        counts[classification["verdict"]] += 1
        dest_counts[classification["destination_category"]] += 1
        if classification["verdict"] == "escalate" and len(escalate_examples) < args.limit_print:
            escalate_examples.append((event, classification))

    conn.commit()
    conn.close()

    print("\n=== Verdict summary ===")
    total = sum(counts.values()) or 1
    for verdict in ["auto_clear", "baseline_match", "spot_check", "escalate"]:
        c = counts.get(verdict, 0)
        print(f"  {verdict:15s} {c:6d}  ({100*c/total:.1f}%)")

    print("\n=== Destination category breakdown ===")
    for cat, c in dest_counts.most_common():
        print(f"  {cat:25s} {c:6d}")

    if escalate_examples:
        print(f"\n=== Escalate examples (up to {args.limit_print}) ===")
        for event, classification in escalate_examples:
            fname = ntpath.basename(event.get("file_path") or "")
            print(f"  user_locator={event['user_locator']}  app_desc={event['app_desc']}  file={fname}")
            print(f"    -> {classification['reasoning']}")


if __name__ == "__main__":
    main()
