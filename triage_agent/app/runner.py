"""Orchestrates analysis work: either a bulk time-ranged pass (pull every
treportfilesnd event in a date range, classify with Track B, investigate whatever
escalates with Track C) or a single on-demand event investigation triggered from the
employee file-send report. Both run in background threads so the API can report live
progress instead of the caller blocking on a request.
"""
import json
import ntpath
import sqlite3
import threading
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

import emp_sql as k
import agent
import ollama_client
from rule_engine import classify_event

DB_PATH = Path(__file__).parent.parent / "db" / "dlp_ai.sqlite3"
OLE_EPOCH = datetime(1899, 12, 30)
BATCH_CAP = 20000  # max events processed per bulk run, to keep any single run bounded

_run_lock = threading.Lock()
_run_in_progress = False


def to_ole(dt: datetime) -> float:
    return (dt - OLE_EPOCH).total_seconds() / 86400.0


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def load_baseline_index(conn):
    cur = conn.execute("SELECT id, user_locator, destination, pattern_type, pattern_value FROM baseline_exceptions WHERE active=1;")
    idx = {}
    for row in cur.fetchall():
        idx[(row["user_locator"], row["destination"])] = dict(row)
    return idx


def sync_employees(sess, conn):
    """Refreshes the local `employees` table from tuserlocations (the real
    user_locator source — see schema.sql for why), LEFT JOIN tuserinfo for
    full_name/department. Cheap (~3000 rows), safe to call on every bulk run so the
    directory doesn't silently go stale as new devices log in.
    """
    cols, rows, _ = k.run_sql(sess, """
        SELECT tl.id AS user_locator, tl.user_domain, tl.user_name, tl.comp_name,
               ti.fio AS full_name, ti.department
        FROM tuserlocations tl
        LEFT JOIN tuserinfo ti ON ti.user_domain = tl.user_domain AND ti.user_name = tl.user_name;
    """)
    n = 0
    for r in rows:
        rec = dict(zip(cols, r))
        conn.execute(
            """INSERT INTO employees (user_locator, user_domain, user_name, comp_name, full_name, department, synced_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(user_locator) DO UPDATE SET
                 user_domain=excluded.user_domain, user_name=excluded.user_name,
                 comp_name=excluded.comp_name, full_name=excluded.full_name,
                 department=excluded.department, synced_at=excluded.synced_at;""",
            (rec["user_locator"], rec["user_domain"], rec["user_name"], rec["comp_name"], rec["full_name"], rec["department"]),
        )
        n += 1
    conn.commit()
    return n


def fetch_events_in_range(sess, begin_dt: datetime, end_dt: datetime, user_locator: int = None):
    begin_ole, end_ole = to_ole(begin_dt), to_ole(end_dt)
    user_filter = f"AND user_locator = {int(user_locator)}" if user_locator is not None else ""
    query = f"""
        SELECT row_auto_increment, user_locator, op_time, file_path, url, size_kb, app_desc, id_vocab
        FROM treportfilesnd
        WHERE op_time >= {begin_ole} AND op_time <= {end_ole} {user_filter}
        ORDER BY op_time
        LIMIT {BATCH_CAP};
    """
    cols, rows, _ = k.run_sql(sess, query)
    events = [dict(zip(cols, r)) for r in rows]
    for e in events:
        e["file_path"] = unquote(e.get("file_path") or "")
        e["url"] = unquote(e.get("url") or "")
    return events


def fetch_single_event(sess, row_auto_increment: int):
    query = f"""
        SELECT row_auto_increment, user_locator, op_time, file_path, url, size_kb, app_desc, id_vocab
        FROM treportfilesnd WHERE row_auto_increment = {int(row_auto_increment)};
    """
    cols, rows, _ = k.run_sql(sess, query)
    if not rows:
        return None
    event = dict(zip(cols, rows[0]))
    event["file_path"] = unquote(event.get("file_path") or "")
    event["url"] = unquote(event.get("url") or "")
    return event


def store_verdict(conn, event, classification):
    """Insert/refresh the Track B verdict for one event. Deliberately does NOT touch
    verdict/severity/reasoning/destination_category if the row has already been
    investigated by Track C (model_version IS NOT NULL) — otherwise re-viewing an
    employee's report or re-running an overlapping date range would silently revert
    a completed investigation back to the raw Track B bucket. matched_rule is
    excluded from that guard since it only records *why Track B originally flagged
    it*, which doesn't change.
    """
    file_name = ntpath.basename(event.get("file_path") or "")
    conn.execute(
        """INSERT INTO event_verdicts
             (source_table, row_auto_increment, user_locator, event_time, file_path, file_name,
              size_kb, app_desc, destination_category, id_vocab, verdict, severity, reasoning, matched_rule)
           VALUES ('treportfilesnd', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(source_table, row_auto_increment) DO UPDATE SET
             destination_category=excluded.destination_category,
             verdict=excluded.verdict, severity=excluded.severity,
             reasoning=excluded.reasoning, matched_rule=excluded.matched_rule
           WHERE event_verdicts.model_version IS NULL;""",
        (
            event["row_auto_increment"], event["user_locator"], event["op_time"],
            event["file_path"], file_name, event.get("size_kb"), event.get("app_desc"),
            classification["destination_category"], event.get("id_vocab"),
            classification["verdict"], classification["severity"],
            classification["reasoning"], classification["matched_rule"],
        ),
    )


def store_investigation(conn, source_table, row_auto_increment, user_locator, result, model_version):
    evidence_for_storage = agent.persist_and_strip_images(result["evidence_by_kind"], user_locator)
    conn.execute(
        """UPDATE event_verdicts SET
             verdict=?, severity=?, reasoning=?, screenshots_used=?, extra_queries=?,
             model_version=?, reviewed_at=datetime('now')
           WHERE source_table=? AND row_auto_increment=?;""",
        (
            result["verdict"], result["severity"], result["reasoning"],
            json.dumps(evidence_for_storage, ensure_ascii=False),
            json.dumps(result["extra_queries"], ensure_ascii=False),
            model_version, source_table, row_auto_increment,
        ),
    )


def _update_run(conn, run_id, **fields):
    set_clause = ", ".join(f"{k2}=?" for k2 in fields)
    conn.execute(f"UPDATE analysis_runs SET {set_clause} WHERE id=?;", (*fields.values(), run_id))
    conn.commit()


def run_analysis(begin_dt: datetime, end_dt: datetime):
    """Bulk pass over a time range, run in a background thread. Safe to re-run over
    an overlapping/identical range — see store_verdict's model_version guard."""
    global _run_in_progress
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO analysis_runs (status, begin_time, end_time) VALUES ('running', ?, ?);",
        (begin_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")),
    )
    run_id = cur.lastrowid
    conn.commit()

    try:
        sess = k.get_session()
        sync_employees(sess, conn)
        events = fetch_events_in_range(sess, begin_dt, end_dt)
        baseline_index = load_baseline_index(conn)

        events_pulled = 0
        events_escalated = 0
        events_investigated = 0
        max_row = 0

        escalated_events = []
        for event in events:
            classification = classify_event(event, baseline_index)
            store_verdict(conn, event, classification)
            conn.commit()
            events_pulled += 1
            max_row = max(max_row, event["row_auto_increment"])
            if classification["verdict"] == "escalate":
                events_escalated += 1
                escalated_events.append(event)
            if events_pulled % 50 == 0:
                _update_run(conn, run_id, events_pulled=events_pulled, events_escalated=events_escalated)

        _update_run(conn, run_id, events_pulled=events_pulled, events_escalated=events_escalated)

        for event in escalated_events:
            row = conn.execute(
                "SELECT * FROM event_verdicts WHERE source_table='treportfilesnd' AND row_auto_increment=?;",
                (event["row_auto_increment"],),
            ).fetchone()
            if row["model_version"] is not None:
                # already investigated in a previous overlapping run — don't redo it
                events_investigated += 1
                continue
            investigate_input = dict(row)
            try:
                result = agent.investigate_event(sess, investigate_input)
                store_investigation(conn, "treportfilesnd", event["row_auto_increment"], event["user_locator"], result, agent.REASONING_MODEL)
            except Exception as e:
                conn.execute(
                    "UPDATE event_verdicts SET reasoning=?, model_version='error' WHERE source_table='treportfilesnd' AND row_auto_increment=?;",
                    (f"Investigation failed: {e}", event["row_auto_increment"]),
                )
            conn.commit()
            events_investigated += 1
            _update_run(conn, run_id, events_investigated=events_investigated)

        _update_run(
            conn, run_id, status="done", finished_at=datetime.utcnow().isoformat(timespec="seconds"),
            events_pulled=events_pulled, events_escalated=events_escalated,
            events_investigated=events_investigated, high_water_mark=max_row,
        )
    except Exception as e:
        _update_run(
            conn, run_id, status="failed", error=f"{e}\n{traceback.format_exc()}",
            finished_at=datetime.utcnow().isoformat(timespec="seconds"),
        )
    finally:
        conn.close()
        with _run_lock:
            _run_in_progress = False


def start_run_if_idle(begin_dt: datetime, end_dt: datetime):
    """Returns True if a run was started, False if one was already in progress."""
    global _run_in_progress
    with _run_lock:
        if _run_in_progress:
            return False
        _run_in_progress = True
    thread = threading.Thread(target=run_analysis, args=(begin_dt, end_dt), daemon=True)
    thread.start()
    return True


# ---------------------------------------------------------------------------
# On-demand single-event investigation ("Analyze event" button, item 3)
# ---------------------------------------------------------------------------

# job_id -> threading.Event, so a "Stop" click from the API can actually reach the
# thread doing the work. See ollama_client.py for why setting this event genuinely
# stops GPU inference (closes the streaming connection) rather than just abandoning
# interest in the result — the earlier version of "Cancel" only did the latter,
# which the user caught by noticing GPU usage stayed high after clicking it.
_job_cancel_events = {}


def cancel_job(job_id) -> bool:
    """Returns True if a running job was found and told to stop."""
    event = _job_cancel_events.get(job_id)
    if event is None:
        return False
    event.set()
    return True


def _append_job_step(conn, job_id, step):
    row = conn.execute("SELECT steps_json FROM investigation_jobs WHERE id=?;", (job_id,)).fetchone()
    steps = json.loads(row["steps_json"]) if row else []
    steps.append({"time": datetime.utcnow().strftime("%H:%M:%S"), "step": step})
    conn.execute("UPDATE investigation_jobs SET steps_json=? WHERE id=?;", (json.dumps(steps, ensure_ascii=False), job_id))
    conn.commit()


def run_analyze_job(job_id, row_auto_increment, user_locator, reasoning_model=None, vision_model=None):
    """Runs a single event through Track B + Track C, always (regardless of what
    Track B's verdict is) since this is an explicit "investigate this one" request.
    Updates investigation_jobs with a live step log as it goes.
    """
    conn = get_connection()
    # registered in start_analyze_job *before* this thread starts, so a cancel
    # click that arrives in the first instant of the job is never silently missed
    cancel_event = _job_cancel_events[job_id]
    try:
        sess = k.get_session()
        _append_job_step(conn, job_id, "Fetching event details from DLP…")
        event = fetch_single_event(sess, row_auto_increment)
        if not event:
            raise RuntimeError(f"row_auto_increment={row_auto_increment} not found in treportfilesnd")

        baseline_index = load_baseline_index(conn)
        classification = classify_event(event, baseline_index)
        _append_job_step(conn, job_id, f"Rule engine: {classification['verdict']} ({classification['reasoning']})")
        store_verdict(conn, event, classification)
        conn.commit()

        def on_progress(msg):
            _append_job_step(conn, job_id, msg)

        investigate_input = {
            **event, **classification,
            "event_time": event["op_time"], "file_name": ntpath.basename(event["file_path"]),
        }
        result = agent.investigate_event(sess, investigate_input, on_progress=on_progress,
                                          reasoning_model=reasoning_model, vision_model=vision_model,
                                          cancel_event=cancel_event)
        model_label = reasoning_model or agent.REASONING_MODEL
        store_investigation(conn, "treportfilesnd", row_auto_increment, user_locator, result, model_label)
        conn.commit()

        verdict_row = conn.execute(
            "SELECT id FROM event_verdicts WHERE source_table='treportfilesnd' AND row_auto_increment=?;",
            (row_auto_increment,),
        ).fetchone()
        conn.execute(
            "UPDATE investigation_jobs SET status='done', finished_at=datetime('now'), event_verdict_id=? WHERE id=?;",
            (verdict_row["id"] if verdict_row else None, job_id),
        )
        conn.commit()
    except ollama_client.Cancelled:
        _append_job_step(conn, job_id, "Stopped by user.")
        conn.execute(
            "UPDATE investigation_jobs SET status='cancelled', finished_at=datetime('now') WHERE id=?;",
            (job_id,),
        )
        conn.commit()
    except Exception as e:
        conn.execute(
            "UPDATE investigation_jobs SET status='failed', finished_at=datetime('now'), error=? WHERE id=?;",
            (f"{e}\n{traceback.format_exc()}", job_id),
        )
        conn.commit()
    finally:
        conn.close()
        _job_cancel_events.pop(job_id, None)


def start_analyze_job(row_auto_increment, user_locator, reasoning_model=None, vision_model=None):
    """Creates an investigation_jobs row and starts the work in a background thread.
    Returns the job id immediately so the caller can poll it."""
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO investigation_jobs (row_auto_increment, user_locator, reasoning_model, vision_model) VALUES (?, ?, ?, ?);",
        (row_auto_increment, user_locator, reasoning_model, vision_model),
    )
    job_id = cur.lastrowid
    conn.commit()
    conn.close()

    _job_cancel_events[job_id] = threading.Event()
    thread = threading.Thread(
        target=run_analyze_job, args=(job_id, row_auto_increment, user_locator, reasoning_model, vision_model), daemon=True,
    )
    thread.start()
    return job_id
