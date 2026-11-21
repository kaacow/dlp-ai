import sqlite3
import json
import statistics
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path("./data")  # fresh DB per the merge plan (old standalone file_analyzer DB was test-only)
DB_PATH = BASE_DIR / "db" / "file_analyzer.sqlite3"
SCHEMA_PATH = BASE_DIR / "db" / "file_analyzer_schema.sql"


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    conn.executescript(SCHEMA_PATH.read_text())
    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def create_job(conn, total_files, save_to_history):
    cur = conn.execute(
        "INSERT INTO jobs (created_at, status, total_files, completed_files, save_to_history, steps_json) "
        "VALUES (?, 'running', ?, 0, ?, '[]')",
        (now_iso(), total_files, 1 if save_to_history else 0),
    )
    conn.commit()
    return cur.lastrowid


def append_job_step(conn, job_id, message):
    row = conn.execute("SELECT steps_json FROM jobs WHERE id = ?", (job_id,)).fetchone()
    steps = json.loads(row["steps_json"]) if row else []
    steps.append({"t": now_iso(), "msg": message})
    conn.execute("UPDATE jobs SET steps_json = ? WHERE id = ?", (json.dumps(steps), job_id))
    conn.commit()


def set_job_progress(conn, job_id, completed_files):
    conn.execute("UPDATE jobs SET completed_files = ? WHERE id = ?", (completed_files, job_id))
    conn.commit()


def finish_job(conn, job_id, status, error=None):
    conn.execute("UPDATE jobs SET status = ?, error = ? WHERE id = ?", (status, error, job_id))
    conn.commit()


def get_job(conn, job_id):
    job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not job:
        return None
    scans = conn.execute(
        "SELECT * FROM scans WHERE job_id = ? ORDER BY id", (job_id,)
    ).fetchall()
    result = dict(job)
    result["steps"] = json.loads(result.pop("steps_json"))
    result["scans"] = [scan_to_dict(s) for s in scans]
    return result


def scan_to_dict(row):
    d = dict(row)
    d["categories"] = json.loads(d.pop("categories_json") or "[]")
    d["related_entities"] = json.loads(d.pop("related_entities_json") or "[]")
    d["company_keywords_found"] = json.loads(d.pop("company_keywords_found_json") or "[]")
    d["is_confidential"] = bool(d["is_confidential"]) if d["is_confidential"] is not None else None
    d["related_to_company"] = bool(d["related_to_company"]) if d["related_to_company"] is not None else None
    d["used_vision"] = bool(d["used_vision"])
    d["truncated"] = bool(d["truncated"])
    d["saved_to_history"] = bool(d["saved_to_history"])
    return d


def insert_scan(conn, job_id, filename, file_ext, file_size, sha256, save_to_history, instructions="", depth="thorough"):
    cur = conn.execute(
        "INSERT INTO scans (job_id, created_at, filename, file_ext, file_size, sha256, saved_to_history, analyst_instructions, analysis_depth) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (job_id, now_iso(), filename, file_ext, file_size, sha256, 1 if save_to_history else 0, instructions or None, depth),
    )
    conn.commit()
    return cur.lastrowid


def update_scan_result(conn, scan_id, result):
    conn.execute(
        """UPDATE scans SET
            used_vision = ?, model_used = ?, is_confidential = ?, risk_score = ?,
            categories_json = ?, related_entities_json = ?, summary = ?, reasoning = ?,
            recommended_action = ?, extracted_text = ?, truncated = ?, completed_at = ?,
            related_to_company = ?, company_relevance_reasoning = ?, company_keywords_found_json = ?,
            segment_count = ?
        WHERE id = ?""",
        (
            1 if result.get("used_vision") else 0,
            result.get("model_used"),
            1 if result.get("is_confidential") else 0,
            result.get("risk_score"),
            json.dumps(result.get("categories", [])),
            json.dumps(result.get("related_entities", [])),
            result.get("summary"),
            result.get("reasoning"),
            result.get("recommended_action"),
            result.get("extracted_text_preview"),
            1 if result.get("truncated") else 0,
            now_iso(),
            1 if result.get("related_to_company") else 0,
            result.get("company_relevance_reasoning"),
            json.dumps(result.get("company_keywords_found", [])),
            result.get("segment_count"),
            scan_id,
        ),
    )
    conn.commit()


def update_scan_error(conn, scan_id, error):
    conn.execute("UPDATE scans SET error = ?, completed_at = ? WHERE id = ?", (error, now_iso(), scan_id))
    conn.commit()


def get_avg_scan_duration(conn, limit=20, default=75.0):
    """Typical duration of recent successful scans, in seconds — used to estimate
    progress/ETA for a scan currently in flight. Uses the median rather than the
    mean: large documents now get analyzed in multiple segments and can take
    several minutes, and a single such outlier shouldn't drag the ETA estimate for
    every subsequent normal-sized file far off course. Falls back to a reasonable
    default when there's no history yet (fresh install, or DB just wiped)."""
    rows = conn.execute(
        """SELECT (julianday(completed_at) - julianday(created_at)) * 86400.0 AS secs
           FROM scans
           WHERE completed_at IS NOT NULL AND error IS NULL AND risk_score IS NOT NULL
           ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    durations = [r["secs"] for r in rows if r["secs"] and r["secs"] > 0]
    if not durations:
        return default
    return statistics.median(durations)


def delete_scans_not_saved(conn, job_id):
    conn.execute("DELETE FROM scans WHERE job_id = ? AND saved_to_history = 0", (job_id,))
    conn.commit()


def list_history(conn, limit=50, offset=0, min_score=None, related_to_company=None):
    where = "WHERE saved_to_history = 1"
    params = []
    if min_score is not None:
        where += " AND risk_score >= ?"
        params.append(min_score)
    if related_to_company is not None:
        where += " AND related_to_company = ?"
        params.append(1 if related_to_company else 0)

    rows = conn.execute(
        f"SELECT * FROM scans {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    total = conn.execute(f"SELECT COUNT(*) c FROM scans {where}", params).fetchone()["c"]
    return [scan_to_dict(r) for r in rows], total


def get_scan(conn, scan_id):
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return scan_to_dict(row) if row else None


def delete_scan(conn, scan_id):
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()


def insert_chat_message(conn, scan_id, role, content):
    conn.execute(
        "INSERT INTO chat_messages (scan_id, created_at, role, content) VALUES (?, ?, ?, ?)",
        (scan_id, now_iso(), role, content),
    )
    conn.commit()


def list_chat_messages(conn, scan_id):
    rows = conn.execute(
        "SELECT role, content, created_at FROM chat_messages WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    ).fetchall()
    return [dict(r) for r in rows]
