"""Secret Scanner — pulls the "Files sent by user" report (ReportId=215) for a
time range, scans any code file that has a server-side saved copy for hardcoded
secrets using a local code model, and shows the results.

Ported from the standalone content_scan app (former port 8421); logic unchanged,
routes now live under /api/secrets/* behind the console's shared auth.
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path

import requests
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from . import runner

DB_PATH = Path("./data/db/content_scan.sqlite3")

router = APIRouter(prefix="/api/secrets", tags=["secrets"])


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def parse_dt(s: str) -> datetime:
    s = s.replace("T", " ")
    if len(s) == 10:
        s += " 00:00:00"
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def init_db():
    runner.init_db()


@router.post("/runs")
def trigger_run(begin: str, end: str, location_ids: str = ""):
    try:
        begin_dt, end_dt = parse_dt(begin), parse_dt(end)
    except ValueError:
        raise HTTPException(400, "begin/end must be 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'")
    run_id = runner.start_run_if_idle(begin_dt, end_dt, location_ids.strip())
    if run_id is None:
        return JSONResponse({"started": False, "message": "a scan is already in progress"}, status_code=409)
    return {"started": True, "run_id": run_id}


@router.get("/runs")
def list_runs(limit: int = Query(20, le=100)):
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?;", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/runs/{run_id}")
def get_run(run_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM scan_runs WHERE id = ?;", (run_id,)).fetchone()
        if not row:
            raise HTTPException(404, "run not found")
        return dict(row)
    finally:
        conn.close()


@router.get("/files")
def list_files(
    run_id: int | None = None,
    begin: str | None = None,
    end: str | None = None,
    severity: str | None = None,
    scan_status: str | None = None,
    search: str | None = None,
    limit: int = Query(50, le=5000),
    offset: int = 0,
):
    """begin/end (event_time range) exist alongside run_id for the same reason as
    mail's list_events: a file already recorded by an earlier overlapping run
    keeps that run's id, so filtering strictly by run_id can hide files a
    schedule-date-range view expects to see. The default schedule view uses
    begin/end; the manual "pick a range and Generate" flow uses run_id."""
    conn = get_connection()
    try:
        where, params = [], []
        if run_id is not None:
            where.append("run_id = ?")
            params.append(run_id)
        if begin:
            where.append("event_time >= ?")
            params.append(begin)
        if end:
            where.append("event_time <= ?")
            params.append(end)
        if severity:
            where.append("max_severity = ?")
            params.append(severity)
        if scan_status:
            where.append("scan_status = ?")
            params.append(scan_status)
        if search:
            where.append("(file_name LIKE ? OR destination_app LIKE ? OR user_locator_raw LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""

        total = conn.execute(f"SELECT COUNT(*) c FROM scan_files {where_sql};", params).fetchone()["c"]
        rows = conn.execute(
            f"""SELECT id, run_id, user_locator_raw, event_time, file_name, file_type,
                       destination_app, size_kb, scan_status, max_severity, model_version,
                       COALESCE(json_array_length(findings_json), 0) AS finding_count
                FROM scan_files {where_sql}
                ORDER BY event_time DESC LIMIT ? OFFSET ?;""",
            params + [limit, offset],
        ).fetchall()
        return {"total": total, "limit": limit, "offset": offset, "files": [dict(r) for r in rows]}
    finally:
        conn.close()


@router.get("/files/{file_id}")
def get_file(file_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM scan_files WHERE id = ?;", (file_id,)).fetchone()
        if not row:
            raise HTTPException(404, "file not found")
        d = dict(row)
        d["findings"] = json.loads(d.pop("findings_json") or "[]")
        return d
    finally:
        conn.close()


@router.get("/models")
def list_models():
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        resp.raise_for_status()
        return [{"name": m["name"], "size": m["size"]} for m in resp.json().get("models", [])]
    except Exception:
        return []
