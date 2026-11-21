"""Mail self-exfiltration detector — two sub-detectors: corporate self-send
correlation (EMP "Mails" report, ReportId=217) and a Playwright-automated
Exchange webmail scraper for gmail.com/mail.ru personal-domain sends.

Ported from the standalone mail_exfil app (former port 8422); logic unchanged,
routes now live under /api/mail/* and /api/exchange/* behind the console's
shared auth — except /api/exchange/runs/auto, which stays public for the daily
cron trigger (see main.py's PUBLIC_API_EXACT_EXTRA).
"""
import sqlite3
from datetime import date, datetime
from pathlib import Path

import requests
from fastapi import APIRouter, File, Form, HTTPException, Query, Request, Response, UploadFile

from . import analyzer
from . import dlp_correlate
from . import emp_sql as k
from . import msg_fetch
from . import runner
from . import runner_exchange
from .domains import PERSONAL_WATCH_DOMAINS
from .locations import list_users

DB_PATH = Path("./data/db/mail_detector.sqlite3")

router = APIRouter(tags=["mail"])

_SORT_COLUMNS = {
    "time": "event_time",
    "sender": "COALESCE(NULLIF(sender_fullname, ''), sender_username)",
    "match": "match_type",
    "score": "similarity_score",
    "recipient": "recipient_email",
    "subject": "subject",
    "summary": "ai_summary",
}
_EXCHANGE_SORT_COLUMNS = {
    "time": "event_time",
    "sender": "COALESCE(NULLIF(sender_fullname, ''), sender_address)",
    "recipient": "recipient_address",
    "score": "similarity_score",
    "subject": "subject",
    "status": "dlp_status",
    "summary": "ai_summary",
}


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


@router.post("/api/mail/runs")
def trigger_run(begin: str, end: str, location_ids: str = "", threshold: float = 0.5):
    try:
        begin_dt, end_dt = parse_dt(begin), parse_dt(end)
    except ValueError:
        raise HTTPException(400, "begin/end must be 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'")
    run_id = runner.start_run_if_idle(begin_dt, end_dt, location_ids.strip(), threshold, mode="manual")
    if run_id is None:
        return Response(status_code=409, content='{"started": false, "message": "a run is already in progress"}', media_type="application/json")
    return {"started": True, "run_id": run_id}


@router.post("/api/mail/runs/auto")
def trigger_auto_run():
    run_id = runner.start_auto_run()
    if run_id is None:
        return Response(status_code=409, content='{"started": false, "message": "a run is already in progress"}', media_type="application/json")
    return {"started": True, "run_id": run_id}


@router.get("/api/mail/runs")
def list_runs(limit: int = Query(20, le=100), mode: str | None = None):
    conn = get_connection()
    try:
        if mode:
            rows = conn.execute("SELECT * FROM mail_runs WHERE mode = ? ORDER BY id DESC LIMIT ?;", (mode, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM mail_runs ORDER BY id DESC LIMIT ?;", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/api/mail/runs/{run_id}")
def get_run(run_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM mail_runs WHERE id = ?;", (run_id,)).fetchone()
        if not row:
            raise HTTPException(404, "run not found")
        return dict(row)
    finally:
        conn.close()


@router.get("/api/mail/events")
def list_events(
    run_id: int | None = None,
    begin: str | None = None,
    end: str | None = None,
    match_type: str | None = None,
    search: str | None = None,
    sort: str = "time",
    dir: str = "desc",
    limit: int = Query(50, le=5000),
    offset: int = 0,
):
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
        if match_type:
            where.append("match_type = ?")
            params.append(match_type)
        if search:
            where.append("(sender_username LIKE ? OR sender_fullname LIKE ? OR recipient_email LIKE ? OR subject LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like, like]
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        sort_col = _SORT_COLUMNS.get(sort, "event_time")
        sort_dir = "ASC" if dir.lower() == "asc" else "DESC"

        total = conn.execute(f"SELECT COUNT(*) c FROM mail_events {where_sql};", params).fetchone()["c"]
        rows = conn.execute(
            f"""SELECT * FROM mail_events {where_sql}
                ORDER BY {sort_col} {sort_dir}, id {sort_dir} LIMIT ? OFFSET ?;""",
            params + [limit, offset],
        ).fetchall()
        return {"total": total, "limit": limit, "offset": offset, "events": [dict(r) for r in rows]}
    finally:
        conn.close()


@router.get("/api/mail/events/{event_id}")
def get_event(event_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM mail_events WHERE id = ?;", (event_id,)).fetchone()
        if not row:
            raise HTTPException(404, "event not found")
        return dict(row)
    finally:
        conn.close()


@router.get("/api/mail/events/{event_id}/download")
def download_event(event_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT msg_href, event_time FROM mail_events WHERE id = ?;", (event_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "event not found")
    if not row["msg_href"]:
        raise HTTPException(404, "no saved .msg copy for this mail")

    sess = k.get_session()
    try:
        raw = msg_fetch.fetch_mail_bytes(sess, row["msg_href"])
    except Exception as e:
        raise HTTPException(502, f"could not fetch .msg from DLP server: {e}")

    filename = f"mail_{event_id}_{(row['event_time'] or '').replace(' ', '_').replace(':', '-')}.msg"
    return Response(
        content=raw,
        media_type="application/vnd.ms-outlook",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/mail/locations")
def get_locations():
    sess = k.get_session()
    try:
        users = list_users(sess)
    except Exception as e:
        raise HTTPException(502, f"could not fetch locations from DLP server: {e}")
    return {"users": users}


@router.get("/api/mail/models")
def list_models():
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        resp.raise_for_status()
        return [{"name": m["name"], "size": m["size"]} for m in resp.json().get("models", [])]
    except Exception:
        return []


def _parse_day(s: str) -> date:
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(400, "day must be 'YYYY-MM-DD'")


def _check_domain(domain: str):
    if domain not in PERSONAL_WATCH_DOMAINS:
        raise HTTPException(400, f"domain must be one of {PERSONAL_WATCH_DOMAINS}")


@router.post("/api/exchange/runs")
def trigger_exchange_run(domain: str, begin_day: str, end_day: str | None = None, threshold: float = 0.5):
    _check_domain(domain)
    begin = _parse_day(begin_day)
    end = _parse_day(end_day) if end_day else begin
    if end < begin:
        raise HTTPException(400, "end_day must not be before begin_day")
    started = runner_exchange.start_range_run_exchange(domain, begin, end, threshold)
    if not started:
        return Response(status_code=409, content='{"started": false, "message": "a run is already in progress"}', media_type="application/json")
    return {"started": True, "domain": domain, "begin_day": str(begin), "end_day": str(end)}


@router.post("/api/exchange/runs/upload")
async def upload_exchange_run(domain: str = Form(...), day: str = Form(...), threshold: float = Form(0.5), file: UploadFile = File(...)):
    _check_domain(domain)
    day_parsed = _parse_day(day)
    csv_bytes = await file.read()
    started = runner_exchange.ingest_uploaded_csv(domain, day_parsed, csv_bytes, threshold)
    if not started:
        return Response(status_code=409, content='{"started": false, "message": "a run is already in progress"}', media_type="application/json")
    return {"started": True, "domain": domain, "day": str(day_parsed)}


@router.post("/api/exchange/runs/auto")
def trigger_exchange_auto_run():
    """Public (no auth) — see main.py's PUBLIC_API_EXACT_EXTRA. This is the daily
    07:00 cron trigger; a plain crontab curl has no session cookie to send, and
    this endpoint only starts a scheduled scan (no data exposure)."""
    started = runner_exchange.start_auto_run_exchange()
    if not started:
        return Response(status_code=409, content='{"started": false, "message": "a run is already in progress"}', media_type="application/json")
    return {"started": True}


@router.get("/api/exchange/runs")
def list_exchange_runs(domain: str | None = None, limit: int = Query(20, le=100)):
    conn = get_connection()
    try:
        if domain:
            rows = conn.execute("SELECT * FROM exchange_runs WHERE domain = ? ORDER BY id DESC LIMIT ?;", (domain, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM exchange_runs ORDER BY id DESC LIMIT ?;", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/api/exchange/runs/{run_id}")
def get_exchange_run(run_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM exchange_runs WHERE id = ?;", (run_id,)).fetchone()
        if not row:
            raise HTTPException(404, "run not found")
        return dict(row)
    finally:
        conn.close()


@router.get("/api/exchange/status")
def exchange_status():
    conn = get_connection()
    try:
        out = {}
        for domain in PERSONAL_WATCH_DOMAINS:
            row = conn.execute(
                "SELECT * FROM exchange_runs WHERE domain = ? ORDER BY id DESC LIMIT 1;", (domain,)
            ).fetchone()
            out[domain] = dict(row) if row else None
        return out
    finally:
        conn.close()


@router.get("/api/exchange/events")
def list_exchange_events(
    domain: str | None = None,
    run_id: int | None = None,
    begin: str | None = None,
    end: str | None = None,
    dlp_status: str | None = None,
    search: str | None = None,
    sort: str = "time",
    dir: str = "desc",
    limit: int = Query(50, le=5000),
    offset: int = 0,
):
    conn = get_connection()
    try:
        where, params = [], []
        if domain:
            where.append("domain = ?")
            params.append(domain)
        if run_id is not None:
            where.append("run_id = ?")
            params.append(run_id)
        if begin:
            where.append("event_time >= ?")
            params.append(begin)
        if end:
            where.append("event_time <= ?")
            params.append(end)
        if dlp_status:
            where.append("dlp_status = ?")
            params.append(dlp_status)
        if search:
            where.append("(sender_address LIKE ? OR sender_fullname LIKE ? OR recipient_address LIKE ? OR subject LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like, like]
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        sort_col = _EXCHANGE_SORT_COLUMNS.get(sort, "event_time")
        sort_dir = "ASC" if dir.lower() == "asc" else "DESC"

        total = conn.execute(f"SELECT COUNT(*) c FROM exchange_mail_events {where_sql};", params).fetchone()["c"]
        rows = conn.execute(
            f"""SELECT * FROM exchange_mail_events {where_sql}
                ORDER BY {sort_col} {sort_dir}, id {sort_dir} LIMIT ? OFFSET ?;""",
            params + [limit, offset],
        ).fetchall()
        return {"total": total, "limit": limit, "offset": offset, "events": [dict(r) for r in rows]}
    finally:
        conn.close()


@router.get("/api/exchange/events/{event_id}")
def get_exchange_event(event_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM exchange_mail_events WHERE id = ?;", (event_id,)).fetchone()
        if not row:
            raise HTTPException(404, "event not found")
        return dict(row)
    finally:
        conn.close()


@router.post("/api/exchange/events/{event_id}/find_in_dlp")
def find_in_dlp(event_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM exchange_mail_events WHERE id = ?;", (event_id,)).fetchone()
        if not row:
            raise HTTPException(404, "event not found")

        sender_username = row["sender_address"].split("@")[0]
        try:
            approx_time = parse_dt(row["event_time"])
        except ValueError:
            raise HTTPException(500, f"stored event_time is unparseable: {row['event_time']!r}")

        sess = k.get_session()
        try:
            dlp_status, msg_href = dlp_correlate.find_dlp_copy(
                sess, sender_username, row["recipient_address"], row["subject"], approx_time,
            )
        except Exception as e:
            raise HTTPException(502, f"DLP lookup failed: {e}")

        conn.execute(
            "UPDATE exchange_mail_events SET dlp_status = ?, msg_href = ? WHERE id = ?;",
            (dlp_status, msg_href, event_id),
        )
        conn.commit()
        return {"dlp_status": dlp_status, "msg_href": msg_href}
    finally:
        conn.close()


@router.post("/api/exchange/events/{event_id}/analyze")
def analyze_exchange_event(event_id: int, model: str | None = None):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM exchange_mail_events WHERE id = ?;", (event_id,)).fetchone()
        if not row:
            raise HTTPException(404, "event not found")
        if row["dlp_status"] != "found" or not row["msg_href"]:
            raise HTTPException(409, "no DLP-captured file for this mail — likely sent from a phone")

        sess = k.get_session()
        try:
            raw = msg_fetch.fetch_mail_bytes(sess, row["msg_href"])
            content = msg_fetch.parse_msg(raw)
        except Exception as e:
            raise HTTPException(502, f"could not fetch/parse .msg from DLP server: {e}")

        mail = {
            "sender_fullname": row["sender_fullname"],
            "recipient_email": row["recipient_address"],
            "subject": row["subject"],
        }
        match = {"match_type": "personal_domain_match", "similarity_score": row["similarity_score"]}
        try:
            summary, model_used = analyzer.analyze(mail, match, content, model=model)
        except Exception as e:
            raise HTTPException(502, f"local model call failed: {e}")

        conn.execute(
            "UPDATE exchange_mail_events SET ai_summary = ?, model_version = ?, analyzed_at = datetime('now') WHERE id = ?;",
            (summary, model_used, event_id),
        )
        conn.commit()
        return {"ai_summary": summary, "model_version": model_used}
    finally:
        conn.close()


@router.get("/api/exchange/events/{event_id}/download")
def download_exchange_event(event_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT msg_href, event_time FROM exchange_mail_events WHERE id = ?;", (event_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "event not found")
    if not row["msg_href"]:
        raise HTTPException(404, "no saved .msg copy for this mail — likely sent from a phone")

    sess = k.get_session()
    try:
        raw = msg_fetch.fetch_mail_bytes(sess, row["msg_href"])
    except Exception as e:
        raise HTTPException(502, f"could not fetch .msg from DLP server: {e}")

    filename = f"exchange_mail_{event_id}_{(row['event_time'] or '').replace(' ', '_').replace(':', '-')}.msg"
    return Response(
        content=raw,
        media_type="application/vnd.ms-outlook",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
