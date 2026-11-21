#!/usr/bin/env python3
"""DLP AI — the production app. Replaces the old "SSH in and run a script by hand"
workflow: this is a persistent web service with a dashboard, a "Run analysis" button
that pulls file-send events in a chosen time range and investigates whatever gets
escalated, a per-employee file-send report for targeted digging, and an on-demand
"Analyze event" action for investigating one specific send — all with a full
browsable history of the AI's reasoning, evidence, and its own follow-up queries.

Run with: ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8420
"""
import json
import ntpath
import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import agent
import auth
import content_extract
import emp_sql as k
import runner
from content_analyze import VALID_CATEGORIES as CONTENT_LABEL_VALID_CATEGORIES
from rule_engine import classify_event

DB_PATH = Path(__file__).parent.parent / "db" / "dlp_ai.sqlite3"
STATIC_DIR = Path(__file__).parent / "static"
PROFILE_PICTURES_DIR = Path(__file__).parent.parent / "db" / "profile_pictures"
ALLOWED_PICTURE_TYPES = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"}
MAX_PICTURE_BYTES = 5 * 1024 * 1024

# Paths under /api/ reachable without a session — everything else requires login,
# enforced by auth_middleware below, not by decorating every single route.
PUBLIC_API_PATHS = {"/api/auth/status", "/api/auth/setup", "/api/auth/login"}

# columns a caller is allowed to sort /api/events and the employee file-send report
# by (item 8) — never interpolate a client-supplied column name directly into SQL.
SORTABLE_COLUMNS = {
    "event_time": "event_time",
    "severity": "CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END",
    "app_desc": "app_desc COLLATE NOCASE",
    "file_name": "file_name COLLATE NOCASE",
}

app = FastAPI(title="DLP AI")


@app.middleware("http")
async def no_store_static(request: Request, call_next):
    """Disable caching entirely for non-API pages — confirmed live (2026-09-17):
    a user's browser was serving a stale cached copy of content_review.html/
    common.js, making real, successfully-saved corrections look like they weren't
    happening at all (the DB write was fine; the visible page just wasn't
    reflecting it without a hard refresh). Ported from the unified console app
    (dlp_console/app/main.py), which hit and fixed the identical class of issue
    earlier — same reasoning applies here: a low-traffic internal tool iterated
    on frequently is more likely to hit stale-cache confusion than to benefit
    from browser caching."""
    response = await call_next(request)
    if request.url.path == "/" or not request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Every /api/* route requires a logged-in session except the three explicitly
    public auth endpoints. /api/users* is admin-only, as is POST /api/labels (the
    "Feed to AI" action) — everything else is available to any logged-in user, per
    "regular users will be able to do all the stuff we already have."
    """
    path = request.url.path
    if path.startswith("/api/") and path not in PUBLIC_API_PATHS:
        conn = auth.get_connection()
        try:
            user = auth.user_from_token(conn, request.cookies.get(auth.SESSION_COOKIE))
        finally:
            conn.close()
        if not user:
            return JSONResponse({"detail": "not authenticated"}, status_code=401)
        request.state.user = user
        is_admin_only = path.startswith("/api/users") or (path == "/api/labels" and request.method == "POST")
        if is_admin_only and user["role"] != "admin":
            return JSONResponse({"detail": "admin access required"}, status_code=403)
    return await call_next(request)


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def parse_dt(s: str) -> datetime:
    s = s.replace("T", " ")
    if len(s) == 10:  # date only
        s += " 00:00:00"
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def order_clause(order_by: str, order_dir: str) -> str:
    col = SORTABLE_COLUMNS.get(order_by, SORTABLE_COLUMNS["event_time"])
    direction = "ASC" if (order_dir or "").lower() == "asc" else "DESC"
    return f"ORDER BY {col} {direction}"


class LoginRequest(BaseModel):
    username: str
    password: str


class SetupRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


class RoleRequest(BaseModel):
    role: str


class LabelRequest(BaseModel):
    event_verdict_id: int
    label_verdict: str
    label_notes: str


class ContentLabelCorrectRequest(BaseModel):
    is_confidential: bool
    risk_score: int
    categories: list[str]
    related_to_company: bool
    company_relevance_reasoning: str
    summary: str
    reasoning: str


class CompanyKnowledgeNoteRequest(BaseModel):
    title: str = ""
    content_text: str


class CompanyKnowledgePatchRequest(BaseModel):
    title: str | None = None
    content_text: str | None = None
    is_active: bool | None = None


def _set_session_cookie(response: Response, token: str):
    response.set_cookie(
        auth.SESSION_COOKIE, token, httponly=True, samesite="lax",
        max_age=auth.SESSION_DAYS * 86400,
    )


def _user_public_dict(row) -> dict:
    return {
        "id": row["id"], "username": row["username"], "role": row["role"],
        "is_primary_admin": bool(row["is_primary_admin"]), "profile_picture": row["profile_picture"],
    }


@app.get("/api/auth/status")
def auth_status():
    conn = auth.get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) c FROM app_users;").fetchone()["c"]
        return {"setup_required": count == 0}
    finally:
        conn.close()


@app.post("/api/auth/setup")
def auth_setup(req: SetupRequest, response: Response):
    """Only works once — the moment app_users has any row, this 409s forever.
    Creates the permanent primary admin; see app_users table comment for the
    guarantee this implies (nobody, including other admins, can ever demote or
    delete this account)."""
    conn = auth.get_connection()
    try:
        if conn.execute("SELECT COUNT(*) c FROM app_users;").fetchone()["c"] > 0:
            raise HTTPException(409, "setup already completed — use the login page")
        username = req.username.strip()
        if not username:
            raise HTTPException(400, "username required")
        if len(req.password) < auth.MIN_PASSWORD_LEN:
            raise HTTPException(400, f"password must be at least {auth.MIN_PASSWORD_LEN} characters")
        cur = conn.execute(
            "INSERT INTO app_users (username, password_hash, role, is_primary_admin) VALUES (?, ?, 'admin', 1);",
            (username, auth.hash_password(req.password)),
        )
        user_id = cur.lastrowid
        conn.commit()
        token = auth.create_session(conn, user_id)
        _set_session_cookie(response, token)
        row = conn.execute("SELECT * FROM app_users WHERE id = ?;", (user_id,)).fetchone()
        return _user_public_dict(row)
    finally:
        conn.close()


@app.post("/api/auth/login")
def auth_login(req: LoginRequest, response: Response):
    conn = auth.get_connection()
    try:
        row = conn.execute("SELECT * FROM app_users WHERE username = ? AND is_active = 1;", (req.username.strip(),)).fetchone()
        if not row or not auth.verify_password(req.password, row["password_hash"]):
            raise HTTPException(401, "invalid username or password")
        token = auth.create_session(conn, row["id"])
        _set_session_cookie(response, token)
        return _user_public_dict(row)
    finally:
        conn.close()


@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    raw_token = request.cookies.get(auth.SESSION_COOKIE)
    if raw_token:
        conn = auth.get_connection()
        try:
            auth.delete_session(conn, raw_token)
        finally:
            conn.close()
    response.delete_cookie(auth.SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/auth/me")
def auth_me(request: Request):
    return _user_public_dict(request.state.user)


# ---------------------------------------------------------------------------
# User management — admin only (enforced by auth_middleware on /api/users*)
# ---------------------------------------------------------------------------

@app.get("/api/users")
def list_users():
    conn = auth.get_connection()
    try:
        rows = conn.execute(
            """SELECT id, username, role, is_primary_admin, profile_picture, is_active, created_at
               FROM app_users ORDER BY is_primary_admin DESC, created_at;"""
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.post("/api/users")
def create_user(req: CreateUserRequest, request: Request):
    if req.role not in ("admin", "user"):
        raise HTTPException(400, "role must be 'admin' or 'user'")
    username = req.username.strip()
    if not username:
        raise HTTPException(400, "username required")
    if len(req.password) < auth.MIN_PASSWORD_LEN:
        raise HTTPException(400, f"password must be at least {auth.MIN_PASSWORD_LEN} characters")
    conn = auth.get_connection()
    try:
        if conn.execute("SELECT id FROM app_users WHERE username = ?;", (username,)).fetchone():
            raise HTTPException(409, "username already taken")
        cur = conn.execute(
            "INSERT INTO app_users (username, password_hash, role, created_by) VALUES (?, ?, ?, ?);",
            (username, auth.hash_password(req.password), req.role, request.state.user["id"]),
        )
        conn.commit()
        return {"id": cur.lastrowid, "username": username, "role": req.role}
    finally:
        conn.close()


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, request: Request):
    conn = auth.get_connection()
    try:
        target = conn.execute("SELECT * FROM app_users WHERE id = ?;", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user not found")
        if target["is_primary_admin"]:
            raise HTTPException(403, "the primary admin account cannot be deleted")
        if user_id == request.state.user["id"]:
            raise HTTPException(400, "you cannot delete your own account while logged in")
        conn.execute("DELETE FROM app_sessions WHERE user_id = ?;", (user_id,))
        conn.execute("DELETE FROM app_users WHERE id = ?;", (user_id,))
        conn.commit()
        if target["profile_picture"]:
            pic_path = PROFILE_PICTURES_DIR / target["profile_picture"]
            if pic_path.exists():
                pic_path.unlink()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/users/{user_id}/role")
def set_user_role(user_id: int, req: RoleRequest, request: Request):
    """Grant/revoke admin. The primary admin's role can never be changed by anyone
    (including themselves through this endpoint) — that permanence is the whole
    point of the "main admin" concept the user asked for."""
    if req.role not in ("admin", "user"):
        raise HTTPException(400, "role must be 'admin' or 'user'")
    conn = auth.get_connection()
    try:
        target = conn.execute("SELECT * FROM app_users WHERE id = ?;", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user not found")
        if target["is_primary_admin"]:
            raise HTTPException(403, "the primary admin's role cannot be changed")
        conn.execute("UPDATE app_users SET role = ? WHERE id = ?;", (req.role, user_id))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Profile pictures — any logged-in user, for their own account only
# ---------------------------------------------------------------------------

@app.post("/api/me/profile-picture")
async def upload_profile_picture(request: Request, file: UploadFile = File(...)):
    if file.content_type not in ALLOWED_PICTURE_TYPES:
        raise HTTPException(400, "only jpeg/png/webp/gif images are allowed")
    data = await file.read()
    if len(data) > MAX_PICTURE_BYTES:
        raise HTTPException(400, "image too large (max 5MB)")
    PROFILE_PICTURES_DIR.mkdir(parents=True, exist_ok=True)
    user_id = request.state.user["id"]
    for old in PROFILE_PICTURES_DIR.glob(f"user_{user_id}.*"):
        old.unlink()
    fname = f"user_{user_id}.{ALLOWED_PICTURE_TYPES[file.content_type]}"
    (PROFILE_PICTURES_DIR / fname).write_bytes(data)
    conn = auth.get_connection()
    try:
        conn.execute("UPDATE app_users SET profile_picture = ? WHERE id = ?;", (fname, user_id))
        conn.commit()
    finally:
        conn.close()
    return {"profile_picture": fname}


@app.get("/api/profile-pictures/{filename}")
def get_profile_picture(filename: str):
    if "/" in filename or ".." in filename:
        raise HTTPException(400, "bad filename")
    path = PROFILE_PICTURES_DIR / filename
    if not path.exists():
        raise HTTPException(404, "not found")
    return FileResponse(path)


# ---------------------------------------------------------------------------
# "Feed to AI" — admin-only creation (enforced by auth_middleware), readable by
# anyone who can see the event, since seeing why an event was labeled is useful
# context regardless of role.
# ---------------------------------------------------------------------------

@app.post("/api/labels")
def create_label(req: LabelRequest, request: Request):
    if req.label_verdict not in ("cleared", "needs_human_review", "confirmed_risk"):
        raise HTTPException(400, "label_verdict must be cleared, needs_human_review, or confirmed_risk")
    if not req.label_notes.strip():
        raise HTTPException(400, "label_notes required — that's the part the model actually reads")
    conn = get_connection()
    try:
        event = conn.execute(
            "SELECT destination_category, app_desc FROM event_verdicts WHERE id = ?;", (req.event_verdict_id,)
        ).fetchone()
        if not event:
            raise HTTPException(404, "event not found")
        conn.execute(
            """INSERT INTO labeled_examples
                 (event_verdict_id, destination_category, app_desc, label_verdict, label_notes, labeled_by)
               VALUES (?, ?, ?, ?, ?, ?);""",
            (req.event_verdict_id, event["destination_category"], event["app_desc"],
             req.label_verdict, req.label_notes.strip(), request.state.user["id"]),
        )
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.get("/api/events/{event_id}/labels")
def get_event_labels(event_id: int):
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT l.*, u.username AS labeled_by_username FROM labeled_examples l
               JOIN app_users u ON u.id = l.labeled_by
               WHERE l.event_verdict_id = ? ORDER BY l.labeled_at DESC;""",
            (event_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Content-only DLP labeling review (content_labels) — deliberately separate from
# event_verdicts/labeled_examples above. Judges FILE content alone (no destination
# ever shown to the model, see content_label_seed.py); this review UI is where a
# human agrees with or corrects the model's content-only judgment, building a
# labeled dataset for fine-tuning. Open to any logged-in user, not admin-gated
# like "Feed to AI" — this is bulk review work, not a governance action.
# ---------------------------------------------------------------------------

CONTENT_LABEL_PREVIEW_CHARS = 2000


@app.get("/api/content-labels")
def list_content_labels(
    reviewed: str | None = None,  # 'yes' | 'no' | None (all)
    search: str | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    conn = get_connection()
    try:
        where, params = [], []
        if reviewed == "yes":
            where.append("analyst_decision IS NOT NULL")
        elif reviewed == "no":
            where.append("analyst_decision IS NULL")
        if search:
            where.append("(file_name LIKE ? OR model_reasoning LIKE ? OR model_summary LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""

        total = conn.execute(f"SELECT COUNT(*) c FROM content_labels {where_sql};", params).fetchone()["c"]
        rows = conn.execute(
            f"""SELECT id, source_event_id, file_name, file_path, event_date, is_doc_type,
                       model_is_confidential, model_risk_score, model_categories,
                       model_related_to_company, model_company_relevance_reasoning,
                       model_summary, model_reasoning, analyst_decision, analyst_correction,
                       reviewed_by, reviewed_at, created_at,
                       substr(extracted_text_ref, 1, {CONTENT_LABEL_PREVIEW_CHARS}) AS content_preview,
                       length(extracted_text_ref) AS content_length
                FROM content_labels {where_sql}
                ORDER BY event_date DESC, id DESC LIMIT ? OFFSET ?;""",
            params + [limit, offset],
        ).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            d["model_categories"] = json.loads(d["model_categories"] or "[]")
            d["analyst_correction"] = json.loads(d["analyst_correction"]) if d["analyst_correction"] else None
            d["content_truncated"] = (d["content_length"] or 0) > CONTENT_LABEL_PREVIEW_CHARS
            items.append(d)
        return {"total": total, "limit": limit, "offset": offset, "items": items}
    finally:
        conn.close()


@app.get("/api/content-labels/{label_id}")
def get_content_label(label_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM content_labels WHERE id = ?;", (label_id,)).fetchone()
        if not row:
            raise HTTPException(404, "content label not found")
        d = dict(row)
        d["model_categories"] = json.loads(d["model_categories"] or "[]")
        d["analyst_correction"] = json.loads(d["analyst_correction"]) if d["analyst_correction"] else None
        return d
    finally:
        conn.close()


@app.post("/api/content-labels/{label_id}/agree")
def agree_content_label(label_id: int, request: Request):
    conn = get_connection()
    try:
        row = conn.execute("SELECT id FROM content_labels WHERE id = ?;", (label_id,)).fetchone()
        if not row:
            raise HTTPException(404, "content label not found")
        conn.execute(
            """UPDATE content_labels SET analyst_decision='agree', analyst_correction=NULL,
                 reviewed_by=?, reviewed_at=datetime('now') WHERE id=?;""",
            (request.state.user["username"], label_id),
        )
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/content-labels/{label_id}/correct")
def correct_content_label(label_id: int, req: ContentLabelCorrectRequest, request: Request):
    conn = get_connection()
    try:
        row = conn.execute("SELECT id FROM content_labels WHERE id = ?;", (label_id,)).fetchone()
        if not row:
            raise HTTPException(404, "content label not found")
        bad_categories = [c for c in req.categories if c not in CONTENT_LABEL_VALID_CATEGORIES]
        if bad_categories:
            raise HTTPException(400, f"unknown categories: {bad_categories}")
        correction = {
            "is_confidential": req.is_confidential, "risk_score": max(0, min(100, req.risk_score)),
            "categories": req.categories, "related_to_company": req.related_to_company,
            "company_relevance_reasoning": req.company_relevance_reasoning,
            "summary": req.summary, "reasoning": req.reasoning,
        }
        conn.execute(
            """UPDATE content_labels SET analyst_decision='correct', analyst_correction=?,
                 reviewed_by=?, reviewed_at=datetime('now') WHERE id=?;""",
            (json.dumps(correction, ensure_ascii=False), request.state.user["username"], label_id),
        )
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Company knowledge feeder — durable background facts for the content-only
# labeler (content_label_seed.py), injected at prompt time (context injection,
# not fine-tuning — see that module's docstring). Any logged-in user, not
# admin-gated, matching content-labels review's openness.
# ---------------------------------------------------------------------------

MAX_KNOWLEDGE_FILE_BYTES = 20 * 1024 * 1024  # generous; these are reference docs, not huge uploads


@app.get("/api/company-knowledge")
def list_company_knowledge():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM company_knowledge ORDER BY added_at DESC;").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.post("/api/company-knowledge")
def add_company_knowledge_note(req: CompanyKnowledgeNoteRequest, request: Request):
    if not req.content_text.strip():
        raise HTTPException(400, "content_text required")
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO company_knowledge (title, content_text, source_type, added_by)
               VALUES (?, ?, 'note', ?);""",
            (req.title.strip() or None, req.content_text.strip(), request.state.user["username"]),
        )
        conn.commit()
        return {"id": cur.lastrowid, "ok": True}
    finally:
        conn.close()


@app.post("/api/company-knowledge/upload")
async def upload_company_knowledge_file(request: Request, file: UploadFile = File(...), title: str = Form("")):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in content_extract.SUPPORTED_EXTS:
        raise HTTPException(400, f"unsupported file type: {ext or '(no extension)'}")
    data = await file.read()
    if len(data) > MAX_KNOWLEDGE_FILE_BYTES:
        raise HTTPException(400, "file too large (max 20MB)")
    with tempfile.NamedTemporaryFile(suffix=ext) as tf:
        tf.write(data)
        tf.flush()
        try:
            chunks, notes = content_extract.extract(tf.name, file.filename)
        except Exception as e:
            raise HTTPException(400, f"could not extract content: {e}")

    # Images inside a knowledge upload aren't read by a vision model here — this
    # feeder is for durable reference text, not full document analysis; a
    # scanned/image-only upload will just extract to `notes` (likely empty).
    text_parts = list(notes)
    for chunk in chunks:
        if chunk.kind == "text":
            text_parts.append(chunk.text)
    content_text = "\n\n".join(text_parts).strip()
    if not content_text:
        raise HTTPException(400, "no extractable text found in this file")

    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO company_knowledge (title, content_text, source_type, source_filename, added_by)
               VALUES (?, ?, 'file', ?, ?);""",
            (title.strip() or None, content_text, file.filename, request.state.user["username"]),
        )
        conn.commit()
        return {"id": cur.lastrowid, "ok": True, "extracted_chars": len(content_text)}
    finally:
        conn.close()


@app.patch("/api/company-knowledge/{knowledge_id}")
def patch_company_knowledge(knowledge_id: int, req: CompanyKnowledgePatchRequest):
    conn = get_connection()
    try:
        row = conn.execute("SELECT id FROM company_knowledge WHERE id = ?;", (knowledge_id,)).fetchone()
        if not row:
            raise HTTPException(404, "not found")
        fields, params = [], []
        if req.title is not None:
            fields.append("title = ?"); params.append(req.title.strip() or None)
        if req.content_text is not None:
            if not req.content_text.strip():
                raise HTTPException(400, "content_text cannot be blank")
            fields.append("content_text = ?"); params.append(req.content_text.strip())
        if req.is_active is not None:
            fields.append("is_active = ?"); params.append(int(req.is_active))
        if not fields:
            return {"ok": True}
        params.append(knowledge_id)
        conn.execute(f"UPDATE company_knowledge SET {', '.join(fields)} WHERE id = ?;", params)
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.delete("/api/company-knowledge/{knowledge_id}")
def delete_company_knowledge(knowledge_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT id FROM company_knowledge WHERE id = ?;", (knowledge_id,)).fetchone()
        if not row:
            raise HTTPException(404, "not found")
        conn.execute("DELETE FROM company_knowledge WHERE id = ?;", (knowledge_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.get("/api/config")
def config():
    return {"emp_host": k.HOST}


@app.get("/api/stats")
def stats():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT verdict, COUNT(*) c FROM event_verdicts GROUP BY verdict;").fetchall()
        by_verdict = {r["verdict"]: r["c"] for r in rows}
        total = sum(by_verdict.values())
        last_run = conn.execute("SELECT * FROM analysis_runs ORDER BY id DESC LIMIT 1;").fetchone()
        return {
            "total_events": total,
            "by_verdict": by_verdict,
            "last_run": dict(last_run) if last_run else None,
            "run_in_progress": runner._run_in_progress,
        }
    finally:
        conn.close()


@app.get("/api/events")
def list_events(
    verdict: str | None = None,
    severity: str | None = None,
    user_locator: int | None = None,
    search: str | None = None,
    begin: str | None = None,
    end: str | None = None,
    order_by: str = "event_time",
    order_dir: str = "desc",
    limit: int = Query(50, le=50000),
    offset: int = 0,
):
    conn = get_connection()
    try:
        where = []
        params = []
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if user_locator:
            where.append("user_locator = ?")
            params.append(user_locator)
        if begin:
            where.append("event_time >= ?")
            params.append(parse_dt(begin).strftime("%Y-%m-%d %H:%M:%S"))
        if end:
            where.append("event_time <= ?")
            params.append(parse_dt(end).strftime("%Y-%m-%d %H:%M:%S"))
        if search:
            where.append("(file_name LIKE ? OR app_desc LIKE ? OR reasoning LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""

        total = conn.execute(f"SELECT COUNT(*) c FROM event_verdicts {where_sql};", params).fetchone()["c"]
        rows = conn.execute(
            f"""SELECT id, row_auto_increment, user_locator, event_time, file_name, app_desc, destination_category,
                       verdict, severity, matched_rule, model_version
                FROM event_verdicts {where_sql}
                {order_clause(order_by, order_dir)} LIMIT ? OFFSET ?;""",
            params + [limit, offset],
        ).fetchall()

        # attach employee username/full name where we have them (item 5: lists show
        # username, detail view shows id + full name)
        user_locators = {r["user_locator"] for r in rows}
        emp = {}
        if user_locators:
            placeholders = ",".join("?" * len(user_locators))
            for r in conn.execute(f"SELECT user_locator, user_name, full_name FROM employees WHERE user_locator IN ({placeholders});", list(user_locators)):
                emp[r["user_locator"]] = {"user_name": r["user_name"], "full_name": r["full_name"]}

        events = []
        for r in rows:
            d = dict(r)
            e = emp.get(d["user_locator"])
            d["user_name"] = e["user_name"] if e else None
            d["employee_name"] = e["full_name"] if e else None
            events.append(d)

        return {"total": total, "limit": limit, "offset": offset, "events": events}
    finally:
        conn.close()


@app.get("/api/events/{event_id}")
def get_event(event_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM event_verdicts WHERE id = ?;", (event_id,)).fetchone()
        if not row:
            raise HTTPException(404, "event not found")
        d = dict(row)
        d["screenshots_used"] = json.loads(d["screenshots_used"]) if d["screenshots_used"] else {}
        d["extra_queries"] = json.loads(d["extra_queries"]) if d["extra_queries"] else []
        emp = conn.execute("SELECT * FROM employees WHERE user_locator = ?;", (d["user_locator"],)).fetchone()
        d["employee"] = dict(emp) if emp else None
        return d
    finally:
        conn.close()


@app.get("/api/screenshots/{filename}")
def get_screenshot(filename: str):
    if "/" in filename or ".." in filename:
        raise HTTPException(400, "bad filename")
    path = agent.SCREENSHOT_CACHE_DIR / filename
    if not path.exists():
        raise HTTPException(404, "not found")
    return FileResponse(path, media_type="image/jpeg")


@app.post("/api/runs")
def trigger_run(begin: str, end: str):
    try:
        begin_dt, end_dt = parse_dt(begin), parse_dt(end)
    except ValueError:
        raise HTTPException(400, "begin/end must be 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'")
    started = runner.start_run_if_idle(begin_dt, end_dt)
    if not started:
        return JSONResponse({"started": False, "message": "a run is already in progress"}, status_code=409)
    return {"started": True}


@app.get("/api/runs")
def list_runs(limit: int = Query(20, le=100)):
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM analysis_runs ORDER BY id DESC LIMIT ?;", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/api/runs/{run_id}")
def get_run(run_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?;", (run_id,)).fetchone()
        if not row:
            raise HTTPException(404, "run not found")
        return dict(row)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Employees + per-employee file-send report (item 2)
# ---------------------------------------------------------------------------

@app.get("/api/employees")
def list_employees(search: str | None = None, limit: int = Query(100, le=50000), offset: int = 0):
    """One row per tuserlocations entry (user+device login), which is what
    user_locator actually means — see schema.sql. A person with N devices
    legitimately appears N times, each with its own id/comp_name; that id is what
    "Generate report" and "Analyze event" operate on, not a person-level id.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT e.user_locator, e.user_name, e.comp_name, e.full_name, e.department,
                      (SELECT COUNT(*) FROM event_verdicts v WHERE v.user_locator = e.user_locator) AS events_on_file
               FROM employees e;"""
        ).fetchall()
        employees = [dict(r) for r in rows]

        # Defense in depth: a user_locator with real event activity but no
        # tuserlocations row at all (e.g. a device removed from EMP since)
        # would otherwise be invisible here. Surface it anyway, unlabeled.
        known_ids = {e["user_locator"] for e in employees}
        orphans = conn.execute("SELECT user_locator, COUNT(*) AS events_on_file FROM event_verdicts GROUP BY user_locator;").fetchall()
        for o in orphans:
            if o["user_locator"] not in known_ids:
                employees.append({
                    "user_locator": o["user_locator"], "user_name": f"#{o['user_locator']}", "comp_name": None,
                    "full_name": None, "department": None, "events_on_file": o["events_on_file"],
                })

        if search:
            q = search.lower()
            employees = [e for e in employees if q in (e["user_name"] or "").lower()
                         or q in (e["full_name"] or "").lower() or q in (e["department"] or "").lower()
                         or q in (e["comp_name"] or "").lower() or q == str(e["user_locator"])]

        employees.sort(key=lambda e: (e["full_name"] or e["user_name"] or "").lower())
        total = len(employees)
        return {"total": total, "limit": limit, "offset": offset, "employees": employees[offset:offset + limit]}
    finally:
        conn.close()


@app.get("/api/employees/{user_locator}/filesend")
def employee_filesend_report(
    user_locator: int, begin: str, end: str,
    order_by: str = "event_time", order_dir: str = "desc",
):
    """Pulls this employee's file-send events for the given range directly from the
    live EMP DB (not just what's already in our local store), classifies any
    not-yet-seen ones with Track B so the report is immediately useful, and returns
    the current state (including any prior Track C investigation) for each row.
    """
    try:
        begin_dt, end_dt = parse_dt(begin), parse_dt(end)
    except ValueError:
        raise HTTPException(400, "begin/end must be 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'")

    conn = get_connection()
    try:
        sess = k.get_session()
        events = runner.fetch_events_in_range(sess, begin_dt, end_dt, user_locator=user_locator)
        if not events:
            return {"events": []}

        baseline_index = runner.load_baseline_index(conn)
        for event in events:
            classification = classify_event(event, baseline_index)
            runner.store_verdict(conn, event, classification)
        conn.commit()

        row_ids = [e["row_auto_increment"] for e in events]
        placeholders = ",".join("?" * len(row_ids))
        rows = conn.execute(
            f"""SELECT id, row_auto_increment, event_time, file_name, app_desc, destination_category,
                       verdict, severity, matched_rule, model_version
                FROM event_verdicts
                WHERE source_table='treportfilesnd' AND row_auto_increment IN ({placeholders})
                {order_clause(order_by, order_dir)};""",
            row_ids,
        ).fetchall()
        return {"events": [dict(r) for r in rows]}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# On-demand single-event investigation (item 3)
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    row_auto_increment: int
    user_locator: int
    reasoning_model: str | None = None
    vision_model: str | None = None


@app.post("/api/events/analyze")
def analyze_event(req: AnalyzeRequest):
    job_id = runner.start_analyze_job(
        req.row_auto_increment, req.user_locator,
        reasoning_model=req.reasoning_model, vision_model=req.vision_model,
    )
    return {"job_id": job_id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: int):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM investigation_jobs WHERE id = ?;", (job_id,)).fetchone()
        if not row:
            raise HTTPException(404, "job not found")
        d = dict(row)
        d["steps"] = json.loads(d.pop("steps_json") or "[]")
        return d
    finally:
        conn.close()


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: int):
    """Actually stops the investigation — sets a threading.Event the worker thread
    checks between steps, which also closes the in-flight Ollama streaming
    connection so GPU inference genuinely stops, not just our interest in the
    result. See ollama_client.py / runner.py for the mechanism."""
    found = runner.cancel_job(job_id)
    if not found:
        return {"cancelled": False, "message": "job not running (already finished, or never started)"}
    return {"cancelled": True}


@app.get("/api/models")
def list_models():
    """For the (future, per item 3) model picker — what's actually pulled on this
    box right now, so the UI never offers a model that isn't installed."""
    import requests
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        resp.raise_for_status()
        models = resp.json().get("models", [])
        return [{"name": m["name"], "size": m["size"]} for m in models]
    except Exception:
        return []


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
