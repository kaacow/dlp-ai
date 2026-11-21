#!/usr/bin/env python3
"""DLP AI Console — the unified production app combining Secret Scanner, Mail
Exfil Detector, and File Analyzer behind one login, with admin/user roles.

Run with: ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8424
"""
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auth
from features.secrets.router import router as secrets_router
from features.secrets import router as secrets_module
from features.mail.router import router as mail_router
from features.mail import router as mail_module
from features.files.router import router as files_router
from features.files import router as files_module

BASE_DIR = Path(__file__).parent.parent
STATIC_DIR = BASE_DIR / "static"
PROFILE_PICTURES_DIR = BASE_DIR / "db" / "profile_pictures"
ALLOWED_PICTURE_TYPES = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"}
MAX_PICTURE_BYTES = 5 * 1024 * 1024

# Paths under /api/ reachable without a session. /api/mail/exchange/runs/auto is
# here deliberately — it's the cron-triggered daily Exchange scrape (see
# features/mail/router.py), and cron's plain `curl -X POST` has no session cookie
# to send. That endpoint only starts a scheduled scan (no data exposure, no
# destructive action) and matches its unauthenticated behavior on the old
# standalone service it replaces.
PUBLIC_API_PATHS = {"/api/auth/status", "/api/auth/setup", "/api/auth/login"}
PUBLIC_API_EXACT_EXTRA = {"/api/exchange/runs/auto"}

app = FastAPI(title="DLP AI Console")
app.include_router(secrets_router)
app.include_router(mail_router)
app.include_router(files_router)


@app.middleware("http")
async def no_store_static(request: Request, call_next):
    """Disable caching entirely for non-API pages — a low-traffic internal tool
    that's iterated on frequently is more likely to hit stale-cache confusion
    after a redeploy than to benefit from browser caching. Ported from the
    standalone mail_exfil app's same middleware, now applied globally."""
    response = await call_next(request)
    if request.url.path == "/" or not request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Every /api/* route requires a logged-in session except the explicitly
    public auth/cron paths. /api/users* is admin-only."""
    path = request.url.path
    if path.startswith("/api/") and path not in PUBLIC_API_PATHS and path not in PUBLIC_API_EXACT_EXTRA:
        conn = auth.get_connection()
        try:
            user = auth.user_from_token(conn, request.cookies.get(auth.SESSION_COOKIE))
        finally:
            conn.close()
        if not user:
            return JSONResponse({"detail": "not authenticated"}, status_code=401)
        request.state.user = user
        if path.startswith("/api/users") and user["role"] != "admin":
            return JSONResponse({"detail": "admin access required"}, status_code=403)
    return await call_next(request)


@app.on_event("startup")
def on_startup():
    init_db()
    PROFILE_PICTURES_DIR.mkdir(parents=True, exist_ok=True)
    secrets_module.init_db()
    mail_module.init_db()
    files_module.init_db()


def init_db():
    BASE_DIR.joinpath("db").mkdir(parents=True, exist_ok=True)
    conn = auth.get_connection()
    try:
        conn.executescript((BASE_DIR / "db" / "schema.sql").read_text())
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

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


class ResetPasswordRequest(BaseModel):
    new_password: str


class MeUpdateRequest(BaseModel):
    display_name: str | None = None
    default_session_duration: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


def _set_session_cookie(response: Response, token: str, delta):
    response.set_cookie(
        auth.SESSION_COOKIE, token, httponly=True, samesite="lax",
        max_age=int(delta.total_seconds()),
    )


def _user_public_dict(row) -> dict:
    d = dict(row) if not isinstance(row, dict) else row
    return {
        "id": d["id"], "username": d["username"],
        "display_name": d.get("display_name") or d["username"],
        "role": d["role"], "is_primary_admin": bool(d["is_primary_admin"]),
        "profile_picture": d.get("profile_picture"),
        "default_session_duration": d.get("default_session_duration", auth.DEFAULT_SESSION_DURATION),
    }


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

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
    """Only works once — creates the permanent primary admin. See app_users
    table: nobody, including other admins, can ever demote or delete this account."""
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
            "INSERT INTO app_users (username, display_name, password_hash, role, is_primary_admin) "
            "VALUES (?, ?, ?, 'admin', 1);",
            (username, username, auth.hash_password(req.password)),
        )
        user_id = cur.lastrowid
        conn.commit()
        token, delta = auth.create_session(conn, user_id, auth.DEFAULT_SESSION_DURATION)
        _set_session_cookie(response, token, delta)
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
        # Session length is a per-user preference set in Account Settings, not a
        # per-login choice — keeps the login form simple and matches how the user
        # actually wants to control it (set once, applies every time).
        duration = row["default_session_duration"] if row["default_session_duration"] in auth.SESSION_DURATIONS else auth.DEFAULT_SESSION_DURATION
        token, delta = auth.create_session(conn, row["id"], duration)
        _set_session_cookie(response, token, delta)
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
# Account settings — any logged-in user, own account only
# ---------------------------------------------------------------------------

@app.patch("/api/me")
def update_me(req: MeUpdateRequest, request: Request):
    user_id = request.state.user["id"]
    conn = auth.get_connection()
    try:
        if req.display_name is not None:
            name = req.display_name.strip()
            if not name:
                raise HTTPException(400, "display name cannot be empty")
            conn.execute("UPDATE app_users SET display_name = ? WHERE id = ?;", (name, user_id))
        if req.default_session_duration is not None:
            if req.default_session_duration not in auth.SESSION_DURATIONS:
                raise HTTPException(400, f"default_session_duration must be one of {list(auth.SESSION_DURATIONS)}")
            conn.execute("UPDATE app_users SET default_session_duration = ? WHERE id = ?;", (req.default_session_duration, user_id))
        conn.commit()
        row = conn.execute("SELECT * FROM app_users WHERE id = ?;", (user_id,)).fetchone()
        return _user_public_dict(row)
    finally:
        conn.close()


@app.post("/api/me/password")
def change_own_password(req: ChangePasswordRequest, request: Request):
    user_id = request.state.user["id"]
    if len(req.new_password) < auth.MIN_PASSWORD_LEN:
        raise HTTPException(400, f"password must be at least {auth.MIN_PASSWORD_LEN} characters")
    conn = auth.get_connection()
    try:
        row = conn.execute("SELECT * FROM app_users WHERE id = ?;", (user_id,)).fetchone()
        if not auth.verify_password(req.current_password, row["password_hash"]):
            raise HTTPException(401, "current password is incorrect")
        conn.execute("UPDATE app_users SET password_hash = ? WHERE id = ?;", (auth.hash_password(req.new_password), user_id))
        # Changing your own password invalidates other sessions too, so a stolen
        # long-lived ("never expire") session elsewhere doesn't survive a reset.
        conn.execute("DELETE FROM app_sessions WHERE user_id = ?;", (user_id,))
        conn.commit()
    finally:
        conn.close()

    response = JSONResponse({"ok": True})
    conn = auth.get_connection()
    try:
        token, delta = auth.create_session(conn, user_id, request.state.user.get("default_session_duration", auth.DEFAULT_SESSION_DURATION))
    finally:
        conn.close()
    _set_session_cookie(response, token, delta)
    return response


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
# User management — admin only (enforced by auth_middleware on /api/users*)
# ---------------------------------------------------------------------------

@app.get("/api/users")
def list_users():
    conn = auth.get_connection()
    try:
        rows = conn.execute(
            """SELECT id, username, display_name, role, is_primary_admin, profile_picture,
                      default_session_duration, is_active, created_at
               FROM app_users ORDER BY is_primary_admin DESC, created_at;"""
        ).fetchall()
        return [_user_public_dict(dict(r)) for r in rows]
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
            "INSERT INTO app_users (username, display_name, password_hash, role, created_by) VALUES (?, ?, ?, ?, ?);",
            (username, username, auth.hash_password(req.password), req.role, request.state.user["id"]),
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
    """Grant/revoke admin. The primary admin's role can never be changed by anyone."""
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


@app.post("/api/users/{user_id}/reset-password")
def reset_user_password(user_id: int, req: ResetPasswordRequest, request: Request):
    """Admin sets a new password directly for another user — no email flow, this
    is a small internal tool. Also revokes that user's existing sessions."""
    if len(req.new_password) < auth.MIN_PASSWORD_LEN:
        raise HTTPException(400, f"password must be at least {auth.MIN_PASSWORD_LEN} characters")
    if user_id == request.state.user["id"]:
        raise HTTPException(400, "use Account Settings to change your own password")
    conn = auth.get_connection()
    try:
        target = conn.execute("SELECT * FROM app_users WHERE id = ?;", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user not found")
        conn.execute("UPDATE app_users SET password_hash = ? WHERE id = ?;", (auth.hash_password(req.new_password), user_id))
        conn.execute("DELETE FROM app_sessions WHERE user_id = ?;", (user_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
