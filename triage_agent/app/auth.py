"""Login, sessions, and role checks.

Security notes (read before assuming more than this actually provides):
- Passwords are hashed with bcrypt (cost 12), never stored or logged in plaintext.
- Session tokens are 256 bits of `secrets.token_urlsafe` randomness, stored
  server-side only as a SHA-256 hash (app_sessions.token_hash) — the raw token
  lives only in the client's httponly cookie, so reading the DB never hands out a
  usable session. Sessions expire (SESSION_DAYS) and are checked on every request.
- The cookie is httponly (JS can't read it, blocks XSS token theft) and
  samesite=lax (blocks basic CSRF from cross-site requests).
- What this does NOT cover: the app currently serves plain HTTP, not HTTPS. That
  means the session cookie and login POST body travel unencrypted on the network —
  anyone positioned to observe traffic between a browser and this server (e.g. ARP
  spoofing on the same LAN segment) could intercept a session token. Fine for a
  quick internal test; before this is something coworkers log into regularly with
  real passwords, put a TLS-terminating reverse proxy (Caddy/nginx with even a
  self-signed or internal-CA cert) in front of it. That's a deploy/infra change,
  not something fixable purely in application code.
"""
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import bcrypt
from fastapi import HTTPException, Request

DB_PATH = Path(__file__).parent.parent / "db" / "dlp_ai.sqlite3"
SESSION_COOKIE = "dlpai_session"
SESSION_DAYS = 14
MIN_PASSWORD_LEN = 8


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        return False


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_session(conn, user_id: int) -> str:
    raw_token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(days=SESSION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO app_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?);",
        (_hash_token(raw_token), user_id, expires_at),
    )
    conn.commit()
    return raw_token


def delete_session(conn, raw_token: str):
    conn.execute("DELETE FROM app_sessions WHERE token_hash = ?;", (_hash_token(raw_token),))
    conn.commit()


def user_from_token(conn, raw_token: str):
    if not raw_token:
        return None
    row = conn.execute(
        """SELECT u.* FROM app_sessions s JOIN app_users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.is_active = 1;""",
        (_hash_token(raw_token),),
    ).fetchone()
    return dict(row) if row else None


def get_current_user(request: Request) -> dict:
    """FastAPI dependency — raises 401 if not logged in with a valid, unexpired session."""
    raw_token = request.cookies.get(SESSION_COOKIE)
    conn = get_connection()
    try:
        user = user_from_token(conn, raw_token)
        if not user:
            raise HTTPException(401, "not authenticated")
        return user
    finally:
        conn.close()


def require_admin(request: Request) -> dict:
    """FastAPI dependency — 401 if not logged in, 403 if logged in but not an admin."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "admin access required")
    return user
