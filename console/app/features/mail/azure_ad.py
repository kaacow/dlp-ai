"""Azure AD display-name lookups for Exchange-sourced senders — ported from
`old_server.py`'s `fetch_display_name`/`build_name_map` (the old Flask
self-email tool). The Exchange message-trace CSV never contains a display
name, unlike the DLP "Mails" report's `User` cell, so this is a dependency
this app didn't need before adding the Exchange-based pages.

Names are cached in `sender_names` (db/schema.sql) since the same handful of
employees show up daily and re-querying `az` for all of them every run is
wasteful, and also softens the blast radius if the az CLI token lapses —
already-cached senders still resolve even if fresh lookups start failing.
"""
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

from .errors import ReauthRequiredError

DB_PATH = Path("./data/db/mail_detector.sqlite3")

# Substrings az CLI prints when the local login/token is the problem, as
# opposed to a plain "no such user in this tenant" (which is a normal empty
# result, not an error state).
_REAUTH_MARKERS = ("az login", "AADSTS", "Please run 'az login'")


def _get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _cached_names(emails: list[str]) -> dict[str, str]:
    if not emails:
        return {}
    conn = _get_connection()
    try:
        placeholders = ",".join("?" * len(emails))
        rows = conn.execute(
            f"SELECT email, fullname FROM sender_names WHERE email IN ({placeholders});",
            emails,
        ).fetchall()
        return {r["email"]: r["fullname"] for r in rows}
    finally:
        conn.close()


def _store_names(name_map: dict[str, str]) -> None:
    if not name_map:
        return
    conn = _get_connection()
    try:
        conn.executemany(
            """INSERT INTO sender_names (email, fullname, fetched_at) VALUES (?, ?, datetime('now'))
               ON CONFLICT(email) DO UPDATE SET fullname=excluded.fullname, fetched_at=excluded.fetched_at;""",
            list(name_map.items()),
        )
        conn.commit()
    finally:
        conn.close()


def fetch_display_name(email: str) -> tuple[str, str]:
    """Returns (email, display_name) — display_name is "" if az ran fine but
    found nothing (a normal outcome, e.g. a shared mailbox with no AD user).
    Raises ReauthRequiredError if az itself reports the CLI isn't logged in,
    since that means EVERY lookup will fail until a human runs `az login`
    again, not just this one email."""
    email = email.strip().strip('"').strip("'").lower()
    if not email or "@" not in email:
        return email, ""

    cmd = ["az", "ad", "user", "show", "--id", email, "--query", "displayName", "-o", "tsv"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        raise ReauthRequiredError("'az' CLI not found on this machine")
    except subprocess.TimeoutExpired:
        return email, ""

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if any(marker.lower() in stderr.lower() for marker in _REAUTH_MARKERS):
            raise ReauthRequiredError(f"az CLI not logged in: {stderr[:200]}")
        return email, ""
    return email, result.stdout.strip()


def build_name_map(emails: list[str], max_workers: int = 8) -> dict[str, str]:
    """Cache-first display-name lookup for a batch of sender addresses. Only
    calls `az` for emails not already cached. A ReauthRequiredError from any
    single lookup propagates to the caller (instead of being swallowed into
    an empty name for everyone) — that's the signal a human needs to
    `az login` again. Whatever was already resolved before the error is
    still cached, so it doesn't need re-fetching once login is restored."""
    emails = sorted({e.strip().lower() for e in emails if e and "@" in e})
    cached = _cached_names(emails)
    missing = [e for e in emails if e not in cached]

    name_map: dict[str, str] = dict(cached)
    if not missing:
        return name_map

    lock = Lock()
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fetch_display_name, e): e for e in missing}
            for future in as_completed(futures):
                email, name = future.result()
                with lock:
                    name_map[email] = name
    finally:
        _store_names({e: name_map[e] for e in missing if e in name_map})

    return name_map
