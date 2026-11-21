"""SQLite storage for Global Search. Own DB file next to the console's other feature DBs.
gs_events has a UNIQUE key + INSERT OR IGNORE so re-running an overlapping range never duplicates (lesson from
the secrets feature)."""
import hashlib
import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(os.environ.get("GS_BASE", "./data"))
DB_PATH = BASE_DIR / "db" / "gsearch.sqlite3"

SCHEMA = """
CREATE TABLE IF NOT EXISTS gs_watch (
  bi01_user TEXT NOT NULL, win_user TEXT NOT NULL DEFAULT '', added_at TEXT DEFAULT (datetime('now','localtime')),
  PRIMARY KEY (bi01_user, win_user));
CREATE TABLE IF NOT EXISTS gs_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, status TEXT NOT NULL,
  started TEXT, finished TEXT, t_from TEXT, t_to TEXT, scope TEXT DEFAULT '',
  slices INTEGER DEFAULT 0, rows_seen INTEGER DEFAULT 0, rows_text INTEGER DEFAULT 0,
  ok INTEGER DEFAULT 0, unknown INTEGER DEFAULT 0, review INTEGER DEFAULT 0, alerts INTEGER DEFAULT 0, new_events INTEGER DEFAULT 0,
  warnings TEXT DEFAULT '', error TEXT DEFAULT '', owner TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS gs_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, verdict TEXT NOT NULL,
  user_domain TEXT, user_name TEXT NOT NULL, fio TEXT, machine TEXT, ip TEXT, event_time TEXT NOT NULL, title TEXT,
  foreign_users TEXT, own_users TEXT, snippet TEXT, text_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new', reviewed_by TEXT, reviewed_at TEXT, note TEXT DEFAULT '',
  UNIQUE (user_name, machine, event_time, text_hash));
CREATE INDEX IF NOT EXISTS idx_gs_events_time ON gs_events(event_time);
CREATE INDEX IF NOT EXISTS idx_gs_events_status ON gs_events(status, verdict);
"""


def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = conn()
    try:
        c.executescript(SCHEMA)
        c.commit()
    finally:
        c.close()


def text_hash(t):
    return hashlib.sha1((t or "").encode("utf-8", "replace")).hexdigest()[:16]


def load_watch(c=None):
    own = c is None
    c = c or conn()
    try:
        return [(r["bi01_user"], r["win_user"]) for r in c.execute("SELECT bi01_user, win_user FROM gs_watch ORDER BY bi01_user, win_user")]
    finally:
        if own:
            c.close()


def save_watch(entries, replace):
    c = conn()
    try:
        if replace:
            c.execute("DELETE FROM gs_watch")
        c.executemany("INSERT OR IGNORE INTO gs_watch (bi01_user, win_user) VALUES (?,?)", entries)
        c.commit()
        return c.execute("SELECT COUNT(*) FROM gs_watch").fetchone()[0]
    finally:
        c.close()
