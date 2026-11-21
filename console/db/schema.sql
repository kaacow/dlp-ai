PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS app_users (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    username               TEXT NOT NULL UNIQUE,     -- login name, immutable
    display_name           TEXT,                      -- shown in nav/account widget; defaults to username
    password_hash          TEXT NOT NULL,             -- bcrypt
    role                   TEXT NOT NULL DEFAULT 'user',  -- 'admin' | 'user'
    is_primary_admin       INTEGER NOT NULL DEFAULT 0,
    profile_picture        TEXT,                       -- filename under db/profile_pictures/
    default_session_duration TEXT NOT NULL DEFAULT '24h', -- '6h' | '12h' | '24h' | 'never' — pre-selected at login
    is_active              INTEGER NOT NULL DEFAULT 1,
    created_at             TEXT NOT NULL DEFAULT (datetime('now')),
    created_by             INTEGER                     -- FK app_users.id, nullable (the primary admin has none)
);

-- Session tokens are never stored raw — only their SHA-256 hash, so a read of this
-- table (backup, DB file copy, etc.) doesn't hand out usable logins. The raw token
-- lives only in the client's httponly cookie.
CREATE TABLE IF NOT EXISTS app_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON app_sessions(user_id);
