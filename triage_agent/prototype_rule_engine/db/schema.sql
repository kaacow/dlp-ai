-- dlp_ai side database — SQLite (chosen over Postgres for v1: no root/sudo available
-- on the GPU workstation for package installs, zero external dependency, plenty for this data
-- volume ~3k events/day). Straightforward to migrate to Postgres later if the team
-- wants concurrent multi-writer access or wants it merged into shared infra.

PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS employees (
    user_locator INTEGER PRIMARY KEY,   -- FK back to EMP tuserinfo.id
    user_domain  TEXT,
    user_name    TEXT,
    full_name    TEXT,
    department   TEXT,
    is_active    INTEGER NOT NULL DEFAULT 1,
    synced_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS known_contacts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT,
    platform     TEXT,                  -- WhatsApp / WebTelegram / Teams / etc.
    identifier   TEXT NOT NULL,         -- phone number or handle as seen in user_uin
    company      TEXT,
    trust_level  TEXT NOT NULL DEFAULT 'unknown',  -- trusted / unknown / blocked
    added_by     TEXT,
    added_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(platform, identifier)
);

CREATE TABLE IF NOT EXISTS baseline_exceptions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_locator  INTEGER NOT NULL,
    destination   TEXT NOT NULL,        -- app_desc value or destination_category
    pattern_type  TEXT NOT NULL,        -- 'app_desc' | 'destination_category' | 'filename_regex'
    pattern_value TEXT NOT NULL,
    approved_by   TEXT,
    approved_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT,
    active        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_baseline_user_dest ON baseline_exceptions(user_locator, destination) WHERE active = 1;

CREATE TABLE IF NOT EXISTS event_verdicts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_table        TEXT NOT NULL DEFAULT 'treportfilesnd',
    row_auto_increment  INTEGER NOT NULL,   -- FK back to the EMP source row
    user_locator        INTEGER NOT NULL,
    event_time          TEXT NOT NULL,      -- ISO string, converted from OLE date
    file_path            TEXT,
    file_name            TEXT,
    size_kb              INTEGER,
    app_desc             TEXT,
    destination_category TEXT NOT NULL,
    id_vocab              INTEGER,
    verdict              TEXT NOT NULL,     -- auto_clear | baseline_match | spot_check | escalate
    severity              TEXT,             -- low | medium | high (mainly for escalate/spot_check)
    reasoning             TEXT,
    matched_rule          TEXT,
    screenshots_used       TEXT,            -- JSON array, populated by Track C later
    model_version          TEXT,            -- null for Track B rule-only verdicts
    reviewed_by             TEXT,
    reviewed_at              TEXT,
    created_at               TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(source_table, row_auto_increment)
);
CREATE INDEX IF NOT EXISTS idx_verdicts_user_time ON event_verdicts(user_locator, event_time);
CREATE INDEX IF NOT EXISTS idx_verdicts_verdict ON event_verdicts(verdict);
