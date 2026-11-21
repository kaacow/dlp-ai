-- dlp_ai side database — SQLite (chosen over Postgres for v1: no root/sudo available
-- on the GPU workstation for package installs, zero external dependency, plenty for this data
-- volume ~3k events/day). Straightforward to migrate to Postgres later if the team
-- wants concurrent multi-writer access or wants it merged into shared infra.

PRAGMA journal_mode = WAL;

-- One row per EMP `tuserlocations` row, NOT per `tuserinfo` row — this was a
-- real bug, found and fixed after the fact: tuserlocations is the user+DEVICE login
-- table (one row per distinct computer a person has logged into, e.g. jdoe
-- x NB0001) and its `id` is the actual user_locator FK used by every report table
-- (treportfilesnd, treportappusage, treportchats, treportscreenshots, ...).
-- tuserinfo is a separate, smaller, pure-person table (fullname/department only) in
-- a DIFFERENT id space — seeding straight from tuserinfo (the original approach)
-- meant `employees.user_locator` values didn't actually match any real event data
-- for people without a 1:1 id coincidence. full_name/department are now a LEFT JOIN
-- from tuserinfo onto tuserlocations via (user_domain, user_name), so one person can
-- legitimately appear multiple times here (once per device), and some rows will
-- have full_name/department NULL if EMP has no HR dossier entry for them.
CREATE TABLE IF NOT EXISTS employees (
    user_locator INTEGER PRIMARY KEY,   -- = tuserlocations.id, the real user_locator FK
    user_domain  TEXT,
    user_name    TEXT,
    comp_name    TEXT,                  -- which device this location-id corresponds to
    full_name    TEXT,                  -- from tuserinfo, NULL if no HR dossier entry
    department   TEXT,                  -- from tuserinfo, NULL if no HR dossier entry
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
                                             -- (escalated events get overwritten with
                                             -- cleared | needs_human_review | confirmed_risk
                                             -- once Track C investigates them)
    severity              TEXT,             -- low | medium | high (mainly for escalate/spot_check)
    reasoning             TEXT,
    matched_rule          TEXT,             -- the Track B rule that produced the *original* verdict,
                                             -- preserved even after Track C overwrites verdict/reasoning
    screenshots_used       TEXT,            -- JSON: {kind: [...evidence items]} gathered by Track C
    extra_queries           TEXT,           -- JSON: [{sql, row_count}] — SQL the agentic model
                                             -- chose to run beyond the auto-gathered baseline evidence
    model_version          TEXT,            -- null for Track B rule-only verdicts
    reviewed_by             TEXT,
    reviewed_at              TEXT,
    created_at               TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(source_table, row_auto_increment)
);
CREATE INDEX IF NOT EXISTS idx_verdicts_user_time ON event_verdicts(user_locator, event_time);
CREATE INDEX IF NOT EXISTS idx_verdicts_verdict ON event_verdicts(verdict);

-- One row per "Run analysis" click (or future scheduled run) — lets the UI show
-- progress/history instead of the caller having to babysit a script. Runs are now
-- explicit time-range driven (begin_time/end_time), not high-water-mark driven —
-- re-running an overlapping range is safe/idempotent (see store_verdict's
-- model_version guard), so users can freely re-pick a date range and re-run.
CREATE TABLE IF NOT EXISTS analysis_runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at        TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at       TEXT,
    status            TEXT NOT NULL DEFAULT 'running',  -- running | done | failed
    error             TEXT,
    begin_time        TEXT,                 -- requested range, 'YYYY-MM-DD HH:MM:SS'
    end_time          TEXT,
    events_pulled     INTEGER DEFAULT 0,   -- treportfilesnd rows classified by Track B this run
    events_escalated  INTEGER DEFAULT 0,   -- of those, how many Track B escalated
    events_investigated INTEGER DEFAULT 0, -- of those, how many Track C finished investigating
    high_water_mark   INTEGER              -- max treportfilesnd.row_auto_increment seen, kept for
                                            -- reference/debugging, no longer drives the next run
);

-- One row per on-demand "Analyze event" click (item 3) — single-event investigation
-- triggered from the employee file-send report, with a live step-by-step progress
-- log the UI polls so the user can see "gathering chat evidence", "reading
-- screenshot 2/3", etc. while it runs, not just a spinner.
CREATE TABLE IF NOT EXISTS investigation_jobs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    row_auto_increment  INTEGER NOT NULL,   -- the treportfilesnd row being investigated
    user_locator        INTEGER NOT NULL,
    status              TEXT NOT NULL DEFAULT 'running',  -- running | done | failed
    steps_json          TEXT NOT NULL DEFAULT '[]',       -- [{time, step}], appended to as it runs
    reasoning_model     TEXT,               -- model override used for this job, if any
    vision_model        TEXT,
    event_verdict_id    INTEGER,            -- FK to event_verdicts once done, so the UI can jump to it
    error               TEXT,
    started_at          TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at         TEXT
);

-- ---------------------------------------------------------------------------
-- Auth / users / roles
-- ---------------------------------------------------------------------------

-- Exactly one row ever has is_primary_admin=1 — the account created via the
-- one-time /setup flow (only reachable while this table is empty). That row can
-- never be deleted or demoted by anyone, including other admins — enforced in
-- application code (auth.py / main.py), not just by convention, since this is the
-- guarantee the user explicitly asked for ("first admin... can never revoke this
-- main admin's permissions").
CREATE TABLE IF NOT EXISTS app_users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,             -- bcrypt
    role              TEXT NOT NULL DEFAULT 'user',  -- 'admin' | 'user'
    is_primary_admin  INTEGER NOT NULL DEFAULT 0,
    profile_picture   TEXT,                       -- filename under db/profile_pictures/
    is_active         INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    created_by        INTEGER                     -- FK app_users.id, nullable (the primary admin has none)
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

-- ---------------------------------------------------------------------------
-- Analyst feedback / few-shot examples ("Feed to AI")
-- ---------------------------------------------------------------------------

-- NOT a fine-tuning dataset in the weight-update sense — see agent.py's
-- find_similar_precedent(). Each row is a human judgment call an admin writes on a
-- specific event; investigate_event() looks up the most relevant few of these and
-- includes them in the reasoning model's prompt as precedent for new, similar
-- events. This is what actually makes the system "learn" from feedback here:
-- in-context/few-shot learning, not model weight changes.
CREATE TABLE IF NOT EXISTS labeled_examples (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    event_verdict_id   INTEGER NOT NULL,     -- FK event_verdicts.id, the event being labeled
    destination_category TEXT,               -- denormalized from the event at label time, for fast retrieval matching
    app_desc           TEXT,                 -- denormalized likewise
    label_verdict       TEXT NOT NULL,       -- cleared | needs_human_review | confirmed_risk
    label_notes          TEXT NOT NULL,      -- the analyst's free-text reasoning — this is what gets shown to the model
    labeled_by            INTEGER NOT NULL,  -- FK app_users.id
    labeled_at              TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_labeled_examples_event ON labeled_examples(event_verdict_id);
CREATE INDEX IF NOT EXISTS idx_labeled_examples_dest ON labeled_examples(destination_category);

-- ---------------------------------------------------------------------------
-- Content-only DLP labeling pipeline (2026-08-24) — deliberately separate from
-- event_verdicts/labeled_examples above. Track B/C judge a SEND (destination +
-- content + behavior pattern); this table judges a FILE (content alone, no
-- destination/recipient ever shown to the model) — for building a fine-tuning
-- dataset on "is this file confidential/company-related" from content only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS content_labels (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Backfill sources rows from ReportId=215 (see report_filesend.py), which has
    -- no numeric row id the way treportfilesnd.row_auto_increment does (that's a
    -- raw-SQL/report-221 concept report 215 doesn't expose). source_event_id is
    -- therefore a synthetic composite string "<user>|<event_time>|<file_name>" —
    -- the same (user, time, filename) triple content_evidence.py already uses to
    -- correlate across data sources — not a real FK into any other table. Unique,
    -- so re-running the backfill over an overlapping range is a no-op (INSERT OR
    -- IGNORE), not a duplicate.
    source_event_id    TEXT NOT NULL UNIQUE,
    file_name           TEXT NOT NULL,
    file_path            TEXT,              -- full display path as EMP reported it
    event_date            TEXT NOT NULL,     -- 'YYYY-MM-DD' — just the date, not a full timestamp
    -- Full extracted text (content_extract.py's output, already assembled into one
    -- string with page/sheet/slide labels — see content_label_seed.py), stored
    -- directly rather than as a file-path reference: simplest option, avoids a
    -- second storage mechanism, and SQLite handles this volume trivially (≤400
    -- rows x up to 150k chars ≈ tens of MB worst case). Column name kept as
    -- "extracted_text_ref" per spec even though it holds the text itself, not a
    -- pointer to it.
    extracted_text_ref    TEXT,
    is_doc_type            INTEGER NOT NULL DEFAULT 1,  -- 0/1; this table can hold
                                                          -- image rows later too, not
                                                          -- just this first doc-only batch
    model_is_confidential   INTEGER NOT NULL,   -- 0/1
    model_risk_score         INTEGER NOT NULL,  -- 0-100
    model_categories           TEXT NOT NULL,   -- JSON array, same fixed enum as content_analyze.py
    model_related_to_company    INTEGER NOT NULL,  -- 0/1
    model_company_relevance_reasoning TEXT,
    model_summary                 TEXT,
    model_reasoning                 TEXT,
    -- Human review, filled in later via content_review.html — NULL until reviewed
    analyst_decision                 TEXT,     -- 'agree' | 'correct', NULL = not yet reviewed
    analyst_correction                 TEXT,   -- JSON, same field shape as the model_* columns
                                                -- above, only set when analyst_decision='correct'
    reviewed_by                          TEXT, -- app_users.username (denormalized, not an id FK —
                                                -- matches labeled_examples' simplicity elsewhere,
                                                -- but stored as the username string per spec's "text")
    reviewed_at                            TEXT,
    created_at                               TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (analyst_decision IN ('agree', 'correct') OR analyst_decision IS NULL)
);
CREATE INDEX IF NOT EXISTS idx_content_labels_reviewed ON content_labels(analyst_decision);
CREATE INDEX IF NOT EXISTS idx_content_labels_date ON content_labels(event_date);

-- ---------------------------------------------------------------------------
-- Company knowledge feeder (2026-09-14) — durable background facts an analyst
-- wants the content-only labeler to have (store numbering schemes, department
-- names, terminology, anything that lets the model recognize company-relevance
-- from structure/context rather than needing a literal company-name match).
-- Injected into content_label_seed.py's prompt at request time (not baked into
-- model weights — this is context injection / in-context learning, same
-- established pattern as labeled_examples' "Feed to AI", generalized from
-- one-event precedent to durable company facts). Scoped to the content-only
-- labeler for now (2026-09-14, explicit user choice) — NOT wired into Track C's
-- production investigation prompt (content_analyze.py) yet.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS company_knowledge (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    title            TEXT,                          -- short label, optional
    content_text     TEXT NOT NULL,                  -- the actual knowledge text — either
                                                       -- typed directly, or extracted from an
                                                       -- uploaded file via content_extract.py
    source_type      TEXT NOT NULL DEFAULT 'note',   -- 'note' | 'file'
    source_filename   TEXT,                          -- original filename if source_type='file'
    is_active          INTEGER NOT NULL DEFAULT 1,   -- disable without deleting, e.g. to A/B
                                                       -- whether a fact actually helps
    added_by             TEXT,                       -- app_users.username
    added_at               TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (source_type IN ('note', 'file'))
);
CREATE INDEX IF NOT EXISTS idx_company_knowledge_active ON company_knowledge(is_active);
