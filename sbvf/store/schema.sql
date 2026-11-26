-- SBVF persistence schema (PostgreSQL). Applied idempotently on startup by
-- sbvf/store/migrate.py. The core scanner never touches this; it is written
-- only through sbvf/store/repository.py.

CREATE TABLE IF NOT EXISTS scans (
    id            BIGSERIAL PRIMARY KEY,
    created_at    timestamptz NOT NULL DEFAULT now(),
    target        text,                       -- raw request target (folder/url/sample)
    display_root  text,                       -- root as shown in the UI
    scan_type     text,                       -- 'sample' | 'local' | 'repo'
    frameworks    jsonb NOT NULL DEFAULT '{}'::jsonb,
    files_scanned integer NOT NULL DEFAULT 0,
    counts        jsonb NOT NULL DEFAULT '{}'::jsonb,
    status        text NOT NULL DEFAULT 'completed',   -- 'completed' | 'error'
    duration_ms   integer,
    error         text
);

CREATE TABLE IF NOT EXISTS findings (
    id         BIGSERIAL PRIMARY KEY,
    scan_id    bigint NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    idx        integer NOT NULL DEFAULT 0,    -- order within the scan
    vuln       text,
    cwe        text,
    severity   text,
    title      text,
    file       text,
    line       integer,
    col        integer,
    sink       text,
    source     text,
    param      text,
    method     text,
    function   text,
    framework  text,
    rule       text,
    code       text,
    message    text,
    how_in     text,
    impact     text,
    owner      text,
    action     text,
    exposure   jsonb NOT NULL DEFAULT '[]'::jsonb,
    fix        jsonb NOT NULL DEFAULT '[]'::jsonb
);

-- Append-only audit / change log of every meaningful event.
CREATE TABLE IF NOT EXISTS activity_log (
    id          BIGSERIAL PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    scan_id     bigint REFERENCES scans(id) ON DELETE SET NULL,
    entity_type text NOT NULL,                -- 'scan' | 'finding' | 'agent' | 'system'
    entity_id   bigint,
    action      text NOT NULL,               -- 'scan.created' | 'scan.deleted' | ...
    actor       text NOT NULL DEFAULT 'system',
    details     jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- ---------------------------------------------------------------------------
-- Phase 2: AI-agents layer. All optional; written only through repository.py
-- when an AI provider is configured. The core scanner never touches these.
-- ---------------------------------------------------------------------------

-- One row per agent invocation over a scan (audit of the AI runs themselves).
CREATE TABLE IF NOT EXISTS agent_runs (
    id          BIGSERIAL PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    scan_id     bigint NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    agent       text NOT NULL,               -- 'triage' | 'remediation' | 'prioritization'
    provider    text,                        -- 'claude' | 'openai' | 'ollama'
    model       text,
    status      text NOT NULL DEFAULT 'completed',   -- 'completed' | 'error'
    duration_ms integer,
    error       text,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- Per-finding AI assessment: triage (false-positive judgement) + remediation,
-- merged into one row per analysis run. Reads take the most recent per finding.
CREATE TABLE IF NOT EXISTS finding_assessments (
    id                 BIGSERIAL PRIMARY KEY,
    created_at         timestamptz NOT NULL DEFAULT now(),
    scan_id            bigint NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id         bigint REFERENCES findings(id) ON DELETE CASCADE,
    finding_idx        integer NOT NULL,     -- stable position within the scan
    provider           text,
    model              text,
    is_false_positive  boolean,
    confidence         real,
    rationale          text,
    remediation_summary text,
    remediation        text,
    agents             jsonb NOT NULL DEFAULT '[]'::jsonb,   -- which agents contributed
    details            jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- Scan-level risk prioritization (one summary + a ranking array per run).
CREATE TABLE IF NOT EXISTS scan_prioritizations (
    id          BIGSERIAL PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    scan_id     bigint NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    provider    text,
    model       text,
    summary     text,
    ranking     jsonb NOT NULL DEFAULT '[]'::jsonb
);

-- Q&A over scan history: each user question and assistant answer. Scoped to a
-- scan when the question was asked from a scan's page, else global (scan_id NULL).
CREATE TABLE IF NOT EXISTS chat_messages (
    id          BIGSERIAL PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    scan_id     bigint REFERENCES scans(id) ON DELETE SET NULL,
    role        text NOT NULL,               -- 'user' | 'assistant'
    content     text NOT NULL,
    provider    text,
    model       text,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- ---------------------------------------------------------------------------
-- Multi-user layer (optional). Active only when the server runs with SBVF_AUTH
-- set; the tables are created regardless but stay empty otherwise. Written only
-- through repository.py. Scans gain a nullable owner_id: pre-auth / unowned
-- scans keep NULL and are visible to admins only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      text UNIQUE NOT NULL,
    password_hash text NOT NULL,              -- scrypt$n$r$p$salt$hash (see auth.py)
    role          text NOT NULL DEFAULT 'user',   -- 'admin' | 'user'
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

CREATE TABLE IF NOT EXISTS sessions (
    id          BIGSERIAL PRIMARY KEY,
    token_hash  text UNIQUE NOT NULL,          -- sha256 of the cookie token (never the token)
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);

-- Owner of a scan (NULL for scans created before auth was enabled).
ALTER TABLE scans ADD COLUMN IF NOT EXISTS owner_id bigint REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_findings_scan      ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_created      ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_created   ON activity_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_scan      ON activity_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_scan    ON agent_runs(scan_id);
CREATE INDEX IF NOT EXISTS idx_assessments_scan   ON finding_assessments(scan_id);
CREATE INDEX IF NOT EXISTS idx_prioritizations_scan ON scan_prioritizations(scan_id);
CREATE INDEX IF NOT EXISTS idx_chat_scan          ON chat_messages(scan_id, created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token      ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires    ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_scans_owner         ON scans(owner_id);
