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

CREATE INDEX IF NOT EXISTS idx_findings_scan      ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_created      ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_created   ON activity_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_scan      ON activity_log(scan_id);
