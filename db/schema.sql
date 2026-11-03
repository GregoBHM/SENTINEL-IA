PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    discovered_files INTEGER NOT NULL DEFAULT 0,
    scanned_files INTEGER NOT NULL DEFAULT 0,
    finding_files INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    omitted_checks INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_targets (
    session_id TEXT NOT NULL REFERENCES scan_sessions(id),
    target_path TEXT NOT NULL,
    status TEXT NOT NULL,
    sha256 TEXT,
    error TEXT,
    PRIMARY KEY (session_id, target_path)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES scan_sessions(id),
    target_path TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    reason TEXT NOT NULL,
    sha256 TEXT,
    suppressed INTEGER NOT NULL DEFAULT 0,
    engines_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    engine TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence INTEGER NOT NULL,
    details_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hash_signatures (
    sha256 TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence INTEGER NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS file_cache (
    target_path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    ctime_ns INTEGER NOT NULL,
    inode INTEGER NOT NULL,
    device INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reputation_cache (
    provider TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    response_json TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    checked_ts REAL NOT NULL,
    PRIMARY KEY(provider, sha256)
);
CREATE TABLE IF NOT EXISTS api_quotas (
    provider TEXT NOT NULL,
    utc_day TEXT NOT NULL,
    requests INTEGER NOT NULL,
    PRIMARY KEY(provider, utc_day)
);
CREATE TABLE IF NOT EXISTS whitelist (
    sha256 TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS ix_evidence_finding ON evidence(finding_id);

CREATE TABLE IF NOT EXISTS scan_coverage (
    session_id TEXT NOT NULL REFERENCES scan_sessions(id),
    target_path TEXT NOT NULL,
    engine TEXT NOT NULL,
    event_code TEXT NOT NULL,
    params_json TEXT NOT NULL,
    detail TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(session_id, target_path, engine, event_code)
);
CREATE INDEX IF NOT EXISTS ix_scan_coverage_session ON scan_coverage(session_id);


-- Phase 5. Quarantine state transitions are explicit to allow interrupted-operation review.
CREATE TABLE IF NOT EXISTS quarantine_items (
    id TEXT PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    original_path TEXT NOT NULL,
    stored_path TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN
        ('prepared','quarantined','restoring','restored','deleting','deleted','needs_review','failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS ix_quarantine_status ON quarantine_items(status);

CREATE TABLE IF NOT EXISTS disabled_autoruns (
    id TEXT PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    hive TEXT NOT NULL CHECK(hive='HKCU'),
    key_path TEXT NOT NULL,
    value_name TEXT NOT NULL,
    value_data TEXT NOT NULL,
    value_type INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('prepared','disabled','restored','needs_review')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
