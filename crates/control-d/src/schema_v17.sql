CREATE TABLE IF NOT EXISTS host_discovery_interpretation_attempts (
    lease_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id),
    source_ids TEXT NOT NULL,
    collectors TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    request_id TEXT NOT NULL,
    lease_until TEXT NOT NULL,
    retry_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('leased','failed','saved','cancelled')),
    usage_json TEXT,
    error_class TEXT,
    assessment_version INTEGER,
    UNIQUE (token_hash, request_id)
);
CREATE INDEX IF NOT EXISTS discovery_interpretation_source
    ON host_discovery_interpretation_attempts (host_id, source_ids);
