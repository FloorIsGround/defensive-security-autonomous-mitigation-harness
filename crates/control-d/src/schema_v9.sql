CREATE TABLE host_discovery (
    host_id TEXT PRIMARY KEY REFERENCES hosts,
    deadline TEXT NOT NULL,
    last_polled_at TEXT NOT NULL DEFAULT '',
    latest_version INTEGER NOT NULL DEFAULT 0,
    finished INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX host_discovery_queue ON host_discovery (last_polled_at, host_id);
CREATE TABLE host_discovery_watches (
    host_id TEXT NOT NULL REFERENCES host_discovery,
    collector TEXT NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (host_id, collector),
    FOREIGN KEY (host_id, watch_id, spec_version) REFERENCES watch_specs
);
CREATE TABLE host_discovery_assessments (
    host_id TEXT NOT NULL REFERENCES host_discovery,
    version INTEGER NOT NULL,
    assessment_json TEXT NOT NULL,
    PRIMARY KEY (host_id, version)
);
