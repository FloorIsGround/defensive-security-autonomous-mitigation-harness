CREATE TABLE rule_activation_grants (
    host_id TEXT NOT NULL REFERENCES hosts,
    collector_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    PRIMARY KEY (host_id, collector_type, principal_id)
);

CREATE TABLE rule_maintenance_evidence (
    rule_id TEXT PRIMARY KEY REFERENCES expectation_rules,
    watch_version INTEGER NOT NULL,
    before_id INTEGER NOT NULL REFERENCES observations,
    after_id INTEGER NOT NULL REFERENCES observations,
    corroborated_by TEXT NOT NULL,
    rationale TEXT NOT NULL,
    corroborated_at TEXT NOT NULL,
    activated INTEGER NOT NULL DEFAULT 0
);
