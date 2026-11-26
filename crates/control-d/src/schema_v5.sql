CREATE TABLE expectation_rules (
    rule_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts,
    collector_type TEXT NOT NULL,
    watch_id TEXT,
    spec_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('proposed','active','rejected','revoked')),
    origin TEXT NOT NULL CHECK (origin IN ('operator','investigator')),
    proposed_by TEXT NOT NULL,
    run_id TEXT REFERENCES agent_runs,
    incident_id TEXT REFERENCES incidents,
    idempotency_key TEXT,
    backtest_json TEXT,
    created_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    decision_note TEXT,
    expires_at TEXT,
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_matched_at TEXT,
    UNIQUE (run_id, idempotency_key)
);
CREATE INDEX expectation_rules_scope ON expectation_rules (host_id, collector_type, status);

-- Store the original decision for both admitted and denied submissions.
CREATE TABLE expectation_rule_proposal_receipts (
    run_id TEXT NOT NULL REFERENCES agent_runs,
    idempotency_key TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    response_json TEXT NOT NULL,
    PRIMARY KEY (run_id, idempotency_key)
);
