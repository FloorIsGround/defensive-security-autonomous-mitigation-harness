CREATE TABLE hosts (
    host_id TEXT PRIMARY KEY,
    agent_public_key_hex TEXT,
    agent_version TEXT NOT NULL DEFAULT '',
    boot_id TEXT,
    session_id TEXT,
    last_heartbeat_at TEXT,
    health_json TEXT,
    liveness_status TEXT NOT NULL DEFAULT 'enrolled',
    active_bundle_version INTEGER NOT NULL DEFAULT 0,
    desired_bundle_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE agent_sessions (
    host_id TEXT NOT NULL REFERENCES hosts,
    session_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    acked_seq_no INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, session_id)
);
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts,
    status TEXT NOT NULL,
    priority_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_by TEXT,
    resolution TEXT
);
CREATE TABLE watch_specs (
    host_id TEXT NOT NULL REFERENCES hosts,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    incident_id TEXT REFERENCES incidents,
    spec_json TEXT NOT NULL,
    creator TEXT NOT NULL,
    active INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (host_id, watch_id, spec_version)
);
CREATE UNIQUE INDEX active_watch ON watch_specs (host_id, watch_id) WHERE active = 1;
CREATE TABLE observations (
    observation_id INTEGER PRIMARY KEY,
    host_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    seq_no INTEGER NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    collector_type TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    status_json TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    sample_json TEXT,
    record_json TEXT NOT NULL,
    UNIQUE (host_id, session_id, seq_no),
    FOREIGN KEY (host_id, watch_id, spec_version) REFERENCES watch_specs,
    FOREIGN KEY (host_id, session_id) REFERENCES agent_sessions
);
CREATE INDEX observations_by_watch ON observations (host_id, watch_id, observation_id);
CREATE TABLE baseline_revisions (
    revision_id INTEGER PRIMARY KEY,
    host_id TEXT NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    predecessor_id INTEGER REFERENCES baseline_revisions,
    observation_id INTEGER NOT NULL REFERENCES observations,
    state_hash TEXT NOT NULL,
    sample_json TEXT NOT NULL,
    approver TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    rationale TEXT NOT NULL,
    ticket_ref TEXT,
    policy_version INTEGER NOT NULL,
    FOREIGN KEY (host_id, watch_id, spec_version) REFERENCES watch_specs
);
CREATE TABLE watch_state (
    host_id TEXT NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    last_observation_id INTEGER REFERENCES observations,
    last_success_id INTEGER REFERENCES observations,
    baseline_revision_id INTEGER REFERENCES baseline_revisions,
    last_success_at TEXT,
    observation_errors INTEGER NOT NULL DEFAULT 0,
    summary_errors INTEGER NOT NULL DEFAULT 0,
    outcome_json TEXT,
    summary_json TEXT,
    summary_session_id TEXT,
    retired INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, watch_id, spec_version),
    FOREIGN KEY (host_id, watch_id, spec_version) REFERENCES watch_specs
);
CREATE TABLE trigger_events (
    event_id INTEGER PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents,
    host_id TEXT NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL,
    outcome_json TEXT NOT NULL,
    lease_owner TEXT,
    lease_token TEXT,
    lease_expires_at TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (host_id, watch_id, spec_version) REFERENCES watch_specs
);
CREATE INDEX trigger_coalescing ON trigger_events (host_id, watch_id, fingerprint, created_at);
CREATE TABLE trigger_evidence (
    event_id INTEGER NOT NULL REFERENCES trigger_events,
    observation_id INTEGER NOT NULL REFERENCES observations,
    PRIMARY KEY (event_id, observation_id)
);
CREATE TABLE capability_tokens (
    token_hash TEXT PRIMARY KEY,
    capability_json TEXT NOT NULL
);
CREATE TABLE agent_runs (
    run_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents,
    token_hash TEXT NOT NULL REFERENCES capability_tokens,
    principal_id TEXT NOT NULL,
    backend_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    prompt_schema_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE watch_proposals (
    proposal_id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES agent_runs,
    idempotency_key TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents,
    fingerprint TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    rationale TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (run_id, idempotency_key)
);
CREATE TABLE policy_decisions (
    decision_id INTEGER PRIMARY KEY,
    proposal_id INTEGER REFERENCES watch_proposals,
    actor TEXT NOT NULL,
    request_id TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE findings (
    finding_id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES agent_runs,
    incident_id TEXT NOT NULL REFERENCES incidents,
    finding_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE finding_evidence (
    finding_id INTEGER NOT NULL REFERENCES findings,
    observation_id INTEGER NOT NULL REFERENCES observations,
    state_hash TEXT NOT NULL,
    PRIMARY KEY (finding_id, observation_id)
);
CREATE TABLE wake_budget_state (
    event_id INTEGER PRIMARY KEY REFERENCES trigger_events,
    host_id TEXT NOT NULL REFERENCES hosts,
    watch_id TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents,
    woke_at TEXT NOT NULL
);
CREATE INDEX recent_wakes ON wake_budget_state (woke_at);
CREATE TABLE audit_outbox (
    seq_no INTEGER PRIMARY KEY,
    entry_hash TEXT NOT NULL,
    entry_json TEXT NOT NULL
);
CREATE TABLE issued_bundles (
    host_id TEXT NOT NULL REFERENCES hosts,
    bundle_version INTEGER NOT NULL,
    bundle_id TEXT NOT NULL UNIQUE,
    payload_digest TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ack_json TEXT,
    PRIMARY KEY (host_id, bundle_version)
);
