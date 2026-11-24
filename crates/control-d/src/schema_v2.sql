CREATE TABLE action_proposals (
    proposal_id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES agent_runs,
    idempotency_key TEXT NOT NULL,
    host_id TEXT NOT NULL REFERENCES hosts,
    incident_id TEXT NOT NULL REFERENCES incidents,
    verb_json TEXT NOT NULL,
    expected_effect TEXT NOT NULL,
    blast_radius TEXT NOT NULL,
    rollback_plan TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    auth_mode_json TEXT,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (run_id, idempotency_key)
);
CREATE TABLE action_intents (
    intent_id TEXT PRIMARY KEY,
    proposal_id INTEGER NOT NULL UNIQUE REFERENCES action_proposals,
    nonce TEXT NOT NULL UNIQUE,
    host_id TEXT NOT NULL REFERENCES hosts,
    incident_id TEXT NOT NULL REFERENCES incidents,
    auth_mode_json TEXT NOT NULL,
    status_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    control_envelope_json TEXT NOT NULL,
    operator_approval_json TEXT,
    approver TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX action_intents_by_host ON action_intents (host_id, updated_at);
CREATE INDEX action_intents_by_incident ON action_intents (incident_id, proposal_id);
CREATE TABLE action_receipts (
    receipt_id INTEGER PRIMARY KEY,
    intent_id TEXT NOT NULL REFERENCES action_intents,
    host_id TEXT NOT NULL REFERENCES hosts,
    status_json TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE INDEX action_receipts_by_intent ON action_receipts (intent_id);
ALTER TABLE policy_decisions ADD COLUMN action_proposal_id INTEGER REFERENCES action_proposals;
