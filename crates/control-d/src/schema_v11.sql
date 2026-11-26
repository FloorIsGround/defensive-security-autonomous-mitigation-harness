CREATE TABLE action_verification_plans (
    intent_id TEXT PRIMARY KEY REFERENCES action_intents,
    host_id TEXT NOT NULL REFERENCES hosts,
    target_key TEXT NOT NULL,
    precondition_id INTEGER REFERENCES observations
);
CREATE INDEX verification_by_target ON action_verification_plans(host_id,target_key);

CREATE TABLE action_effect_checks (
    receipt_id INTEGER PRIMARY KEY REFERENCES action_receipts,
    intent_id TEXT NOT NULL REFERENCES action_verification_plans,
    opened_at TEXT NOT NULL,
    deadline TEXT NOT NULL,
    expected_state TEXT,
    result TEXT NOT NULL CHECK (result IN ('awaiting_evidence','verified','contradicted','indeterminate')),
    reason TEXT NOT NULL,
    observation_id INTEGER REFERENCES observations
);
CREATE INDEX pending_effects ON action_effect_checks(intent_id) WHERE result='awaiting_evidence';
