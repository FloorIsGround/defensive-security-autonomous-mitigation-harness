ALTER TABLE agent_runs ADD COLUMN ended_at TEXT;
ALTER TABLE agent_runs ADD COLUMN outcome_json TEXT;
CREATE TABLE run_events (
    event_seq INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES agent_runs,
    kind TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX run_events_by_run ON run_events (run_id, event_seq);
