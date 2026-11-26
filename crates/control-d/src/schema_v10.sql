CREATE TABLE monitoring_grants (
    host_id TEXT NOT NULL REFERENCES hosts,
    principal_id TEXT NOT NULL,
    max_watches INTEGER NOT NULL,
    allow_promotion INTEGER NOT NULL,
    PRIMARY KEY (host_id, principal_id)
);
CREATE TABLE monitoring_watches (
    host_id TEXT NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    principal_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    intent_json TEXT NOT NULL,
    PRIMARY KEY (host_id, watch_id),
    FOREIGN KEY (host_id, watch_id, spec_version) REFERENCES watch_specs
);
CREATE TABLE monitoring_candidates (
    candidate_id INTEGER PRIMARY KEY,
    host_id TEXT NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    observation_id INTEGER NOT NULL REFERENCES observations,
    confirmation_id INTEGER NOT NULL REFERENCES observations,
    principal_id TEXT NOT NULL,
    rationale TEXT NOT NULL,
    predecessor_id INTEGER REFERENCES baseline_revisions,
    corroboration TEXT,
    promoted_id INTEGER REFERENCES baseline_revisions,
    FOREIGN KEY (host_id, watch_id, spec_version) REFERENCES watch_specs
);
