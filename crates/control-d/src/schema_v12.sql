CREATE TABLE host_review_schedules (
    host_id TEXT PRIMARY KEY REFERENCES host_discovery,
    config_json TEXT NOT NULL,
    route TEXT NOT NULL,
    next_due_at TEXT NOT NULL,
    last_claimed_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE host_reviews (
    review_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES host_discovery,
    config_json TEXT NOT NULL,
    due_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    assessment_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'cancelled', 'expired')),
    lease_hash TEXT,
    grant_hash TEXT,
    lease_until TEXT,
    result_json TEXT,
    completed_at TEXT,
    FOREIGN KEY (host_id, assessment_version) REFERENCES host_discovery_assessments (host_id, version)
);
CREATE UNIQUE INDEX host_reviews_outstanding ON host_reviews(host_id) WHERE status = 'pending';
CREATE INDEX host_review_due ON host_review_schedules(route, next_due_at, host_id);
CREATE INDEX host_review_expiry ON host_reviews(expires_at) WHERE status = 'pending';
CREATE INDEX host_review_latest ON host_reviews(host_id, completed_at DESC, review_id DESC)
    WHERE status = 'completed';
