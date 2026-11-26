ALTER TABLE capability_tokens ADD COLUMN revoked_at TEXT;
ALTER TABLE agent_runs ADD COLUMN delegated INTEGER NOT NULL DEFAULT 0 CHECK (delegated IN (0, 1));
CREATE INDEX delegated_runs_by_principal
    ON agent_runs (principal_id, expires_at) WHERE delegated=1 AND status='active';
CREATE UNIQUE INDEX delegated_runs_by_token ON agent_runs (token_hash) WHERE delegated=1;
