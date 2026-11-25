ALTER TABLE incidents ADD COLUMN is_liveness INTEGER NOT NULL DEFAULT 0 CHECK (is_liveness IN (0, 1));

CREATE UNIQUE INDEX one_open_liveness_incident_per_host
ON incidents (host_id) WHERE is_liveness = 1 AND status = 'open';
