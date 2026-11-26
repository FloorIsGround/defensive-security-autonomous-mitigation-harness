ALTER TABLE agent_runs ADD COLUMN trigger_event_id INTEGER REFERENCES trigger_events;
ALTER TABLE agent_runs ADD COLUMN trigger_lease_token TEXT;
-- Pending legacy candidates must be corroborated again by an authenticated admin.
ALTER TABLE monitoring_candidates ADD COLUMN corroborated_by TEXT;
