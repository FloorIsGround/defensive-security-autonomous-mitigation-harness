CREATE TABLE watch_followups (
    proposal_id INTEGER PRIMARY KEY REFERENCES watch_proposals,
    host_id TEXT NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    admitted_at TEXT NOT NULL,
    deadline TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    cursor INTEGER NOT NULL,
    observation_id INTEGER REFERENCES observations,
    finding_id INTEGER UNIQUE REFERENCES findings,
    UNIQUE (host_id, watch_id, spec_version),
    FOREIGN KEY (host_id, watch_id, spec_version) REFERENCES watch_specs
);
CREATE TABLE followup_attempts (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs,
    proposal_id INTEGER NOT NULL REFERENCES watch_followups
);
CREATE INDEX followup_attempts_by_question ON followup_attempts(proposal_id);
CREATE VIEW watch_followup_status AS
SELECT q.*,p.incident_id,p.rationale,p.run_id AS origin_run,w.spec_json,
       c.capability_json AS origin_scope,
       CASE WHEN q.finding_id IS NOT NULL THEN 'answered'
            WHEN i.status <> 'open' OR r.status = 'cancelled' OR c.revoked_at IS NOT NULL
                 OR (w.active <> 1 AND q.observation_id IS NULL) OR EXISTS
                    (SELECT 1 FROM followup_attempts a JOIN agent_runs attempt USING(run_id)
                     WHERE a.proposal_id=q.proposal_id AND attempt.status='cancelled') THEN 'cancelled'
            WHEN julianday(q.deadline) <= julianday('now') THEN 'expired'
            WHEN EXISTS (SELECT 1 FROM followup_attempts a JOIN agent_runs attempt USING(run_id)
                         WHERE a.proposal_id=q.proposal_id AND attempt.status='active'
                           AND julianday(attempt.expires_at)>julianday('now')) THEN 'leased'
            WHEN (SELECT COUNT(*) FROM followup_attempts a WHERE a.proposal_id=q.proposal_id)>=3 THEN 'exhausted'
            WHEN q.observation_id IS NULL THEN 'awaiting_evidence'
            ELSE 'ready' END AS status
FROM watch_followups q JOIN watch_proposals p USING(proposal_id)
JOIN agent_runs r ON r.run_id=p.run_id JOIN capability_tokens c ON c.token_hash=r.token_hash
JOIN incidents i ON i.incident_id=p.incident_id
JOIN watch_specs w USING(host_id,watch_id,spec_version);
