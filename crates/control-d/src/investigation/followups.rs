use super::*;

/// A question may quote earlier evidence. Its reader must be able to see the
/// collector scope under which it was written, as well as the specific sample.
const VISIBLE: &str = "q.host_id IN (SELECT value FROM json_each(?1))
    AND (?2 IS NULL OR q.incident_id=?2)
    AND NOT EXISTS (SELECT value FROM json_each(q.origin_scope,'$.allowed_collectors')
                    EXCEPT SELECT value FROM json_each(?3))";

pub(super) fn list(
    db: &Connection,
    cap: &ScopedCapability,
    incident: &str,
    policy: u32,
) -> Result<InvestigationResponse> {
    authorize_incident(db, cap, incident)?;
    let sql = format!("SELECT q.proposal_id,q.origin_run,q.watch_id,q.spec_version,q.rationale,
        CASE WHEN q.policy_version<>?4 AND q.finding_id IS NULL THEN 'policy_changed' ELSE q.status END,
        q.deadline,q.observation_id,q.finding_id FROM watch_followup_status q WHERE {VISIBLE}
        ORDER BY q.proposal_id DESC LIMIT 100");
    let followups = rows(
        db,
        &sql,
        params![
            serde_json::to_string(&cap.allowed_hosts)?,
            incident,
            collector_scope_json(cap)?,
            policy
        ],
        |r| {
            Ok(
                json!({"proposal_id":r.get::<_,i64>(0)?,"origin_run":r.get::<_,String>(1)?,
            "watch_id":r.get::<_,String>(2)?,"spec_version":r.get::<_,u32>(3)?,
            "question":r.get::<_,String>(4)?,"status":r.get::<_,String>(5)?,"deadline":r.get::<_,String>(6)?,
            "observation_id":r.get::<_,Option<i64>>(7)?,"finding_id":r.get::<_,Option<i64>>(8)?}),
            )
        },
    )?;
    Ok(InvestigationResponse::WatchFollowups { followups })
}

pub(super) fn claim(
    db: &Connection,
    cap: &ScopedCapability,
    request: &str,
    now: DateTime<Utc>,
    policy: u32,
    sources: Option<&[HostEvidenceScope]>,
    mut start: delegation::Start,
) -> Result<InvestigationResponse> {
    require_investigator(cap)?;
    if !cap.may_spawn_runs || cap.run_id.is_some() {
        return Err(ControlError::denied(
            "an unbound run-spawn grant is required for follow-up",
        ));
    }
    let ttl = start.ttl_seconds.unwrap_or_default();
    if !(1..=900).contains(&ttl) {
        return Err(ControlError::invalid(
            "lease_seconds must be within 1..=900",
        ));
    }
    let sql=format!("SELECT q.proposal_id,q.incident_id,q.rationale,q.deadline,
        o.observation_id,o.host_id,o.watch_id,o.spec_version,o.observed_at,o.status_json,o.state_hash,o.payload_json
        FROM watch_followup_status q JOIN observations o USING(observation_id)
        WHERE {VISIBLE} AND q.status='ready' AND q.policy_version=?4 AND (?5 IS NULL OR EXISTS (
            SELECT 1 FROM json_each(?5) route WHERE json_extract(route.value,'$.host_id')=q.host_id
            AND NOT EXISTS (SELECT value FROM json_each(q.origin_scope,'$.allowed_collectors')
                            EXCEPT SELECT value FROM json_each(route.value,'$.collectors'))))
        ORDER BY q.proposal_id LIMIT 1");
    let row = db
        .query_row(
            &sql,
            params![
                serde_json::to_string(&cap.allowed_hosts)?,
                cap.incident_id,
                collector_scope_json(cap)?,
                policy,
                sources.map(serde_json::to_string).transpose()?
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    parse_stamp(&r.get::<_, String>(3)?, 3)?,
                    ObservationSlice {
                        observation_id: r.get(4)?,
                        host_id: r.get(5)?,
                        watch_id: r.get(6)?,
                        spec_version: r.get(7)?,
                        observed_at: parse_stamp(&r.get::<_, String>(8)?, 8)?,
                        status: json_column(r, 9)?,
                        state_hash: r.get(10)?,
                        payload: json_column(r, 11)?,
                    },
                ))
            },
        )
        .optional()?;
    let Some((proposal_id, incident_id, question, deadline, mut observation)) = row else {
        return Ok(InvestigationResponse::WatchFollowupClaimed { task: None });
    };
    let mut parent = cap.clone();
    parent.expires_at = parent.expires_at.min(deadline);
    start.incident_id = incident_id.clone();
    let grant = delegation::start(db, &parent, request, now, start)?;
    let InvestigationResponse::DelegatedRunStarted {
        run_id, run_token, ..
    } = grant
    else {
        unreachable!("delegation::start returns a delegated run")
    };
    db.execute(
        "INSERT INTO followup_attempts(run_id,proposal_id) VALUES (?1,?2)",
        params![run_id, proposal_id],
    )?;
    // Avoid crossing the frame limit with large package/network inventories.
    // The marker is explicit so the worker can record insufficient evidence.
    if serde_json::to_vec(&observation.payload)?.len() > 128 * 1024 {
        observation.payload = json!({"omitted":"payload exceeds the follow-up evidence limit"});
    }
    Ok(InvestigationResponse::WatchFollowupClaimed {
        task: Some(Box::new(WatchFollowupTask {
            run_id,
            run_token,
            incident_id,
            question,
            observation,
        })),
    })
}

pub(super) struct Assessment {
    pub run_id: String,
    pub observation_id: i64,
    pub interpretation: EvidenceInterpretation,
    pub summary: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

pub(super) fn submit(
    db: &Connection,
    cap: &ScopedCapability,
    request: &str,
    now: DateTime<Utc>,
    policy: u32,
    a: Assessment,
) -> Result<InvestigationResponse> {
    require_investigator(cap)?;
    let incident = authorize_run(db, cap, &a.run_id)?;
    require_text(&a.summary, "summary", 2048)?;
    let row=db.query_row("SELECT q.proposal_id,q.observation_id,q.finding_id,q.status,
        o.state_hash,r.status,length(CAST(o.payload_json AS BLOB)) FROM followup_attempts attempt JOIN watch_followup_status q USING(proposal_id)
        JOIN observations o USING(observation_id) JOIN agent_runs r ON r.run_id=attempt.run_id
        WHERE attempt.run_id=?1 AND q.incident_id=?2 AND q.policy_version=?3 AND o.collector_type IN (SELECT value FROM json_each(?4))",
        params![a.run_id,incident.incident_id,policy,collector_scope_json(cap)?],|r|Ok((
            r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,Option<i64>>(2)?,r.get::<_,String>(3)?,
            r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,usize>(6)?))).optional()?;
    let Some((proposal, observation, prior, status, hash, run_status, payload_size)) = row else {
        return Err(ControlError::denied(
            "follow-up run or evidence is outside scope",
        ));
    };
    if a.observation_id != observation {
        return Err(ControlError::invalid(
            "assessment must cite the requested observation",
        ));
    }
    if payload_size > 128 * 1024 && a.interpretation != EvidenceInterpretation::Unresolved {
        return Err(ControlError::invalid("omitted follow-up evidence cannot support a conclusion"));
    }
    let finding = json!({"kind":FindingKind::Hypothesis,"severity":Severity::Info,"summary":a.summary,
        "interpretation":a.interpretation,"evidence_observation_ids":[observation],
        "uncertainty":"Model interpretation of scoped evidence","escalation_requested":false});
    if let Some(id) = prior {
        let same:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM findings WHERE finding_id=?1 AND run_id=?2 AND finding_json=?3)",
            params![id,a.run_id,finding.to_string()],|r|r.get(0))?;
        if same {
            return Ok(InvestigationResponse::WatchAssessmentRecorded { finding_id: id });
        }
        return Err(ControlError::invalid("follow-up already answered"));
    }
    if status != "leased" || run_status != "active" {
        return Err(ControlError::denied("follow-up is no longer active"));
    }
    db.execute(
        "INSERT INTO findings(run_id,incident_id,finding_json,created_at) VALUES(?1,?2,?3,?4)",
        params![
            a.run_id,
            incident.incident_id,
            finding.to_string(),
            stamp(now)
        ],
    )?;
    let finding_id = db.last_insert_rowid();
    db.execute(
        "INSERT INTO finding_evidence VALUES (?1,?2,?3)",
        params![finding_id, observation, hash],
    )?;
    db.execute(
        "UPDATE watch_followups SET finding_id=?1 WHERE proposal_id=?2",
        params![finding_id, proposal],
    )?;
    audit(
        db,
        FindingRecorded,
        &cap.principal_id,
        request,
        json!({"finding_id":finding_id,"run_id":a.run_id,
        "incident_id":incident.incident_id,"finding":finding,"evidence_hashes":{observation.to_string():hash}}),
    )?;
    let token_hash: String = db.query_row(
        "SELECT token_hash FROM agent_runs WHERE run_id=?1",
        [&a.run_id],
        |r| r.get(0),
    )?;
    progress::finish_run(
        db,
        cap,
        &token_hash,
        request,
        a.run_id,
        RunOutcome {
            status: RunTerminalStatus::Completed,
            summary: "Recorded an evidence assessment.".into(),
            budget_stop_reason: None,
            turns: 1,
            tool_calls: 0,
            input_tokens: a.input_tokens,
            output_tokens: a.output_tokens,
            findings: 1,
            proposals: 0,
            proposals_accepted: 0,
        },
        now,
    )?;
    Ok(InvestigationResponse::WatchAssessmentRecorded { finding_id })
}
