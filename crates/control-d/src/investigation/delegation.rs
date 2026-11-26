use defsec_protocol::audit::AuditEventType::RunFinished;

use super::*;

pub(super) struct Start {
    pub incident_id: String,
    pub backend_id: String,
    pub model_id: String,
    pub prompt_schema_version: String,
    pub ttl_seconds: Option<u64>,
}

pub(super) fn start(
    db: &Connection,
    parent: &ScopedCapability,
    request_id: &str,
    now: DateTime<Utc>,
    start: Start,
) -> Result<InvestigationResponse> {
    require_investigator(parent)?;
    if !parent.may_spawn_runs || parent.run_id.is_some() {
        return Err(ControlError::denied(
            "capability cannot spawn delegated runs",
        ));
    }
    let Start {
        incident_id,
        backend_id,
        model_id,
        prompt_schema_version,
        ttl_seconds,
    } = start;
    let incident = authorize_incident(db, parent, &incident_id)?;
    require_open(&incident)?;
    require_text(&backend_id, "backend_id", 128)?;
    require_text(&model_id, "model_id", 128)?;
    require_text(&prompt_schema_version, "prompt_schema_version", 128)?;
    let ttl = ttl_seconds.unwrap_or(3600).min(3600);
    if ttl == 0 {
        return Err(ControlError::invalid("delegated run TTL must be positive"));
    }
    let active: u32 = db.query_row(
        "SELECT COUNT(*) FROM agent_runs
         WHERE principal_id=?1 AND delegated=1 AND status='active' AND expires_at>?2",
        params![parent.principal_id, stamp(now)],
        |r| r.get(0),
    )?;
    if active >= 4 {
        return Err(ControlError::Request {
            code: "delegated_run_quota",
            message: "active delegated run quota of 4 reached".into(),
        });
    }
    let run_id = uuid();
    let expires_at = parent.expires_at.min(now + Duration::seconds(ttl as i64));
    let child = ScopedCapability {
        principal_id: parent.principal_id.clone(),
        role: PrincipalRole::Investigator,
        run_id: Some(run_id.clone()),
        incident_id: Some(incident_id.clone()),
        may_spawn_runs: false,
        allowed_hosts: vec![incident.host_id],
        allowed_collectors: parent.allowed_collectors.clone(),
        expires_at,
    };
    let (run_token, child_hash) = store_capability_token(db, &child)?;
    db.execute(
        "INSERT INTO agent_runs (run_id,incident_id,token_hash,principal_id,backend_id,
            model_id,prompt_schema_version,started_at,expires_at,delegated)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
        params![
            run_id,
            incident_id,
            child_hash,
            child.principal_id,
            backend_id,
            model_id,
            prompt_schema_version,
            stamp(now),
            stamp(expires_at)
        ],
    )?;
    audit(
        db,
        RunStarted,
        &child.principal_id,
        request_id,
        json!({"run_id":run_id,"incident_id":incident_id,"backend_id":backend_id,
            "model_id":model_id,"prompt_schema_version":prompt_schema_version,
            "expires_at":expires_at,"delegated":true}),
    )?;
    Ok(InvestigationResponse::DelegatedRunStarted {
        run_id,
        incident_id,
        expires_at,
        run_token,
    })
}

pub(super) fn cancel(
    db: &Connection,
    capability: &ScopedCapability,
    hash: &str,
    request_id: &str,
    run_id: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<InvestigationResponse> {
    require_investigator(capability)?;
    require_text(reason, "reason", 2048)?;
    let (incident_id, child_hash, status) = db
        .query_row(
            "SELECT incident_id,token_hash,status FROM agent_runs WHERE run_id=?1
         AND (token_hash=?2 OR (delegated=1 AND principal_id=?3 AND ?4))",
            params![
                run_id,
                hash,
                capability.principal_id,
                capability.run_id.is_none() && capability.may_spawn_runs
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| ControlError::denied("run is outside capability scope"))?;
    authorize_incident(db, capability, &incident_id)?;
    if status == "active" {
        progress::record_terminal_tool_result(db, run_id, request_id, "cancel_investigation", now)?;
        let outcome = RunOutcome {
            status: RunTerminalStatus::Cancelled,
            summary: reason.into(),
            budget_stop_reason: None,
            turns: 0,
            tool_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
            findings: 0,
            proposals: 0,
            proposals_accepted: 0,
        };
        db.execute(
            "UPDATE agent_runs SET status='cancelled',ended_at=?2,outcome_json=?3 WHERE run_id=?1",
            params![run_id, stamp(now), serde_json::to_string(&outcome)?],
        )?;
        db.execute(
            "UPDATE capability_tokens SET revoked_at=?2 WHERE token_hash=?1",
            params![child_hash, stamp(now)],
        )?;
        audit(
            db,
            RunFinished,
            &capability.principal_id,
            request_id,
            json!({"run_id":run_id,"incident_id":incident_id,"outcome":outcome}),
        )?;
    } else if status != "cancelled" {
        return Err(ControlError::Request {
            code: "conflict",
            message: "run already finished".into(),
        });
    }
    Ok(InvestigationResponse::RunFinished {
        run_id: run_id.into(),
        status: RunTerminalStatus::Cancelled,
    })
}
