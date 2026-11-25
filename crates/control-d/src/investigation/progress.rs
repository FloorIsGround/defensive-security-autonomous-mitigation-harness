use defsec_protocol::{audit::AuditEventType::RunFinished, canonical::value_to_canonical_json};
use rusqlite::{Row, types::ValueRef};

use super::*;

pub(super) fn report_progress(
    db: &Connection,
    capability: &ScopedCapability,
    run_id: String,
    kind: RunEventKind,
    detail: Value,
    now: DateTime<Utc>,
) -> Result<InvestigationResponse> {
    require_investigator(capability)?;
    authorize_run(db, capability, &run_id)?;
    let detail = value_to_canonical_json(&detail)?;
    if detail.len() > 4096 {
        return Err(ControlError::invalid("run event detail exceeds 4096 bytes"));
    }
    let count: u32 = db.query_row(
        "SELECT COUNT(*) FROM run_events WHERE run_id=?1",
        [&run_id],
        |r| r.get(0),
    )?;
    if count >= 256 {
        return Err(ControlError::Request {
            code: "run_event_quota",
            message: "run event quota of 256 reached".into(),
        });
    }
    db.execute(
        "INSERT INTO run_events (run_id, kind, detail_json, created_at) VALUES (?1,?2,?3,?4)",
        params![run_id, enum_tag(kind), detail, stamp(now)],
    )?;
    Ok(InvestigationResponse::RunProgressRecorded {
        run_id,
        event_seq: db.last_insert_rowid(),
    })
}

pub(super) fn finish_run(
    db: &Connection,
    capability: &ScopedCapability,
    token_hash: &str,
    request_id: &str,
    run_id: String,
    outcome: RunOutcome,
    now: DateTime<Utc>,
) -> Result<InvestigationResponse> {
    require_investigator(capability)?;
    let previous = db
        .query_row(
            "SELECT incident_id, status, outcome_json FROM agent_runs WHERE run_id=?1 AND token_hash=?2",
            params![run_id, token_hash],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    optional_json::<RunOutcome>(r, 2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| ControlError::denied("run is outside capability scope"))?;
    let (incident_id, status, recorded_outcome) = previous;
    authorize_incident(db, capability, &incident_id)?;
    if outcome.summary.len() > 2048
        || outcome
            .budget_stop_reason
            .as_ref()
            .is_some_and(|reason| reason.len() > 64)
    {
        return Err(ControlError::invalid(
            "run summary or budget stop reason exceeds byte limit",
        ));
    }
    if status == "active" {
        db.execute(
            "UPDATE agent_runs SET status=?2, ended_at=?3, outcome_json=?4 WHERE run_id=?1",
            params![
                run_id,
                enum_tag(outcome.status),
                stamp(now),
                serde_json::to_string(&outcome)?
            ],
        )?;
        audit(
            db,
            RunFinished,
            &capability.principal_id,
            request_id,
            json!({"run_id": run_id, "incident_id": incident_id, "outcome": outcome}),
        )?;
    } else if recorded_outcome.as_ref() != Some(&outcome) {
        return Err(ControlError::Request {
            code: "conflict",
            message: "run already finished with a different outcome".into(),
        });
    }
    Ok(InvestigationResponse::RunFinished {
        run_id,
        status: outcome.status,
    })
}

fn enum_tag(value: impl serde::Serialize) -> String {
    match json!(value) {
        Value::String(tag) => tag,
        _ => unreachable!("expected a unit enum"),
    }
}

fn optional_json<T: serde::de::DeserializeOwned>(
    row: &Row<'_>,
    col: usize,
) -> rusqlite::Result<Option<T>> {
    if matches!(row.get_ref(col)?, ValueRef::Null) {
        Ok(None)
    } else {
        json_column(row, col).map(Some)
    }
}

fn timestamp(row: &Row<'_>, col: usize) -> rusqlite::Result<DateTime<Utc>> {
    parse_stamp(row.get_ref(col)?.as_str()?, col)
}

fn optional_timestamp(row: &Row<'_>, col: usize) -> rusqlite::Result<Option<DateTime<Utc>>> {
    row.get::<_, Option<String>>(col)?
        .map(|s| parse_stamp(&s, col))
        .transpose()
}

fn run_event(row: &Row<'_>, col: usize) -> rusqlite::Result<RunEvent> {
    let kind: String = row.get(col + 1)?;
    let kind = serde_json::from_value(Value::String(kind)).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            col + 1,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(RunEvent {
        event_seq: row.get(col)?,
        kind,
        detail: json_column(row, col + 2)?,
        created_at: timestamp(row, col + 3)?,
    })
}

fn check_filters(
    db: &Connection,
    capability: &ScopedCapability,
    host_id: Option<&str>,
    incident_id: Option<&str>,
) -> Result<()> {
    if let Some(host) = host_id {
        authorize_host(capability, host)?;
    }
    if let Some(incident) = incident_id {
        authorize_incident(db, capability, incident)?;
    }
    Ok(())
}

pub(super) fn list_runs(
    db: &Connection,
    capability: &ScopedCapability,
    host_id: Option<&str>,
    incident_id: Option<&str>,
    limit: Option<u32>,
    now: DateTime<Utc>,
) -> Result<Vec<RunSummary>> {
    check_filters(db, capability, host_id, incident_id)?;
    rows(
        db,
        "SELECT r.run_id,r.incident_id,i.host_id,r.principal_id,r.backend_id,r.model_id,
                r.status,r.started_at,r.expires_at,r.ended_at,r.outcome_json,
                (SELECT COUNT(*) FROM run_events WHERE run_id=r.run_id),
                (SELECT COUNT(*) FROM findings WHERE run_id=r.run_id),
                (SELECT COUNT(*) FROM watch_proposals WHERE run_id=r.run_id)
                    + (SELECT COUNT(*) FROM action_proposals WHERE run_id=r.run_id),
                e.event_seq,e.kind,e.detail_json,e.created_at
         FROM agent_runs r JOIN incidents i USING (incident_id)
         LEFT JOIN run_events e ON e.event_seq=(
             SELECT MAX(event_seq) FROM run_events WHERE run_id=r.run_id
         )
         WHERE i.host_id IN (SELECT value FROM json_each(?1))
           AND (?2 IS NULL OR r.incident_id=?2)
           AND (?3 IS NULL OR i.host_id=?3)
         ORDER BY r.started_at DESC, r.rowid DESC LIMIT ?4",
        params![
            serde_json::to_string(&capability.allowed_hosts)?,
            incident_id.or(capability.incident_id.as_deref()),
            host_id,
            bounded(limit),
        ],
        |r| {
            let mut status: String = r.get(6)?;
            let expires_at = timestamp(r, 8)?;
            if status == "active" && expires_at <= now {
                status = "expired".into();
            } else if status == "closed" {
                status = "cancelled".into();
            }
            Ok(RunSummary {
                run_id: r.get(0)?,
                incident_id: r.get(1)?,
                host_id: r.get(2)?,
                principal_id: r.get(3)?,
                backend_id: r.get(4)?,
                model_id: r.get(5)?,
                status,
                started_at: timestamp(r, 7)?,
                expires_at,
                ended_at: optional_timestamp(r, 9)?,
                outcome: optional_json(r, 10)?,
                event_count: r.get(11)?,
                findings_count: r.get(12)?,
                proposals_count: r.get(13)?,
                last_event: if matches!(r.get_ref(14)?, ValueRef::Null) {
                    None
                } else {
                    Some(run_event(r, 14)?)
                },
            })
        },
    )
}

pub(super) fn get_events(
    db: &Connection,
    capability: &ScopedCapability,
    run_id: &str,
    after_seq: Option<i64>,
    limit: Option<u32>,
) -> Result<Vec<RunEvent>> {
    let incident_id: String = db
        .query_row(
            "SELECT incident_id FROM agent_runs WHERE run_id=?1",
            [run_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| ControlError::denied("run is outside capability scope"))?;
    authorize_incident(db, capability, &incident_id)?;
    rows(
        db,
        "SELECT event_seq,kind,detail_json,created_at FROM run_events
         WHERE run_id=?1 AND event_seq>?2 ORDER BY event_seq LIMIT ?3",
        params![run_id, after_seq.unwrap_or(0), bounded(limit)],
        |r| run_event(r, 0),
    )
}

pub(super) fn list_triggers(
    db: &Connection,
    capability: &ScopedCapability,
    host_id: Option<&str>,
    incident_id: Option<&str>,
    statuses: Option<Vec<String>>,
    limit: Option<u32>,
) -> Result<Vec<TriggerSummary>> {
    const STATUSES: &[&str] = &["pending", "leased", "done", "dead_letter"];
    let statuses = if let Some(ref statuses) = statuses {
        if statuses.iter().any(|s| !STATUSES.contains(&s.as_str())) {
            return Err(ControlError::invalid("unknown trigger queue status"));
        }
        serde_json::to_string(statuses)?
    } else {
        serde_json::to_string(STATUSES)?
    };
    check_filters(db, capability, host_id, incident_id)?;
    rows(
        db,
        "SELECT event_id,incident_id,host_id,watch_id,status,created_at,updated_at,lease_owner,
                lease_expires_at,retry_count,
                CASE WHEN json_type(outcome_json, '$.reason')='text'
                     THEN json_extract(outcome_json, '$.reason') END
         FROM trigger_events
         WHERE host_id IN (SELECT value FROM json_each(?1))
           AND (?2 IS NULL OR incident_id=?2)
           AND (?3 IS NULL OR host_id=?3)
           AND status IN (SELECT value FROM json_each(?4))
         ORDER BY event_id DESC LIMIT ?5",
        params![
            serde_json::to_string(&capability.allowed_hosts)?,
            incident_id.or(capability.incident_id.as_deref()),
            host_id,
            statuses,
            bounded(limit),
        ],
        |r| {
            let reason = r.get::<_, Option<String>>(10)?.map(|mut reason| {
                reason.truncate(reason.floor_char_boundary(512));
                reason
            });
            Ok(TriggerSummary {
                event_id: r.get(0)?,
                incident_id: r.get(1)?,
                host_id: r.get(2)?,
                watch_id: r.get(3)?,
                status: r.get(4)?,
                created_at: timestamp(r, 5)?,
                updated_at: timestamp(r, 6)?,
                lease_owner: r.get(7)?,
                lease_expires_at: optional_timestamp(r, 8)?,
                retry_count: r.get(9)?,
                reason,
            })
        },
    )
}
