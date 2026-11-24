use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use defsec_policy::control_gate::{
    ProposalContext, evaluate_watch_proposal, watch_target_fingerprint,
};
use defsec_protocol::{
    audit::AuditEventType::{FindingRecorded, RunStarted, WatchProposed},
    canonical::sha256_hex,
    rpc::*,
    watch::{CollectorCapability, CollectorType, DataClassification, WatchClass, WatchSpec},
    wire::MAX_FRAME_BYTES,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::{
    ledger::{audit, json_column, rows},
    service::{
        ControlError, ControlService, Result, active_watches, get_incident, insert_watch,
        latest_spec, list_hosts, list_incidents, parse_stamp, record_decision, require_host, stamp,
        uuid,
    },
};

impl ControlService {
    pub fn handle_investigation_call(&self, call: InvestigationCall) -> InvestigationResponse {
        match self.transaction(|db| self.investigate(db, call)) {
            Ok(response) => {
                if matches!(
                    response,
                    InvestigationResponse::ProposalEvaluated {
                        bundle_version: Some(_),
                        ..
                    }
                ) {
                    self.bundle_changed();
                }
                response
            }
            Err(error) => {
                let (code, message) = error.response_parts();
                InvestigationResponse::Error { code, message }
            }
        }
    }

    fn investigate(
        &self,
        db: &Connection,
        call: InvestigationCall,
    ) -> Result<InvestigationResponse> {
        let now = Utc::now();
        let request_id = &call.request_id;
        require_text(request_id, "request_id", 128)?;
        let hash = sha256_hex(call.capability_token.as_bytes());
        let mut capability: ScopedCapability = db
            .query_row(
                "SELECT capability_json FROM capability_tokens WHERE token_hash=?1",
                [&hash],
                |r| json_column(r, 0),
            )
            .optional()?
            .ok_or_else(|| ControlError::denied("invalid capability token"))?;
        if capability.expires_at <= now || capability.role == PrincipalRole::Admin {
            return Err(ControlError::denied(
                "capability expired or role is unavailable on this interface",
            ));
        }
        if let Some(id) = &capability.incident_id {
            let incident = get_incident(db, id)?;
            if !capability.allowed_hosts.contains(&incident.host_id) {
                return Err(ControlError::denied(
                    "incident host is outside capability scope",
                ));
            }
            capability
                .allowed_hosts
                .retain(|host| host == &incident.host_id);
        }
        if let Some(run) = &capability.run_id {
            let valid: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE run_id=?1 AND token_hash=?2 AND expires_at>?3 AND status='active')",
                params![run,hash,stamp(now)], |r| r.get(0))?;
            if !valid {
                return Err(ControlError::denied("investigation run is inactive"));
            }
        }
        let response = match call.request {
            InvestigationRequest::ListHosts { limit } => InvestigationResponse::Hosts {
                hosts: list_hosts(db)?
                    .into_iter()
                    .filter(|h| capability.allowed_hosts.contains(&h.host_id))
                    .take(bounded(limit))
                    .collect(),
            },
            InvestigationRequest::ListActiveIncidents { host_id, limit } => {
                if let Some(host) = &host_id {
                    authorize_host(&capability, host)?;
                }
                InvestigationResponse::Incidents {
                    incidents: list_incidents(db)?
                        .into_iter()
                        .filter(|i| {
                            i.status == "open"
                                && host_id.as_ref().is_none_or(|host| host == &i.host_id)
                                && capability.allowed_hosts.contains(&i.host_id)
                                && capability
                                    .incident_id
                                    .as_ref()
                                    .is_none_or(|id| id == &i.incident_id)
                        })
                        .take(bounded(limit))
                        .collect(),
                }
            }
            InvestigationRequest::ListActiveWatches { host_id } => {
                authorize_host(&capability, &host_id)?;
                require_host(db, &host_id)?;
                InvestigationResponse::Watches {
                    watches: scoped_watches(db, &capability, &host_id, now)?,
                }
            }
            InvestigationRequest::ListCollectorCapabilities { host_id } => {
                authorize_host(&capability, &host_id)?;
                require_host(db, &host_id)?;
                let capabilities = self
                    .policy()
                    .edge_floor
                    .allowed_collectors
                    .iter()
                    .copied()
                    .filter(|collector| capability.allowed_collectors.contains(collector))
                    .map(|collector_type| {
                        collector_capability(
                            collector_type,
                            self.policy().edge_floor.min_interval_seconds,
                        )
                    })
                    .collect();
                InvestigationResponse::Capabilities { capabilities }
            }
            InvestigationRequest::GetIncidentContext { incident_id } => {
                let incident = authorize_incident(db, &capability, &incident_id)?;
                let active_watches = scoped_watches(db, &capability, &incident.host_id, now)?
                    .into_iter()
                    .filter(|w| w.incident_id.as_ref().is_none_or(|id| id == &incident_id))
                    .collect();
                let recent_observations = observations(
                    db,
                    &capability,
                    &incident.host_id,
                    None,
                    Some(&incident_id),
                    Some(incident.created_at),
                    20,
                    true,
                )?;
                let findings = rows(
                    db,
                    "SELECT f.finding_id,f.finding_json FROM findings f WHERE f.incident_id=?1
                    AND NOT EXISTS (
                      SELECT 1 FROM finding_evidence e JOIN observations o USING(observation_id)
                      JOIN watch_specs w USING(host_id,watch_id,spec_version)
                      WHERE e.finding_id=f.finding_id
                      AND (o.collector_type NOT IN (SELECT value FROM json_each(?2))
                        OR (w.incident_id IS NOT NULL AND w.incident_id<>?1)))
                    ORDER BY f.finding_id DESC LIMIT 20",
                    params![incident_id, collector_scope_json(&capability)?],
                    |r| {
                        Ok(
                            json!({"finding_id":r.get::<_,i64>(0)?,"finding":json_column::<Value>(r,1)?}),
                        )
                    },
                )?;
                InvestigationResponse::IncidentContext {
                    incident,
                    active_watches,
                    recent_observations,
                    findings,
                }
            }
            InvestigationRequest::QueryObservations {
                host_id,
                watch_id,
                since,
                limit,
            } => {
                authorize_host(&capability, &host_id)?;
                InvestigationResponse::Observations {
                    observations: observations(
                        db,
                        &capability,
                        &host_id,
                        watch_id.as_deref(),
                        capability.incident_id.as_deref(),
                        since,
                        bounded(limit),
                        false,
                    )?,
                }
            }
            InvestigationRequest::GetHostBaselineSummary { host_id } => {
                authorize_host(&capability, &host_id)?;
                let baselines = rows(db,"SELECT b.watch_id,b.revision_id,b.state_hash,b.approver,b.approved_at,b.ticket_ref FROM baseline_revisions b
                    JOIN watch_state s ON s.baseline_revision_id=b.revision_id
                    JOIN watch_specs w ON w.host_id=b.host_id AND w.watch_id=b.watch_id AND w.spec_version=b.spec_version
                    WHERE b.host_id=?1 AND w.active=1 AND json_extract(w.spec_json,'$.collector.type') IN (SELECT value FROM json_each(?2))
                    ORDER BY b.watch_id",params![host_id,collector_scope_json(&capability)?],|r| Ok(BaselineSummaryEntry {
                        watch_id:r.get(0)?,revision_id:r.get(1)?,state_hash:r.get(2)?,approver:r.get(3)?,
                        approved_at:parse_stamp(&r.get::<_,String>(4)?,4)?,ticket_ref:r.get(5)?
                    }))?;
                InvestigationResponse::BaselineSummary { host_id, baselines }
            }
            InvestigationRequest::StartInvestigationRun {
                incident_id,
                backend_id,
                model_id,
                prompt_schema_version,
            } => {
                require_investigator(&capability)?;
                let incident = authorize_incident(db, &capability, &incident_id)?;
                require_open(&incident)?;
                require_text(&backend_id, "backend_id", 128)?;
                require_text(&model_id, "model_id", 128)?;
                require_text(&prompt_schema_version, "prompt_schema_version", 128)?;
                if let Some(run_id) = capability.run_id {
                    let same: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM agent_runs WHERE run_id=?1 AND incident_id=?2 AND backend_id=?3 AND model_id=?4 AND prompt_schema_version=?5)",
                        params![run_id,incident_id,backend_id,model_id,prompt_schema_version],|r|r.get(0))?;
                    if !same {
                        return Err(ControlError::denied(
                            "capability is already bound to another run",
                        ));
                    }
                    InvestigationResponse::RunStarted {
                        run_id,
                        incident_id,
                        expires_at: capability.expires_at,
                    }
                } else {
                    let run_id = uuid();
                    db.execute("INSERT INTO agent_runs (run_id,incident_id,token_hash,principal_id,backend_id,model_id,prompt_schema_version,started_at,expires_at)
                        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                        params![run_id,incident_id,hash,capability.principal_id,backend_id,model_id,prompt_schema_version,stamp(now),stamp(capability.expires_at)])?;
                    capability.run_id = Some(run_id.clone());
                    capability.incident_id = Some(incident_id.clone());
                    capability.allowed_hosts = vec![incident.host_id];
                    db.execute(
                        "UPDATE capability_tokens SET capability_json=?2 WHERE token_hash=?1",
                        params![hash, serde_json::to_string(&capability)?],
                    )?;
                    audit(
                        db,
                        RunStarted,
                        &capability.principal_id,
                        request_id,
                        json!({"run_id":run_id,"incident_id":incident_id,"backend_id":backend_id,"model_id":model_id,"prompt_schema_version":prompt_schema_version,"expires_at":capability.expires_at}),
                    )?;
                    InvestigationResponse::RunStarted {
                        run_id,
                        incident_id,
                        expires_at: capability.expires_at,
                    }
                }
            }
            InvestigationRequest::ProposeEphemeralWatch {
                run_id,
                idempotency_key,
                spec,
                rationale,
            } => {
                require_investigator(&capability)?;
                let incident = authorize_run(db, &capability, &run_id)?;
                self.propose(
                    db,
                    Proposal {
                        capability: &capability,
                        request_id,
                        incident: &incident,
                        run_id: &run_id,
                        key: &idempotency_key,
                        spec,
                        rationale: &rationale,
                        now,
                    },
                )?
            }
            InvestigationRequest::RecordHypothesisOrFinding {
                run_id,
                incident_id,
                kind,
                severity,
                summary,
                uncertainty,
                evidence_observation_ids,
                escalation_requested,
            } => {
                require_investigator(&capability)?;
                let incident = authorize_run(db, &capability, &run_id)?;
                if incident.incident_id != incident_id {
                    return Err(ControlError::denied("finding incident does not match run"));
                }
                require_text(&summary, "summary", 4096)?;
                if uncertainty.len() > 4096
                    || evidence_observation_ids.len() > 100
                    || (kind == FindingKind::VerifiedFinding && evidence_observation_ids.is_empty())
                {
                    return Err(ControlError::invalid(
                        "invalid finding evidence or uncertainty bounds",
                    ));
                }
                let mut evidence = BTreeMap::new();
                for id in evidence_observation_ids {
                    let state_hash: String = db.query_row("SELECT o.state_hash FROM observations o JOIN watch_specs w USING (host_id,watch_id,spec_version)
                        WHERE o.observation_id=?1 AND o.host_id=?2 AND o.collector_type IN (SELECT value FROM json_each(?3))
                        AND (w.incident_id IS NULL OR w.incident_id=?4)",
                        params![id,incident.host_id,collector_scope_json(&capability)?,incident_id], |r|r.get(0)).optional()?
                        .ok_or_else(|| ControlError::invalid("observation evidence is missing or outside incident scope"))?;
                    evidence.insert(id, state_hash);
                }
                let finding = json!({"kind":kind,"severity":severity,"summary":summary,"uncertainty":uncertainty,"escalation_requested":escalation_requested,"evidence_observation_ids":evidence.keys().collect::<Vec<_>>()});
                db.execute("INSERT INTO findings (run_id,incident_id,finding_json,created_at) VALUES (?1,?2,?3,?4)",
                    params![run_id,incident_id,finding.to_string(),stamp(now)])?;
                let finding_id = db.last_insert_rowid();
                for (id, hash) in &evidence {
                    db.execute(
                        "INSERT INTO finding_evidence VALUES (?1,?2,?3)",
                        params![finding_id, id, hash],
                    )?;
                }
                audit(
                    db,
                    FindingRecorded,
                    &capability.principal_id,
                    request_id,
                    json!({"finding_id":finding_id,"run_id":run_id,"incident_id":incident_id,"finding":finding,"evidence_hashes":evidence}),
                )?;
                InvestigationResponse::FindingRecorded {
                    finding_id,
                    verified_evidence_count: evidence.len(),
                }
            }
        };
        if serde_json::to_vec(&response)?.len() > MAX_FRAME_BYTES {
            return Err(ControlError::invalid(
                "response exceeds the frame limit; query a smaller slice",
            ));
        }
        Ok(response)
    }

    fn propose(&self, db: &Connection, p: Proposal<'_>) -> Result<InvestigationResponse> {
        let Proposal {
            capability,
            request_id,
            incident,
            run_id,
            key,
            mut spec,
            rationale,
            now,
        } = p;
        require_text(key, "idempotency_key", 128)?;
        require_text(rationale, "rationale", 4096)?;
        let submitted = serde_json::to_string(&spec)?;
        let previous: Option<(String,String,InvestigationResponse)> = db.query_row(
            "SELECT spec_json,rationale,response_json FROM watch_proposals WHERE run_id=?1 AND idempotency_key=?2",
            params![run_id,key],|r|Ok((r.get(0)?,r.get(1)?,json_column(r,2)?))).optional()?;
        if let Some((prior_spec, prior_rationale, response)) = previous {
            if submitted != prior_spec || rationale != prior_rationale {
                return Err(ControlError::invalid(
                    "idempotency key was reused with a different proposal",
                ));
            }
            return Ok(response);
        }
        let active_host_watches = active_watches(db, &incident.host_id, now)?;
        let counts = rows(db,"SELECT p.fingerprint,COUNT(*) FROM watch_proposals p JOIN policy_decisions d USING (proposal_id)
            WHERE p.incident_id=?1 AND json_extract(d.decision_json,'$.allowed')=1 GROUP BY p.fingerprint",
            [&incident.incident_id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let context = ProposalContext {
            active_incident_watches: active_host_watches
                .iter()
                .filter(|w| {
                    w.class == WatchClass::Ephemeral
                        && w.incident_id.as_ref() == Some(&incident.incident_id)
                })
                .cloned()
                .collect(),
            active_host_watches,
            prior_incident_proposal_count: db.query_row(
                "SELECT COUNT(*) FROM watch_proposals WHERE incident_id=?1",
                [&incident.incident_id],
                |r| r.get(0),
            )?,
            prior_equivalent_fingerprints_in_incident: counts.into_iter().collect(),
        };
        spec.version = 1;
        let mut decision = evaluate_watch_proposal(capability, &spec, &context, self.policy(), now);
        if decision.allowed {
            let floor = &self.policy().edge_floor;
            let invalid = if latest_spec(db, &spec.host_id, &spec.id)?.is_some() {
                Some((
                    "spec.watch_id_exists",
                    "watch ID already exists on this host",
                ))
            } else if !spec.lifecycle.enabled
                || spec.lifecycle.expires_at.is_none_or(|expiry| expiry <= now)
            {
                Some((
                    "spec.inactive",
                    "ephemeral proposal must be enabled and unexpired",
                ))
            } else if context.active_host_watches.len() >= floor.max_watches_total
                || context
                    .active_host_watches
                    .iter()
                    .filter(|w| w.class == WatchClass::Ephemeral)
                    .count()
                    >= floor.max_ephemeral_watches
            {
                Some((
                    "quota.bundle_safety",
                    "host bundle has reached its safety limit",
                ))
            } else {
                None
            };
            if let Some((rule, reason)) = invalid {
                decision = PolicyDecision {
                    allowed: false,
                    rule_id: rule.into(),
                    reason: reason.into(),
                    policy_version: self.policy().policy_version,
                };
            }
        }
        let bundle_version = if decision.allowed {
            insert_watch(db, &spec, &capability.principal_id, now)?;
            Some(self.issue_bundle(
                db,
                &incident.host_id,
                &capability.principal_id,
                request_id,
                now,
            )?)
        } else {
            None
        };
        let response = InvestigationResponse::ProposalEvaluated {
            decision: decision.clone(),
            watch_id: decision.allowed.then(|| spec.id.clone()),
            bundle_version,
        };
        db.execute("INSERT INTO watch_proposals (run_id,idempotency_key,incident_id,fingerprint,spec_json,rationale,response_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![run_id,key,incident.incident_id,watch_target_fingerprint(&spec),submitted,rationale,serde_json::to_string(&response)?,stamp(now)])?;
        let proposal_id = db.last_insert_rowid();
        audit(
            db,
            WatchProposed,
            &capability.principal_id,
            request_id,
            json!({"proposal_id":proposal_id,"run_id":run_id,"incident_id":incident.incident_id,"spec":spec,"rationale":rationale,"idempotency_key":key}),
        )?;
        record_decision(
            db,
            Some(proposal_id),
            &capability.principal_id,
            request_id,
            &decision,
            json!({"watch_id":spec.id,"bundle_version":bundle_version}),
            now,
        )?;
        Ok(response)
    }
}

struct Proposal<'a> {
    capability: &'a ScopedCapability,
    request_id: &'a str,
    incident: &'a IncidentSummary,
    run_id: &'a str,
    key: &'a str,
    spec: WatchSpec,
    rationale: &'a str,
    now: DateTime<Utc>,
}

fn require_text(value: &str, name: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max {
        return Err(ControlError::invalid(format!(
            "{name} must contain 1 to {max} bytes"
        )));
    }
    Ok(())
}

fn bounded(limit: Option<u32>) -> usize {
    limit.unwrap_or(50).min(100) as usize
}

fn authorize_host(capability: &ScopedCapability, host: &str) -> Result<()> {
    if !capability
        .allowed_hosts
        .iter()
        .any(|allowed| allowed == host)
    {
        return Err(ControlError::denied("host is outside capability scope"));
    }
    Ok(())
}

fn authorize_incident(
    db: &Connection,
    capability: &ScopedCapability,
    id: &str,
) -> Result<IncidentSummary> {
    if capability
        .incident_id
        .as_deref()
        .is_some_and(|allowed| allowed != id)
    {
        return Err(ControlError::denied("incident is outside capability scope"));
    }
    let incident = get_incident(db, id).map_err(|error| match error {
        ControlError::Request {
            code: "not_found", ..
        } => ControlError::denied("incident is outside capability scope"),
        error => error,
    })?;
    authorize_host(capability, &incident.host_id)?;
    Ok(incident)
}

fn require_open(incident: &IncidentSummary) -> Result<()> {
    if incident.status != "open" {
        return Err(ControlError::denied("incident is closed"));
    }
    Ok(())
}

fn require_investigator(capability: &ScopedCapability) -> Result<()> {
    if capability.role != PrincipalRole::Investigator {
        return Err(ControlError::denied("investigator role required"));
    }
    Ok(())
}

fn authorize_run(
    db: &Connection,
    capability: &ScopedCapability,
    run: &str,
) -> Result<IncidentSummary> {
    if capability.run_id.as_deref() != Some(run) {
        return Err(ControlError::denied("run is outside capability scope"));
    }
    let id = capability
        .incident_id
        .as_deref()
        .ok_or_else(|| ControlError::denied("run requires an incident scope"))?;
    let incident = authorize_incident(db, capability, id)?;
    require_open(&incident)?;
    Ok(incident)
}

fn collector_scope_json(cap: &ScopedCapability) -> Result<String> {
    Ok(serde_json::to_string(&cap.allowed_collectors)?)
}

fn scoped_watches(
    db: &Connection,
    cap: &ScopedCapability,
    host: &str,
    now: DateTime<Utc>,
) -> Result<Vec<WatchSpec>> {
    Ok(active_watches(db, host, now)?
        .into_iter()
        .filter(|w| {
            cap.allowed_collectors
                .contains(&w.collector.collector_type())
                && w.incident_id
                    .as_ref()
                    .is_none_or(|id| cap.incident_id.as_ref().is_none_or(|allowed| allowed == id))
        })
        .collect())
}

fn observations(
    db: &Connection,
    cap: &ScopedCapability,
    host: &str,
    watch: Option<&str>,
    incident: Option<&str>,
    since: Option<DateTime<Utc>>,
    limit: usize,
    include_incident_evidence: bool,
) -> Result<Vec<ObservationSlice>> {
    rows(db,"SELECT o.observation_id,o.host_id,o.watch_id,o.spec_version,o.observed_at,o.status_json,o.state_hash,o.payload_json,
        (?7 AND EXISTS (
          SELECT 1 FROM trigger_evidence e JOIN trigger_events t USING(event_id)
          WHERE e.observation_id=o.observation_id AND t.incident_id=?4
        )) AS incident_evidence
        FROM observations o JOIN watch_specs w USING (host_id,watch_id,spec_version)
        WHERE o.host_id=?1 AND (?2 IS NULL OR o.watch_id=?2) AND (?3 IS NULL OR o.observed_at>=?3 OR incident_evidence)
        AND (?4 IS NULL OR w.incident_id IS NULL OR w.incident_id=?4)
        AND o.collector_type IN (SELECT value FROM json_each(?5))
        ORDER BY incident_evidence DESC,o.observation_id DESC LIMIT ?6",
        params![host,watch,since.map(stamp),incident,collector_scope_json(cap)?,limit,include_incident_evidence],|r|Ok(ObservationSlice {
            observation_id:r.get(0)?,host_id:r.get(1)?,watch_id:r.get(2)?,spec_version:r.get(3)?,
            observed_at:parse_stamp(&r.get::<_,String>(4)?,4)?,status:json_column(r,5)?,state_hash:r.get(6)?,payload:json_column(r,7)?
        }))
}

fn collector_capability(
    collector_type: CollectorType,
    min_interval_seconds: u64,
) -> CollectorCapability {
    let (sensitivity, description) = match collector_type {
        CollectorType::SocketsListening => (
            DataClassification::MetadataSensitive,
            "Listening socket and process metadata",
        ),
        CollectorType::SystemdUnitState => (
            DataClassification::MetadataLow,
            "Systemd unit status and configuration hashes",
        ),
        CollectorType::FilesMetadata => (
            DataClassification::MetadataSensitive,
            "Metadata and hashes for approved file paths",
        ),
        CollectorType::JournalUnitEvents => (
            DataClassification::BoundedRedactedText,
            "Bounded, redacted systemd journal events",
        ),
    };
    CollectorCapability {
        collector_type,
        schema_version: 1,
        is_stream: collector_type.is_stream(),
        sensitivity,
        min_interval_seconds,
        description: description.into(),
        declared_privileges: vec![],
    }
}
