use std::borrow::Cow;

use chrono::{DateTime, Duration, Utc};
use defsec_policy::{
    control_gate::{WakeBudgetConfig, WakeDecision, check_wake_budget},
    edge_floor::{EdgeSafetyConfig, is_valid_identifier},
    host_profile::validate_host_profile_summary,
    predicate::{PredicateOutcome, evaluate_predicate},
    rules::apply_expectation_rules,
};
use defsec_protocol::{
    audit::AuditEventType::{BundleAcked, HostProfileChanged, HostProfileRejected, IncidentOpened},
    canonical::{canonical_sha256_hex, value_to_canonical_json},
    observation::{ObservationPayload, ObservationRecord, ObservationStatus},
    profile::HostProfileSummary,
    rpc::{PolicyDecision, Severity},
    watch::{
        CollectorSpec, CompareTarget, DataClassification, TriggerPredicate, WatchClass, WatchSpec,
    },
    wire::{
        AgentToControl, AgentToControlMessage, BundleAckStatus, ControlToAgent,
        WIRE_PROTOCOL_VERSION, WatchRunSummary,
    },
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::{
    expectation_rules::{active_rules, record_rule_hits},
    ledger::{audit, json_column, optional_json},
    service::{
        ControlError, ControlService, Result, active_watches, bundle, record_decision,
        require_host, stamp, uuid,
    },
};

impl ControlService {
    pub fn handle_agent_message(&self, msg: AgentToControl) -> Vec<ControlToAgent> {
        self.handle_agent_message_with_profile(msg, Ok)
    }

    pub(crate) fn handle_agent_message_with_profile<P>(
        &self,
        msg: AgentToControlMessage<P>,
        decode_profile: impl FnOnce(P) -> std::result::Result<HostProfileSummary, String>,
    ) -> Vec<ControlToAgent> {
        let registering = matches!(msg, AgentToControlMessage::Register { .. });
        match self.transaction(|db| self.agent(db, msg, decode_profile)) {
            Ok(replies) => replies,
            Err(error) => {
                let (_, message) = error.response_parts();
                if registering {
                    vec![register_ack(Utc::now(), Some(message), 0)]
                } else {
                    tracing::warn!(%message, "agent message rejected");
                    vec![]
                }
            }
        }
    }

    fn agent<P>(
        &self,
        db: &Connection,
        msg: AgentToControlMessage<P>,
        decode_profile: impl FnOnce(P) -> std::result::Result<HostProfileSummary, String>,
    ) -> Result<Vec<ControlToAgent>> {
        let now = Utc::now();
        match msg {
            AgentToControlMessage::Register {
                protocol_version,
                host_id,
                agent_version,
                boot_id,
                session_id,
                active_bundle_version,
                active_bundle_digest,
                host_profile,
                ..
            } => {
                require_host(db, &host_id)?;
                if protocol_version != WIRE_PROTOCOL_VERSION
                    || !is_valid_identifier(&session_id)
                    || !is_valid_identifier(&boot_id)
                {
                    return Err(ControlError::invalid(
                        "unsupported protocol or invalid boot/session ID",
                    ));
                }
                let (prior_session, desired): (Option<String>, u64) = db.query_row(
                    "SELECT session_id,desired_bundle_version FROM hosts WHERE host_id=?1",
                    [&host_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let new_session = prior_session.as_deref() != Some(&session_id);
                let inserted = db.execute("INSERT INTO agent_sessions (host_id,session_id,boot_id) VALUES (?1,?2,?3) ON CONFLICT DO NOTHING", params![host_id,session_id,boot_id])?;
                let (session_boot, acked): (String, u64) = db.query_row("SELECT boot_id,acked_seq_no FROM agent_sessions WHERE host_id=?1 AND session_id=?2", params![host_id,session_id], |r| Ok((r.get(0)?,r.get(1)?)))?;
                if session_boot != boot_id || (new_session && inserted == 0) {
                    return Err(ControlError::denied(
                        "session is retired or bound to another boot",
                    ));
                }
                let expected = bundle(db, &host_id)?;
                let active_matches = expected.as_ref().is_some_and(|(version, digest, _)| {
                    *version == active_bundle_version
                        && active_bundle_digest.as_ref() == Some(digest)
                });
                db.execute(
                    "UPDATE hosts SET agent_version=?2,boot_id=?3,session_id=?4,last_heartbeat_at=?5,liveness_status='online',
                     active_bundle_version=CASE WHEN ?6 THEN ?7 WHEN ?8 THEN 0 ELSE active_bundle_version END WHERE host_id=?1",
                    params![host_id,agent_version,boot_id,session_id,stamp(now),active_matches,active_bundle_version,new_session])?;
                record_host_profile(db, &host_id, host_profile.map(decode_profile).transpose(), now)?;
                let mut reply = vec![register_ack(now, None, acked)];
                let renew = bundle_expiring(db, &host_id, desired, now)?;
                let expected = if renew {
                    self.issue_bundle(db, &host_id, "control", &uuid(), now)?;
                    bundle(db, &host_id)?
                } else {
                    expected
                };
                if let Some((_, _, envelope)) = expected.filter(|_| !active_matches || renew) {
                    reply.push(ControlToAgent::SyncWatchBundle { envelope });
                }
                if new_session || !active_matches {
                    reply.push(reconcile(
                        host_id,
                        vec![],
                        if new_session {
                            "new agent session"
                        } else {
                            "bundle mismatch"
                        },
                    ));
                }
                Ok(reply)
            }
            AgentToControlMessage::Heartbeat {
                host_id,
                session_id,
                active_bundle_version,
                last_seq_no,
                dropped_events_total,
                stale_desired_state,
                health,
                watch_summaries,
                ..
            } => {
                let acked = session_ack(db, &host_id, &session_id)?;
                let (desired, previous_health): (u64, Option<Value>) = db.query_row(
                    "SELECT desired_bundle_version,health_json FROM hosts WHERE host_id=?1",
                    [&host_id],
                    |r| {
                        Ok((
                            r.get(0)?,
                            if r.get::<_, Option<String>>(1)?.is_some() {
                                Some(json_column(r, 1)?)
                            } else {
                                None
                            },
                        ))
                    },
                )?;
                let previous_drops = previous_health
                    .as_ref()
                    .filter(|v| v["session_id"].as_str() == Some(&session_id))
                    .and_then(|v| v["drops"].as_u64())
                    .unwrap_or(0);
                db.execute("UPDATE hosts SET last_heartbeat_at=?2,health_json=?3,liveness_status='online' WHERE host_id=?1",
                    params![host_id,stamp(now),json!({"session_id":session_id,"drops":dropped_events_total,"resources":health,"stale_desired_state":stale_desired_state}).to_string()])?;
                let watches = active_watches(db, &host_id, now)?;
                for spec in watches {
                    let summary = watch_summaries
                        .iter()
                        .find(|s| s.watch_id == spec.id && s.spec_version == spec.version);
                    heartbeat_watch(
                        db,
                        &spec,
                        &session_id,
                        summary,
                        self.policy().policy_version,
                        now,
                    )?;
                }
                let mut replies = Vec::new();
                let renew = bundle_expiring(db, &host_id, desired, now)?;
                if renew {
                    self.issue_bundle(db, &host_id, "control", &uuid(), now)?;
                }
                if (renew || active_bundle_version != desired || stale_desired_state)
                    && let Some((_, _, envelope)) = bundle(db, &host_id)?
                {
                    replies.push(ControlToAgent::SyncWatchBundle { envelope });
                }
                if dropped_events_total > previous_drops || last_seq_no > acked.saturating_add(1) {
                    replies.push(reconcile(
                        host_id,
                        vec![],
                        "agent reports missing observation history",
                    ));
                }
                Ok(replies)
            }
            AgentToControlMessage::PushObservationDelta { observation } => {
                ingest(db, observation, &self.policy().edge_floor, now)
            }
            AgentToControlMessage::BundleAck {
                host_id,
                bundle_id,
                bundle_version,
                payload_digest,
                status,
                reason,
                acked_at,
            } => {
                let (expected_id, digest, prior): (String,String,Option<String>) = db.query_row(
                    "SELECT bundle_id,payload_digest,ack_json FROM issued_bundles WHERE host_id=?1 AND bundle_version=?2",
                    params![host_id,bundle_version], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))
                ).optional()?.ok_or_else(|| ControlError::missing("unissued bundle acknowledgment"))?;
                // A rejected bundle can fail before the edge computes its digest.
                if expected_id != bundle_id
                    || (digest != payload_digest
                        && !(status == BundleAckStatus::Rejected && payload_digest.is_empty()))
                {
                    return Err(ControlError::invalid(
                        "bundle acknowledgment does not match issued envelope",
                    ));
                }
                let receipt = json!({"host_id":host_id,"bundle_id":bundle_id,"bundle_version":bundle_version,"payload_digest":payload_digest,"status":status,"reason":reason,"acked_at":acked_at});
                let serialized = receipt.to_string();
                if prior.as_deref() != Some(&serialized) {
                    db.execute("UPDATE issued_bundles SET ack_json=?3 WHERE host_id=?1 AND bundle_version=?2", params![host_id,bundle_version,serialized])?;
                    if status != BundleAckStatus::Rejected {
                        db.execute("UPDATE hosts SET active_bundle_version=MAX(active_bundle_version,?2) WHERE host_id=?1", params![host_id,bundle_version])?;
                    }
                    audit(db, BundleAcked, &host_id, &uuid(), receipt)?;
                }
                Ok(vec![])
            }
        }
    }
}

fn record_host_profile(
    db: &Connection,
    host_id: &str,
    reported: std::result::Result<Option<HostProfileSummary>, String>,
    now: DateTime<Utc>,
) -> Result<()> {
    let before: Option<HostProfileSummary> = db.query_row(
        "SELECT profile_json FROM hosts WHERE host_id=?1",
        [host_id],
        |r| optional_json(r, 0),
    )?;
    let request = uuid();
    let previous_rejection: Option<String> = db.query_row(
        "SELECT profile_rejection FROM hosts WHERE host_id=?1",
        [host_id],
        |r| r.get(0),
    )?;
    let (after, rejection) = match reported.and_then(|profile| {
        if let Some(profile) = &profile {
            validate_host_profile_summary(profile)?;
        }
        Ok(profile.map(normalize_profile))
    }) {
        Ok(profile) => (profile, None),
        Err(reason) => {
            tracing::warn!(%host_id, ?reason, "invalid host profile summary");
            // A looping agent resending the same bad profile is audited once.
            if previous_rejection.as_deref() != Some(reason.as_str()) {
                audit(
                    db,
                    HostProfileRejected,
                    host_id,
                    &request,
                    json!({"host_id": host_id, "reason": reason}),
                )?;
            }
            (None, Some(reason))
        }
    };
    let profile_json = after
        .as_ref()
        .map(|profile| value_to_canonical_json(&json!(profile)))
        .transpose()?;
    db.execute(
        "UPDATE hosts SET profile_json=?2,profile_reported_at=?3,profile_rejection=?4 WHERE host_id=?1",
        params![host_id, profile_json, stamp(now), rejection],
    )?;
    if before != after {
        audit(
            db,
            HostProfileChanged,
            host_id,
            &request,
            json!({"host_id": host_id, "before": before, "after": after}),
        )?;
    }
    Ok(())
}

/// Order-insensitive form, so reordering a profile is not reported as drift.
fn normalize_profile(mut profile: HostProfileSummary) -> HostProfileSummary {
    profile.host_tags.sort();
    profile.host_tags.dedup();
    profile.expected_services.sort();
    profile.expected_services.dedup();
    profile.enabled_collectors.sort();
    profile.enabled_collectors.dedup();
    profile
}

fn bundle_expiring(db: &Connection, host: &str, desired: u64, now: DateTime<Utc>) -> Result<bool> {
    if desired == 0 {
        return Ok(false);
    }
    Ok(db.query_row(
        "SELECT expires_at <= ?3 FROM issued_bundles WHERE host_id=?1 AND bundle_version=?2",
        params![host, desired, stamp(now + Duration::hours(1))],
        |r| r.get(0),
    )?)
}

fn register_ack(now: DateTime<Utc>, reason: Option<String>, acked: u64) -> ControlToAgent {
    ControlToAgent::RegisterAck {
        protocol_version: WIRE_PROTOCOL_VERSION,
        accepted: reason.is_none(),
        reason,
        server_time: now,
        last_acked_seq_no: acked,
    }
}

fn reconcile(host_id: String, watch_ids: Vec<String>, reason: &str) -> ControlToAgent {
    ControlToAgent::RequestReconciliation {
        host_id,
        watch_ids,
        reason: reason.into(),
    }
}

fn session_ack(db: &Connection, host: &str, session: &str) -> Result<u64> {
    db.query_row("SELECT a.acked_seq_no FROM hosts h JOIN agent_sessions a USING (host_id,session_id) WHERE h.host_id=?1 AND h.session_id=?2",
        params![host,session], |r| r.get(0)).optional()?.ok_or_else(|| ControlError::denied("agent has no active session"))
}

/// Resolve the sequence watermark for an observation push. Accepts both the
/// host's currently active session and any previously registered session of the
/// same host so durable-spool records survive restarts and drain cleanly.
fn ingest_session_ack(db: &Connection, host: &str, session: &str) -> Result<(u64, bool)> {
    let active_session: Option<String> = db
        .query_row(
            "SELECT session_id FROM hosts WHERE host_id=?1",
            [host],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let Some(active_session) = active_session else {
        return Err(ControlError::denied("agent has no active session"));
    };
    let acked: Option<u64> = db
        .query_row(
            "SELECT acked_seq_no FROM agent_sessions WHERE host_id=?1 AND session_id=?2",
            params![host, session],
            |r| r.get(0),
        )
        .optional()?;
    let acked = acked.ok_or_else(|| ControlError::denied("unknown agent session"))?;
    Ok((acked, active_session != session))
}

fn observation_ack(o: &ObservationRecord, acked: u64, now: DateTime<Utc>) -> ControlToAgent {
    ControlToAgent::ObservationAck {
        host_id: o.host_id.clone(),
        session_id: o.session_id.clone(),
        acked_seq_no: acked,
        acked_at: now,
    }
}

fn ingest(
    db: &Connection,
    o: ObservationRecord,
    floor: &EdgeSafetyConfig,
    now: DateTime<Utc>,
) -> Result<Vec<ControlToAgent>> {
    let (acked, is_historical_session) = ingest_session_ack(db, &o.host_id, &o.session_id)?;
    let request = |reason| reconcile(o.host_id.clone(), vec![o.watch_id.clone()], reason);
    if o.seq_no == 0 || o.seq_no > i64::MAX as u64 {
        return Ok(vec![request("invalid sequence number")]);
    }
    let key = params![o.host_id, o.session_id, o.seq_no];
    let prior: Option<ObservationRecord> = db
        .query_row(
            "SELECT record_json FROM observations WHERE host_id=?1 AND session_id=?2 AND seq_no=?3",
            key,
            |r| json_column(r, 0),
        )
        .optional()?;
    if let Some(prior) = prior {
        if prior != o {
            return Ok(vec![request(
                "sequence already belongs to different evidence",
            )]);
        }
        return Ok(vec![observation_ack(&o, acked, now)]);
    }
    let gap = o.seq_no > acked + 1;
    if gap && !(o.is_reconciliation && matches!(o.payload, ObservationPayload::Snapshot { .. })) {
        return Ok(vec![reconcile(
            o.host_id,
            vec![],
            "observation sequence gap",
        )]);
    }
    let watch: Option<WatchSpec> = db.query_row("SELECT spec_json FROM watch_specs WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
        params![o.host_id,o.watch_id,o.spec_version], |r| json_column(r,0)).optional()?;
    let Some(spec) = watch.filter(|s| s.collector.collector_type() == o.collector_type) else {
        let mut response = vec![request("unknown watch revision or mismatched collector")];
        if let Some((_, _, envelope)) = bundle(db, &o.host_id)? {
            response.insert(0, ControlToAgent::SyncWatchBundle { envelope });
        }
        return Ok(response);
    };
    let state = read_state(db, &spec)?;
    let older_than_checkpoint = (state.latest_session.as_deref() == Some(&o.session_id)
        && state.latest_seq.is_some_and(|seq| seq > o.seq_no))
        || (is_historical_session
            && state
                .latest_session
                .as_deref()
                .is_some_and(|latest| latest != o.session_id));
    let (sample, computed_hash) =
        match (&o.payload, &spec.collector) {
            (ObservationPayload::Snapshot { data }, _) if !o.collector_type.is_stream() => {
                if !data.is_object() {
                    return Ok(vec![request("normalized snapshot must be an object")]);
                }
                (
                    o.status.is_valid_sample().then_some(Cow::Borrowed(data)),
                    canonical_sha256_hex(data)?,
                )
            }
            (ObservationPayload::Delta { base_hash, data }, _)
                if o.status.is_valid_sample() && !o.collector_type.is_stream() =>
            {
                // Delta data carries the resulting normalized state. The wire contract
                // has no patch encoding, so a matching base is a precondition for use.
                let base_found =
                    if older_than_checkpoint {
                        let previous: Option<String> = db.query_row(
                    "SELECT state_hash FROM observations WHERE host_id=?1 AND session_id=?2
                     AND watch_id=?3 AND spec_version=?4 AND seq_no<?5 AND sample_json IS NOT NULL
                     ORDER BY seq_no DESC LIMIT 1",
                    params![o.host_id,o.session_id,o.watch_id,o.spec_version,o.seq_no], |r| r.get(0)
                ).optional()?;
                        previous.as_ref() == Some(base_hash)
                    } else {
                        state.last_hash.as_ref() == Some(base_hash)
                            && state.last_session.as_deref() == Some(&o.session_id)
                    };
                if !base_found || gap || o.is_reconciliation || !data.is_object() {
                    return Ok(vec![request("delta base unavailable or mismatched")]);
                }
                (Some(Cow::Borrowed(data)), canonical_sha256_hex(data)?)
            }
            (
                ObservationPayload::StreamBatch {
                    events,
                    gap_detected,
                    ..
                },
                CollectorSpec::JournalUnitEvents(params),
            ) => {
                let event_limit = params
                    .max_events_per_batch
                    .unwrap_or(floor.max_journal_batch_events)
                    as usize;
                let message_limit = params
                    .max_message_bytes
                    .unwrap_or(floor.max_journal_message_bytes);
                if events.len() > event_limit
                    || events.iter().any(|event| {
                        event.classification != DataClassification::BoundedRedactedText
                            || event.unit != params.unit
                            || event.priority > 7
                            || event.message_redacted.len() > message_limit
                    })
                {
                    return Ok(vec![request("stream evidence violates collector bounds")]);
                }
                let sample = (o.status.is_valid_sample() && !gap_detected)
                    .then(|| serde_json::to_value(&o.payload).map(Cow::Owned))
                    .transpose()?;
                (sample, canonical_sha256_hex(events)?)
            }
            (ObservationPayload::ErrorDetail { .. }, _) if !o.status.is_valid_sample() => {
                (None, canonical_sha256_hex(&o.payload)?)
            }
            _ => return Ok(vec![request("payload does not match collector or status")]),
        };
    if computed_hash != o.state_hash {
        return Ok(vec![request("normalized observation hash mismatch")]);
    }
    let sample = sample.as_deref();
    db.execute(
        "INSERT INTO observations (host_id,session_id,seq_no,watch_id,spec_version,collector_type,observed_at,received_at,status_json,state_hash,payload_json,sample_json,record_json)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![o.host_id,o.session_id,o.seq_no,o.watch_id,o.spec_version,o.collector_type.as_str(),stamp(o.observed_at),stamp(now),
            serde_json::to_string(&o.status)?,o.state_hash,serde_json::to_string(&o.payload)?,sample.map(Value::to_string),serde_json::to_string(&o)?])?;
    let id = db.last_insert_rowid();
    if !older_than_checkpoint {
        let errors = if o.status.is_valid_sample() {
            0
        } else if state.latest_session.as_deref() == Some(&o.session_id) {
            state.observation_errors.saturating_add(1)
        } else {
            1
        };
        let outcome = evaluate_predicate(
            &spec.trigger,
            o.status,
            sample,
            state.last_sample.as_ref(),
            state.baseline.as_ref(),
            o.sustained_count,
            errors,
            0,
        );
        let outcome = if let TriggerPredicate::SetDiff {
            compare_against, ..
        } = &spec.trigger
            && matches!(
                outcome,
                PredicateOutcome::Triggered { .. } | PredicateOutcome::NotTriggered
            ) {
            let reference = match compare_against {
                CompareTarget::LastObserved => state.last_sample.as_ref(),
                CompareTarget::AcceptedBaseline => state.baseline.as_ref(),
            };
            let rules = active_rules(db, &o.host_id, o.collector_type, &o.watch_id, now)?;
            let evaluation = apply_expectation_rules(
                &spec.trigger,
                o.collector_type,
                outcome,
                o.status,
                sample,
                reference,
                &rules,
            );
            record_rule_hits(db, &evaluation.matched_rule_ids, now)?;
            evaluation.outcome
        } else {
            outcome
        };
        let freshness = sample.map(|_| {
            let observed = o.observed_at.min(now);
            stamp(
                state
                    .freshness
                    .map_or(observed, |previous| previous.max(observed)),
            )
        });
        db.execute("UPDATE watch_state SET last_observation_id=?4,
            last_success_id=CASE WHEN ?5 IS NOT NULL THEN ?4 ELSE last_success_id END,
            last_success_at=COALESCE(?5,last_success_at),
            observation_errors=?6,outcome_json=?7 WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
            params![o.host_id,o.watch_id,o.spec_version,id,freshness,errors,serde_json::to_string(&outcome)?])?;
        if spec.lifecycle.enabled
            && state.enabled
            && !state.retired
            && spec.lifecycle.expires_at.is_none_or(|expiry| expiry > now)
            && let PredicateOutcome::Triggered { .. } = outcome
        {
            let comparison_id = match spec.trigger {
                TriggerPredicate::SetDiff {
                    compare_against: CompareTarget::LastObserved,
                    ..
                } => state.last_success_id,
                TriggerPredicate::SetDiff {
                    compare_against: CompareTarget::AcceptedBaseline,
                    ..
                } => state.baseline_observation_id,
                _ => None,
            };
            let evidence = [Some(id), comparison_id];
            trigger(
                db,
                &spec,
                &outcome,
                &evidence,
                floor.expected_policy_version,
                now,
            )?;
        }
    }
    let contiguous = if gap {
        acked
    } else {
        let last = db.query_row(
            "SELECT o.seq_no FROM observations o WHERE o.host_id=?1 AND o.session_id=?2 AND o.seq_no>=?3
            AND NOT EXISTS (
              SELECT 1 FROM observations next WHERE next.host_id=o.host_id
              AND next.session_id=o.session_id AND next.seq_no=o.seq_no+1
            ) ORDER BY o.seq_no LIMIT 1",
            params![o.host_id,o.session_id,o.seq_no], |r| r.get(0))?;
        db.execute(
            "UPDATE agent_sessions SET acked_seq_no=?3 WHERE host_id=?1 AND session_id=?2",
            params![o.host_id, o.session_id, last],
        )?;
        last
    };
    Ok(vec![observation_ack(&o, contiguous, now)])
}

struct WatchState {
    last_hash: Option<String>,
    last_success_id: Option<i64>,
    baseline_observation_id: Option<i64>,
    last_session: Option<String>,
    last_sample: Option<Value>,
    latest_session: Option<String>,
    latest_seq: Option<u64>,
    baseline: Option<Value>,
    observation_errors: u32,
    summary_errors: u32,
    enabled: bool,
    retired: bool,
    freshness: Option<DateTime<Utc>>,
    created: DateTime<Utc>,
    summary: Option<WatchRunSummary>,
    summary_session: Option<String>,
}

fn read_state(db: &Connection, spec: &WatchSpec) -> Result<WatchState> {
    Ok(db.query_row("SELECT prior.state_hash,prior.session_id,prior.sample_json,latest.session_id,latest.seq_no,b.sample_json,
        s.observation_errors,w.active,s.retired,s.last_success_at,w.created_at,s.summary_json,s.summary_session_id,s.summary_errors,
        prior.observation_id,b.observation_id
        FROM watch_state s JOIN watch_specs w USING(host_id,watch_id,spec_version)
        LEFT JOIN observations prior ON s.last_success_id=prior.observation_id
        LEFT JOIN observations latest ON s.last_observation_id=latest.observation_id
        LEFT JOIN baseline_revisions b ON s.baseline_revision_id=b.revision_id
        WHERE s.host_id=?1 AND s.watch_id=?2 AND s.spec_version=?3",
        params![spec.host_id,spec.id,spec.version], |r| Ok(WatchState {
            last_hash:r.get(0)?,last_success_id:r.get(14)?,baseline_observation_id:r.get(15)?,last_session:r.get(1)?,last_sample:optional_json(r,2)?,latest_session:r.get(3)?,latest_seq:r.get(4)?,
            baseline:optional_json(r,5)?,observation_errors:r.get(6)?,enabled:r.get(7)?,retired:r.get(8)?,
            freshness:r.get::<_,Option<String>>(9)?.map(|v| crate::service::parse_stamp(&v,9)).transpose()?,
            created:crate::service::parse_stamp(&r.get::<_,String>(10)?,10)?,summary:optional_json(r,11)?,summary_session:r.get(12)?,summary_errors:r.get(13)?,
        }))?)
}

fn heartbeat_watch(
    db: &Connection,
    spec: &WatchSpec,
    session: &str,
    summary: Option<&WatchRunSummary>,
    policy_version: u32,
    now: DateTime<Utc>,
) -> Result<()> {
    let state = read_state(db, spec)?;
    let mut errors = if state.summary_session.as_deref() == Some(session) {
        state.summary_errors
    } else {
        0
    };
    let mut freshness = state.freshness;
    let mut status = ObservationStatus::Ok;
    if let Some(summary) = summary {
        let previous = state
            .summary
            .filter(|_| state.summary_session.as_deref() == Some(session));
        if previous.as_ref().is_some_and(|p| {
            summary.completed_runs < p.completed_runs
                || summary.success_runs < p.success_runs
                || summary.error_runs < p.error_runs
        }) {
            return Ok(());
        }
        let retired = spec.class == WatchClass::Ephemeral
            && spec
                .lifecycle
                .max_runs
                .is_some_and(|max| summary.completed_runs >= max);
        if retired {
            db.execute("UPDATE watch_state SET retired=1 WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3", params![spec.host_id,spec.id,spec.version])?;
        }
        status = summary.last_status;
        let new_errors = summary
            .error_runs
            .saturating_sub(previous.as_ref().map_or(0, |p| p.error_runs));
        let new_successes = summary
            .success_runs
            .saturating_sub(previous.as_ref().map_or(0, |p| p.success_runs));
        // Summaries and observation frames may describe the same run. Track
        // each source independently to avoid counting an error twice.
        errors = if status.is_valid_sample() {
            0
        } else if new_successes > 0 {
            1
        } else {
            errors.saturating_add(new_errors.min(u64::from(u32::MAX)) as u32)
        };
        if let Some(success) = summary.last_success_at {
            freshness = freshness.max(Some(success.min(now)));
        }
        db.execute("UPDATE watch_state SET summary_json=?4,summary_session_id=?5,last_success_at=?6,summary_errors=?7
            WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
            params![spec.host_id,spec.id,spec.version,serde_json::to_string(summary)?,session,freshness.map(stamp),errors])?;
    }
    if matches!(spec.trigger, TriggerPredicate::CollectorStaleOrError { .. }) {
        let stale = (now - freshness.unwrap_or(state.created))
            .num_seconds()
            .max(0) as u64;
        let outcome =
            evaluate_predicate(&spec.trigger, status, None, None, None, None, errors, stale);
        db.execute("UPDATE watch_state SET outcome_json=?4 WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
            params![spec.host_id,spec.id,spec.version,serde_json::to_string(&outcome)?])?;
        if matches!(outcome, PredicateOutcome::Triggered { .. }) {
            trigger(db, spec, &outcome, &[], policy_version, now)?;
        }
    }
    Ok(())
}

fn trigger(
    db: &Connection,
    spec: &WatchSpec,
    outcome: &PredicateOutcome,
    evidence: &[Option<i64>],
    policy_version: u32,
    now: DateTime<Utc>,
) -> Result<()> {
    let PredicateOutcome::Triggered { reason, details } = outcome else {
        return Ok(());
    };
    let health = matches!(spec.trigger, TriggerPredicate::CollectorStaleOrError { .. });
    let comparison = match spec.trigger {
        TriggerPredicate::CollectorStaleOrError { .. } => json!("collector_health"),
        TriggerPredicate::ThresholdSustained { .. } => json!("sustained_threshold"),
        _ => details.clone(),
    };
    let fingerprint = canonical_sha256_hex(&(spec.version, comparison))?;
    let prior: Option<(i64, String)> = db.query_row(
        "SELECT t.event_id,t.incident_id FROM trigger_events t JOIN incidents i USING (incident_id)
        WHERE t.host_id=?1 AND t.watch_id=?2 AND t.fingerprint=?3 AND t.created_at>=?4
        AND t.status IN ('pending','suppressed') AND i.status='open' ORDER BY t.event_id DESC LIMIT 1",
        params![spec.host_id,spec.id,fingerprint,stamp(now-Duration::minutes(10))], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    let (event, incident) = if let Some((event, incident)) = prior {
        db.execute(
            "UPDATE trigger_events SET updated_at=?2 WHERE event_id=?1",
            params![event, stamp(now)],
        )?;
        (event, incident)
    } else {
        let incident = if let Some(incident) = &spec.incident_id {
            incident.clone()
        } else if let Some(existing) = db
            .query_row(
                "SELECT i.incident_id FROM trigger_events t JOIN incidents i USING (incident_id)
                WHERE t.host_id=?1 AND t.watch_id=?2 AND i.status='open' AND i.is_liveness=0
                ORDER BY i.updated_at DESC LIMIT 1",
                params![spec.host_id, spec.id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            db.execute(
                "UPDATE incidents SET summary=?2, updated_at=?3 WHERE incident_id=?1",
                params![existing, reason, stamp(now)],
            )?;
            existing
        } else {
            let incident = uuid();
            let severity = if health {
                Severity::High
            } else {
                Severity::Medium
            };
            db.execute("INSERT INTO incidents (incident_id,host_id,status,priority_json,summary,created_at,updated_at)
                VALUES (?1,?2,'open',?3,?4,?5,?5)", params![incident,spec.host_id,serde_json::to_string(&severity)?,reason,stamp(now)])?;
            audit(
                db,
                IncidentOpened,
                "control",
                &uuid(),
                json!({"incident_id":incident,"host_id":spec.host_id,"watch_id":spec.id,"observation_id":evidence.first().copied().flatten(),"fingerprint":fingerprint}),
            )?;
            incident
        };
        let cutoff = stamp(now - Duration::hours(1));
        let last_watch: Option<String> = db.query_row(
            "SELECT MAX(woke_at) FROM wake_budget_state WHERE host_id=?1 AND watch_id=?2",
            params![spec.host_id, spec.id],
            |r| r.get(0),
        )?;
        let last_watch = last_watch
            .as_deref()
            .map(|value| crate::service::parse_stamp(value, 0))
            .transpose()?;
        let (watch,host,global,incident_wakes): (u32,u32,u32,u32) = db.query_row(
            "SELECT COUNT(CASE WHEN host_id=?1 AND watch_id=?2 THEN 1 END), COUNT(CASE WHEN host_id=?1 THEN 1 END),
             COUNT(*), COUNT(CASE WHEN incident_id=?4 THEN 1 END) FROM wake_budget_state WHERE woke_at>?3",
            params![spec.host_id,spec.id,cutoff,incident], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        let config = WakeBudgetConfig::default();
        let cooldown = last_watch.map_or(0, |last| {
            let remaining = (DateTime::<Utc>::MAX_UTC - last).num_seconds().max(0) as u64;
            spec.wake_policy.cooldown_seconds.min(remaining)
        });
        let wake = check_wake_budget(
            now,
            health,
            cooldown,
            spec.wake_policy.max_wakeups_per_hour,
            last_watch,
            watch,
            host,
            global,
            &config,
        );
        let suppressed = match wake {
            WakeDecision::Suppress { reason } => Some(reason),
            WakeDecision::Allow
                if !health && incident_wakes >= config.max_host_wakeups_per_hour =>
            {
                Some("incident hourly wake budget exhausted".into())
            }
            WakeDecision::Allow => None,
        };
        db.execute("INSERT INTO trigger_events (incident_id,host_id,watch_id,spec_version,fingerprint,created_at,updated_at,status,outcome_json)
            VALUES (?1,?2,?3,?4,?5,?6,?6,?7,?8)", params![incident,spec.host_id,spec.id,spec.version,fingerprint,stamp(now),
                if suppressed.is_some() {"suppressed"} else {"pending"},json!({"predicate":outcome,"suppression":suppressed,"reason":reason}).to_string()])?;
        let event = db.last_insert_rowid();
        if suppressed.is_none() {
            db.execute(
                "INSERT INTO wake_budget_state VALUES (?1,?2,?3,?4,?5)",
                params![event, spec.host_id, spec.id, incident, stamp(now)],
            )?;
        }
        let decision = PolicyDecision {
            allowed: suppressed.is_none(),
            rule_id: "wake.budget".into(),
            reason: suppressed.unwrap_or_else(|| "wake admitted".into()),
            policy_version,
        };
        record_decision(
            db,
            None,
            "control",
            &uuid(),
            &decision,
            json!({"event_id":event,"incident_id":incident,"host_id":spec.host_id,"watch_id":spec.id}),
            now,
        )?;
        (event, incident)
    };
    for id in evidence.iter().flatten() {
        db.execute(
            "INSERT OR IGNORE INTO trigger_evidence VALUES (?1,?2)",
            params![event, id],
        )?;
    }
    db.execute(
        "UPDATE incidents SET updated_at=?2 WHERE incident_id=?1",
        params![incident, stamp(now)],
    )?;
    Ok(())
}
