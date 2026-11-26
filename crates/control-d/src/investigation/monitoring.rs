use chrono::{DateTime, Duration, Utc};
use defsec_policy::edge_floor::{is_valid_identifier, validate_watch_spec};
use defsec_protocol::{
    audit::AuditEventType::{BaselinePromoted, PolicyDecision},
    rpc::{AdminRequest, MonitoringOperation, PrincipalRole, ScopedCapability},
    watch::{CollectorSpec, CompareTarget, TriggerPredicate, WatchClass, WatchSpec},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::{
    ledger::{audit, json_column},
    service::{
        ControlError, ControlService, Result, active_watches, bundle_collector_denial,
        insert_watch, latest_spec, require_host, stamp,
    },
};

use super::require_text;

pub(crate) struct Monitoring<'a> {
    pub service: &'a ControlService,
    pub db: &'a Connection,
    pub now: DateTime<Utc>,
    pub request: &'a str,
}

struct Managed {
    spec_version: u32,
    owner: String,
    revision: u32,
    intent: Value,
}

impl Monitoring<'_> {
    fn record(&self, actor: &str, intent: &Value, decision: &Value) -> Result<()> {
        audit(
            self.db,
            PolicyDecision,
            actor,
            self.request,
            json!({
                "policy_version": self.service.policy().policy_version,
                "intent": intent,
                "decision": decision,
            }),
        )
    }

    fn managed(&self, host: &str, watch: &str) -> Result<Option<Managed>> {
        Ok(self
            .db
            .query_row(
                "SELECT spec_version,principal_id,revision,intent_json FROM monitoring_watches
             WHERE host_id=?1 AND watch_id=?2",
                params![host, watch],
                |r| {
                    Ok(Managed {
                        spec_version: r.get(0)?,
                        owner: r.get(1)?,
                        revision: r.get(2)?,
                        intent: json_column(r, 3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn investigate(
        &self,
        cap: &ScopedCapability,
        host: &str,
        watch: &str,
        change: MonitoringOperation,
    ) -> Result<Value> {
        let actor = &cap.principal_id;
        let intent = json!({"host_id":host,"watch_id":watch,"change":change});
        let decision = self.evaluate(cap, host, watch, change)?;
        self.record(actor, &intent, &decision)?;
        Ok(decision)
    }

    fn evaluate(
        &self,
        cap: &ScopedCapability,
        host: &str,
        watch: &str,
        change: MonitoringOperation,
    ) -> Result<Value> {
        let actor = &cap.principal_id;
        let deny = |reason: &str| Ok(json!({"allowed":false,"reason":reason}));
        if cap.role != PrincipalRole::Investigator
            || !cap.allowed_hosts.iter().any(|h| h == host)
            || cap.incident_id.is_some()
            || cap.run_id.is_some()
            || !is_valid_identifier(watch)
        {
            return deny("requires a host-scoped investigator capability");
        }
        let grant: Option<(u32, bool)> = self.db.query_row(
            "SELECT g.max_watches,g.allow_promotion FROM monitoring_grants g JOIN hosts h USING(host_id)
             WHERE g.host_id=?1 AND g.principal_id=?2 AND h.session_id IS NOT NULL",
            params![host,actor], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let Some((max_watches, allow_promotion)) = grant.filter(|(max, _)| *max > 0) else {
            return deny("active host monitoring grant required");
        };
        let managed = self.managed(host, watch)?;
        let previous = latest_spec(self.db, host, watch)?;
        if managed.as_ref().is_some_and(|m| &m.owner != actor)
            || previous.as_ref().is_some_and(|s| {
                !cap.allowed_collectors
                    .contains(&s.collector.collector_type())
                    || managed.as_ref().is_none_or(|m| m.spec_version != s.version)
            })
        {
            return deny("watch is outside the grant or operator-owned");
        }
        if let Some(existing) = &managed {
            let evidence: Vec<i64> = serde_json::from_value(existing.intent["evidence"].clone())?;
            if !self.evidence_in_scope(cap, host, &evidence)? {
                return deny("monitoring evidence is unavailable within scope");
            }
        }
        let replacement = match &change {
            MonitoringOperation::Test { spec } | MonitoringOperation::Apply { spec, .. } => {
                Some(spec)
            }
            _ => None,
        };
        if let Some(spec) = replacement {
            if spec.host_id != host
                || spec.id != watch
                || spec.class != WatchClass::Baseline
                || spec.incident_id.is_some()
                || !spec.lifecycle.enabled
                || spec.lifecycle.expires_at.is_some()
                || spec.lifecycle.max_runs.is_some()
                || !cap
                    .allowed_collectors
                    .contains(&spec.collector.collector_type())
                || !matches!(&spec.collector, CollectorSpec::SystemdUnitState(p) if p.unit.ends_with(".service"))
                || !matches!(&spec.trigger, TriggerPredicate::FieldChanged { compare_against: CompareTarget::LastObserved, fields }
                    if fields.iter().any(|field| field == "active_state"))
            {
                return deny("watch must be a permitted persistent service-state monitor");
            }
            let active = active_watches(self.db, host, self.now)?;
            match previous.as_ref() {
                None if spec.version != 1 => return deny("initial spec version must be one"),
                Some(old) if !active.contains(old)
                    || (old != spec && (!strengthens(old, spec) || self.baseline(old)?.is_some())) => {
                    return deny("revision requires active coverage and must preserve existing protection");
                }
                _ => {}
            }
            if let Some((rule_id, reason)) = bundle_collector_denial(
                self.db,
                host,
                active
                    .iter()
                    .filter(|watch| watch.id != spec.id)
                    .chain([spec])
                    .map(|watch| watch.collector.collector_type()),
            )? {
                return Ok(json!({"allowed":false,"rule_id":rule_id,"reason":reason}));
            }
            let policy = self.service.policy();
            if let Err(error) = validate_watch_spec(spec, &policy.edge_floor, self.now) {
                return deny(&error.to_string());
            }
            let cost = runs_per_hour(spec);
            if previous.as_ref() != Some(spec) {
                let count: u32 = self.db.query_row(
                    "SELECT count(*) FROM monitoring_watches WHERE host_id=?1 AND principal_id=?2",
                    params![host, actor],
                    |r| r.get(0),
                )?;
                let added_cost: u64 = active
                    .iter()
                    .filter(|w| w.class == WatchClass::Baseline && w.id != watch)
                    .map(runs_per_hour)
                    .sum();
                if (previous.is_none()
                    && (count >= max_watches
                        || active.len() >= policy.edge_floor.max_watches_total))
                    || added_cost + cost > 3600
                    || active.iter().any(|watch| {
                        watch.id != spec.id
                            && watch.collector == spec.collector
                            && watch.trigger == spec.trigger
                    })
                {
                    return deny("watch exceeds host budget or duplicates existing coverage");
                }
            }
            if matches!(change, MonitoringOperation::Test { .. }) {
                return Ok(json!({"allowed":true,"runs_per_hour":cost}));
            }
        }
        match change {
            MonitoringOperation::Inspect {} => {
                let Some(m) = managed else {
                    return deny("managed watch required");
                };
                let spec = previous.expect("managed watch references a spec");
                let candidates: Vec<Value> = crate::ledger::rows(self.db,
                    "SELECT candidate_id,observation_id,confirmation_id,rationale,predecessor_id,corroborated_by,promoted_id
                     FROM monitoring_candidates WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3
                     ORDER BY candidate_id DESC LIMIT 20", params![host, watch, spec.version], |r| Ok(json!({
                         "candidate_id":r.get::<_,i64>(0)?, "observations":[r.get::<_,i64>(1)?,r.get::<_,i64>(2)?],
                         "rationale":r.get::<_,String>(3)?, "predecessor":r.get::<_,Option<i64>>(4)?,
                         "corroborated":r.get::<_,Option<String>>(5)?.is_some(), "promoted_revision":r.get::<_,Option<i64>>(6)?,
                     })))?;
                Ok(
                    json!({"allowed":true,"revision":m.revision,"spec":spec,"intent":m.intent,
                    "baseline":self.baseline(&spec)?,"candidates":candidates}),
                )
            }
            MonitoringOperation::Test { .. } => unreachable!("test returned from validation"),
            MonitoringOperation::Apply {
                spec,
                expected_revision,
                purpose,
                expected_signal,
                evidence,
                review_at,
            } => {
                let revision = managed.as_ref().map_or(0, |m| m.revision);
                if revision != expected_revision
                    || review_at <= self.now
                    || review_at > self.now + Duration::days(90)
                    || evidence.is_empty()
                    || evidence.len() > 16
                    || require_text(&purpose, "purpose", 512).is_err()
                    || require_text(&expected_signal, "expected_signal", 512).is_err()
                {
                    return deny("expected watch revision or bounded monitoring intent is invalid");
                }
                if !self.evidence_in_scope(cap, host, &evidence)? {
                    return deny("monitoring evidence is unavailable within scope");
                }
                let Some(next) = revision.checked_add(1) else {
                    return deny("watch revisions exhausted");
                };
                let intent = json!({"purpose":purpose,"expected_signal":expected_signal,"evidence":evidence,
                    "review_at":review_at,"runs_per_hour":runs_per_hour(&spec)});
                let bundle = if previous.as_ref() != Some(&spec) {
                    insert_watch(self.db, &spec, actor, self.now)?;
                    if let Some(old) = previous {
                        self.db.execute(
                            "UPDATE watch_state SET (last_observation_id,last_success_id,last_success_at) =
                             (SELECT last_observation_id,last_success_id,last_success_at FROM watch_state
                              WHERE host_id=?1 AND watch_id=?2 AND spec_version=?4)
                             WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
                            params![host, watch, spec.version, old.version],
                        )?;
                    }
                    Some(
                        self.service
                            .issue_bundle(self.db, host, actor, self.request, self.now)?,
                    )
                } else {
                    None
                };
                self.db.execute(
                    "INSERT INTO monitoring_watches VALUES (?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(host_id,watch_id) DO UPDATE SET spec_version=excluded.spec_version,revision=excluded.revision,intent_json=excluded.intent_json",
                    params![host, watch, spec.version, actor, next, intent.to_string()],
                )?;
                Ok(match bundle {
                    Some(version) => {
                        json!({"allowed":true,"revision":next,"bundle_version":version})
                    }
                    None => json!({"allowed":true,"revision":next}),
                })
            }
            MonitoringOperation::Provisional {
                observations: [first, second],
                rationale,
            } => {
                let Some(spec) = previous else {
                    return deny("managed watch required");
                };
                if first >= second
                    || require_text(&rationale, "rationale", 512).is_err()
                    || self.sample(&spec, first)?.is_none()
                    || self.sample(&spec, second)?.is_none()
                {
                    return deny(
                        "two ordinary observations from the current session and a rationale are required",
                    );
                }
                self.db.execute(
                    "INSERT INTO monitoring_candidates(host_id,watch_id,spec_version,observation_id,confirmation_id,
                     principal_id,rationale,predecessor_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![host,watch,spec.version,first,second,actor,rationale,self.baseline(&spec)?],
                )?;
                Ok(json!({"allowed":true,"candidate_id":self.db.last_insert_rowid()}))
            }
            MonitoringOperation::Promote {
                candidate_id,
                expected_baseline,
            } => {
                let Some(spec) = previous else {
                    return deny("managed watch required");
                };
                if !allow_promotion || self.baseline(&spec)? != expected_baseline {
                    return deny("promotion grant or expected baseline is invalid");
                }
                let candidate = self.db.query_row(
                    "SELECT observation_id,confirmation_id,corroboration,corroborated_by FROM monitoring_candidates
                     WHERE candidate_id=?1 AND host_id=?2 AND watch_id=?3 AND spec_version=?4
                     AND principal_id=?5 AND predecessor_id IS ?6 AND promoted_id IS NULL AND corroboration IS NOT NULL AND corroborated_by IS NOT NULL",
                    params![candidate_id,host,watch,spec.version,actor,expected_baseline],
                    |r| Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)),
                ).optional()?;
                let Some((first, second, corroboration, corroborated_by)) = candidate else {
                    return deny("candidate requires operator corroboration for this predecessor");
                };
                let open: bool = self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM incidents WHERE host_id=?1 AND status='open')",
                    [host],
                    |r| r.get(0),
                )?;
                let latest: Option<i64> = self.db.query_row(
                    "SELECT last_observation_id FROM watch_state WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
                    params![host,watch,spec.version], |r| r.get(0),
                )?;
                let (Some((first_hash, _, first_at)), Some((hash, sample, second_at))) =
                    (self.sample(&spec, first)?, self.sample(&spec, second)?)
                else {
                    return deny("candidate evidence is unavailable");
                };
                let state: Value = serde_json::from_str(&sample)?;
                let CollectorSpec::SystemdUnitState(unit) = &spec.collector else {
                    return deny("collector is ineligible for delegated baseline promotion");
                };
                if open
                    || latest != Some(second)
                    || hash != first_hash
                    || first_at < stamp(self.now - Duration::days(1))
                    || second_at > stamp(self.now)
                    || second_at <= first_at
                    || state["active_state"] != "active"
                    || state["unit"].as_str() != Some(unit.unit.as_str())
                {
                    return deny(
                        "candidate requires fresh stable active service evidence and no open host incident",
                    );
                }
                self.db.execute(
                    "INSERT INTO baseline_revisions(host_id,watch_id,spec_version,predecessor_id,observation_id,state_hash,
                     sample_json,approver,approved_at,rationale,policy_version) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![host,watch,spec.version,expected_baseline,second,hash,sample,corroborated_by,stamp(self.now),
                        corroboration,self.service.policy().policy_version],
                )?;
                let revision = self.db.last_insert_rowid();
                self.set_baseline(&spec, Some(revision))?;
                self.db.execute(
                    "UPDATE monitoring_candidates SET promoted_id=?2 WHERE candidate_id=?1",
                    params![candidate_id, revision],
                )?;
                audit(
                    self.db,
                    BaselinePromoted,
                    actor,
                    self.request,
                    json!({"host_id":host,"watch_id":watch,
                    "revision_id":revision,"predecessor_id":expected_baseline,"candidate_id":candidate_id,
                    "observation_id":second,"corroboration":corroboration,"corroborated_by":corroborated_by}),
                )?;
                Ok(json!({"allowed":true,"baseline":revision}))
            }
        }
    }

    fn evidence_in_scope(
        &self,
        cap: &ScopedCapability,
        host: &str,
        evidence: &[i64],
    ) -> Result<bool> {
        for id in evidence {
            let collector: Option<String> = self
                .db
                .query_row(
                    "SELECT o.collector_type FROM observations o JOIN watch_specs w
                 USING (host_id,watch_id,spec_version)
                 WHERE o.host_id=?1 AND o.observation_id=?2 AND o.sample_json IS NOT NULL
                   AND w.incident_id IS NULL",
                    params![host, id],
                    |r| r.get(0),
                )
                .optional()?;
            if !cap
                .allowed_collectors
                .iter()
                .any(|c| collector.as_deref() == Some(c.as_str()))
            {
                return Ok(false);
            }
        }
        Ok(!evidence.is_empty())
    }

    fn sample(&self, spec: &WatchSpec, id: i64) -> Result<Option<(String, String, String)>> {
        Ok(self
            .db
            .query_row(
                "SELECT o.state_hash,o.sample_json,o.observed_at
             FROM observations o JOIN hosts h ON h.host_id=o.host_id AND h.session_id=o.session_id
             WHERE o.host_id=?1 AND o.watch_id=?2 AND o.spec_version=?3 AND o.observation_id=?4
               AND o.status_json='\"ok\"' AND o.sample_json IS NOT NULL
               AND json_extract(o.record_json,'$.is_reconciliation') IS NOT 1
               AND coalesce(json_array_length(o.record_json,'$.partial_reasons'),0)=0",
            params![spec.host_id,spec.id,spec.version,id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?)
    }

    fn baseline(&self, spec: &WatchSpec) -> Result<Option<i64>> {
        Ok(self.db.query_row(
            "SELECT baseline_revision_id FROM watch_state WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
            params![spec.host_id,spec.id,spec.version], |r| r.get(0),
        )?)
    }

    fn set_baseline(&self, spec: &WatchSpec, revision: Option<i64>) -> Result<()> {
        self.db.execute(
            "UPDATE watch_state SET baseline_revision_id=?4 WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
            params![spec.host_id,spec.id,spec.version,revision],
        )?;
        Ok(())
    }

    pub fn admin(&self, req: AdminRequest, actor: &str) -> Result<Value> {
        let intent = serde_json::to_value(&req)?;
        let result = match req {
            AdminRequest::SetMonitoringGrant {
                host_id,
                principal_id,
                max_watches,
                allow_promotion,
            } => {
                require_host(self.db, &host_id)?;
                require_text(&principal_id, "principal_id", 128)?;
                if max_watches as usize > self.service.policy().edge_floor.max_watches_total {
                    return Err(ControlError::invalid("grant exceeds host watch limit"));
                }
                self.db.execute(
                    "INSERT INTO monitoring_grants VALUES (?1,?2,?3,?4) ON CONFLICT(host_id,principal_id)
                     DO UPDATE SET max_watches=excluded.max_watches,allow_promotion=excluded.allow_promotion",
                    params![host_id,principal_id,max_watches,allow_promotion],
                )?;
                json!({"allowed":true})
            }
            AdminRequest::CorroborateMonitoring {
                candidate_id,
                rationale,
            } => {
                require_text(&rationale, "rationale", 512)?;
                let updated = self.db.execute(
                    "UPDATE monitoring_candidates SET corroboration=?2,corroborated_by=?3 WHERE candidate_id=?1
                     AND corroborated_by IS NULL AND promoted_id IS NULL",
                    params![candidate_id, rationale, actor],
                )?;
                json!({"allowed":updated == 1})
            }
            AdminRequest::RollbackMonitoring {
                host_id,
                watch_id,
                expected_baseline,
                rationale,
            } => {
                require_text(&rationale, "rationale", 512)?;
                self.rollback(&host_id, &watch_id, expected_baseline)?
            }
            _ => unreachable!("monitoring admin dispatch is exhaustive"),
        };
        self.record(actor, &intent, &result)?;
        Ok(result)
    }

    fn rollback(&self, host: &str, watch: &str, expected: i64) -> Result<Value> {
        let deny = || {
            Ok(json!({"allowed":false,"reason":"expected managed baseline is no longer current"}))
        };
        let Some(spec) = latest_spec(self.db, host, watch)? else {
            return deny();
        };
        if self.baseline(&spec)? != Some(expected) {
            return deny();
        }
        let predecessor: Option<Option<i64>> = self
            .db
            .query_row(
                "SELECT predecessor_id FROM monitoring_candidates
             WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3 AND promoted_id=?4",
                params![host, watch, spec.version, expected],
                |r| r.get(0),
            )
            .optional()?;
        let Some(predecessor) = predecessor else {
            return deny();
        };
        self.set_baseline(&spec, predecessor)?;
        Ok(json!({"allowed":true,"baseline":predecessor,"rolled_back":expected}))
    }
}

fn runs_per_hour(spec: &WatchSpec) -> u64 {
    3600_u64.div_ceil(spec.schedule.interval_seconds.max(1))
}

fn strengthens(old: &WatchSpec, new: &WatchSpec) -> bool {
    let (
        TriggerPredicate::FieldChanged {
            compare_against: CompareTarget::LastObserved,
            fields: old_fields,
        },
        TriggerPredicate::FieldChanged {
            compare_against: CompareTarget::LastObserved,
            fields: new_fields,
        },
    ) = (&old.trigger, &new.trigger)
    else {
        return false;
    };
    old.version.checked_add(1) == Some(new.version)
        && old.collector == new.collector
        && old.wake_policy == new.wake_policy
        && old.lifecycle == new.lifecycle
        && old.schedule.timeout_seconds == new.schedule.timeout_seconds
        && new.schedule.interval_seconds <= old.schedule.interval_seconds
        && old_fields.iter().all(|field| new_fields.contains(field))
        && (new.schedule.interval_seconds < old.schedule.interval_seconds
            || new_fields.iter().any(|field| !old_fields.contains(field)))
}
