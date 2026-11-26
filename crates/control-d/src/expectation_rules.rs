use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use chrono::{DateTime, Duration, Utc};
use defsec_policy::{
    edge_floor::is_valid_identifier,
    predicate::{PredicateOutcome, evaluate_predicate},
    rule_gate::{RuleGateConfig, rule_field_registry, validate_rule},
    rules::{apply_expectation_rules, matching_rule_keys},
};
use defsec_protocol::{
    audit::AuditEventType::{RuleActivated, RuleProposed, RuleRejected, RuleRevoked},
    canonical::{sha256_hex, to_canonical_json_bytes},
    observation::ObservationStatus,
    rpc::{
        AdminRequest, AdminResponse, ExpectationRuleRecord, IncidentSummary, InvestigationResponse,
        PolicyDecision, RuleBacktest, ScopedCapability,
    },
    rules::{ActiveRule, ExpectationRuleSpec, MatchClause, RuleEffect, RuleOrigin},
    watch::{CollectorType, CompareTarget, TriggerPredicate, WatchClass, WatchSpec},
};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde_json::{Value, json};

use crate::{
    investigation::require_text,
    ledger::{audit, json_column, optional_json, rows},
    service::{ControlError, Result, parse_stamp, record_decision, require_host, stamp, uuid},
};

pub(crate) struct RuleStore<'a> {
    pub db: &'a Connection,
    pub now: DateTime<Utc>,
    pub request: &'a str,
    pub policy_version: u32,
}

impl RuleStore<'_> {
    pub fn propose(
        &self,
        cap: &ScopedCapability,
        incident: &IncidentSummary,
        run: &str,
        key: &str,
        rule: ExpectationRuleSpec,
    ) -> Result<InvestigationResponse> {
        require_text(key, "idempotency_key", 128)?;
        let spec = canonical_spec(&rule)?;
        let prior: Option<(String, InvestigationResponse)> = self
            .db
            .query_row(
                "SELECT spec_json,response_json FROM expectation_rule_proposal_receipts
             WHERE run_id=?1 AND idempotency_key=?2",
                params![run, key],
                |r| Ok((r.get(0)?, json_column(r, 1)?)),
            )
            .optional()?;
        if let Some((previous, response)) = prior {
            if spec != previous {
                return Err(ControlError::Request {
                    code: "conflict",
                    message: "idempotency key was reused with a different rule".into(),
                });
            }
            return Ok(response);
        }
        let decision = if rule.scope.host_id == incident.host_id
            && cap.allowed_hosts.contains(&rule.scope.host_id)
            && cap.allowed_collectors.contains(&rule.scope.collector)
        {
            let mut cfg = self.gate_config();
            (cfg.prior_run_proposals, cfg.pending_host_proposals) = self.db.query_row(
                "SELECT (SELECT COUNT(*) FROM expectation_rules WHERE run_id=?1),
                        (SELECT COUNT(*) FROM expectation_rules WHERE host_id=?2 AND status='proposed'
                         AND (expires_at IS NULL OR expires_at>?3))",
                params![run, rule.scope.host_id, stamp(self.now)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            self.validate(&rule, RuleOrigin::Investigator, &cfg)?
        } else {
            PolicyDecision {
                allowed: false,
                rule_id: "rule-gate/scope".into(),
                reason: "rule is outside the run's host or collector scope".into(),
                policy_version: self.policy_version,
            }
        };
        let admitted = if decision.allowed {
            let backtest = self.backtest(&rule, Some(&incident.incident_id))?;
            let id = format!("rule-{}", uuid());
            self.db.execute(
                "INSERT INTO expectation_rules (rule_id,host_id,collector_type,watch_id,spec_json,
                    status,origin,proposed_by,run_id,incident_id,idempotency_key,backtest_json,created_at,expires_at)
                 VALUES (?1,?2,?3,?4,?5,'proposed','investigator',?6,?7,?8,?9,?10,?11,?12)",
                params![id, rule.scope.host_id, rule.scope.collector.as_str(), rule.scope.watch_id,
                    spec, cap.principal_id, run, incident.incident_id, key,
                    serde_json::to_string(&backtest)?, stamp(self.now), rule.expires_at.map(stamp)],
            )?;
            Some((id, backtest))
        } else {
            None
        };
        let (rule_id, backtest) = admitted.unzip();
        audit(
            self.db,
            RuleProposed,
            &cap.principal_id,
            self.request,
            json!({"rule_id":rule_id,"spec":rule,"run_id":run,"incident_id":incident.incident_id,"idempotency_key":key}),
        )?;
        self.record(
            &cap.principal_id,
            &decision,
            json!({"operation":"propose","rule_id":rule_id,"run_id":run}),
        )?;
        let response = InvestigationResponse::RuleProposalEvaluated {
            decision,
            rule_id,
            backtest,
        };
        self.db.execute(
            "INSERT INTO expectation_rule_proposal_receipts (run_id,idempotency_key,spec_json,response_json)
             VALUES (?1,?2,?3,?4)",
            params![run, key, spec, serde_json::to_string(&response)?],
        )?;
        Ok(response)
    }

    pub fn create(&self, rule: &ExpectationRuleSpec, actor: &str) -> Result<AdminResponse> {
        require_text(actor, "actor", 128)?;
        let spec = canonical_spec(rule)?;
        let decision = self.validate(rule, RuleOrigin::Operator, &self.gate_config())?;
        let id = decision.allowed.then(|| format!("rule-{}", uuid()));
        self.record(
            actor,
            &decision,
            json!({"operation":"create","rule_id":id,"spec":rule}),
        )?;
        let Some(id) = id else {
            return Ok(decision_error(decision));
        };
        self.db.execute(
            "INSERT INTO expectation_rules (rule_id,host_id,collector_type,watch_id,spec_json,
                status,origin,proposed_by,created_at,decided_by,decided_at,expires_at)
             VALUES (?1,?2,?3,?4,?5,'active','operator',?6,?7,?6,?7,?8)",
            params![
                id,
                rule.scope.host_id,
                rule.scope.collector.as_str(),
                rule.scope.watch_id,
                spec,
                actor,
                stamp(self.now),
                rule.expires_at.map(stamp)
            ],
        )?;
        self.audit_activation(&id, actor, &spec, None)?;
        Ok(decided(id, "active"))
    }

    pub fn decide(
        &self,
        id: String,
        approve: bool,
        actor: &str,
        note: Option<&str>,
    ) -> Result<AdminResponse> {
        require_text(actor, "actor", 128)?;
        let (status, spec) = self.stored_rule(&id)?;
        if status != "proposed" {
            return Err(ControlError::invalid("only proposed rules can be decided"));
        }
        let decision = if approve {
            let rule = serde_json::from_str(&spec)?;
            self.validate(&rule, RuleOrigin::Operator, &self.gate_config())?
        } else {
            PolicyDecision {
                allowed: false,
                rule_id: "rule-gate/rejected".into(),
                reason: "operator rejected the proposal".into(),
                policy_version: self.policy_version,
            }
        };
        self.record(
            actor,
            &decision,
            json!({"operation":"decide","rule_id":id,"approve":approve,"note":note}),
        )?;
        if approve && !decision.allowed {
            return Ok(decision_error(decision));
        }
        if approve {
            self.set_status(&id, "active", actor, note)?;
            self.audit_activation(&id, actor, &spec, note)?;
            Ok(decided(id, "active"))
        } else {
            self.set_status(&id, "rejected", actor, note)?;
            audit(
                self.db,
                RuleRejected,
                actor,
                self.request,
                json!({"rule_id":id,"note":note}),
            )?;
            Ok(decided(id, "rejected"))
        }
    }

    pub fn revoke(&self, id: String, actor: &str, reason: &str) -> Result<AdminResponse> {
        require_text(actor, "actor", 128)?;
        require_text(reason, "reason", 1024)?;
        let (status, _) = self.stored_rule(&id)?;
        if status != "active" {
            return Err(ControlError::invalid("only active rules can be revoked"));
        }
        self.record(
            actor,
            &PolicyDecision {
                allowed: true,
                rule_id: "rule-gate/revoked".into(),
                reason: "operator revoked the rule".into(),
                policy_version: self.policy_version,
            },
            json!({"operation":"revoke","rule_id":id,"reason":reason}),
        )?;
        self.set_status(&id, "revoked", actor, Some(reason))?;
        audit(
            self.db,
            RuleRevoked,
            actor,
            self.request,
            json!({"rule_id":id,"reason":reason}),
        )?;
        Ok(decided(id, "revoked"))
    }

    pub fn admin_backtest(&self, rule: &ExpectationRuleSpec) -> Result<AdminResponse> {
        let decision = self.validate(rule, RuleOrigin::Operator, &self.gate_config())?;
        if !decision.allowed {
            return Ok(decision_error(decision));
        }
        Ok(AdminResponse::RuleBacktestResult {
            backtest: self.backtest(rule, None)?,
        })
    }

    pub fn list(
        &self,
        host: Option<&str>,
        capability: Option<&ScopedCapability>,
        statuses: Option<&[String]>,
        limit: Option<u32>,
        before: Option<&str>,
    ) -> Result<(Vec<ExpectationRuleRecord>, Option<String>)> {
        if let Some(statuses) = statuses
            && statuses.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "active" | "proposed" | "rejected" | "revoked" | "expired"
                )
            })
        {
            return Err(ControlError::invalid("unknown expectation rule status"));
        }
        let (before_time, before_id) = if let Some(cursor) = before {
            let invalid = || ControlError::invalid("invalid expectation rule cursor");
            require_text(cursor, "before", 256)?;
            let (time, id): (DateTime<Utc>, String) =
                serde_json::from_str(cursor).map_err(|_| invalid())?;
            if !is_valid_identifier(&id) {
                return Err(invalid());
            }
            (Some(stamp(time)), Some(id))
        } else {
            (None, None)
        };
        let limit = limit.unwrap_or(50).min(100) as usize;
        let mut rules = rows(
            self.db,
            "SELECT rule_id, effective_status, origin, proposed_by, run_id, incident_id, spec_json,
                    backtest_json, created_at, decided_by, decided_at, decision_note, hit_count, last_matched_at
             FROM (
                 SELECT *, CASE WHEN status IN ('proposed','active') AND expires_at<=?4 THEN 'expired' ELSE status END AS effective_status
                 FROM expectation_rules WHERE (?1 IS NULL OR host_id=?1)
                   AND (?2 IS NULL OR host_id IN (SELECT value FROM json_each(?2)))
                   AND (?8 IS NULL OR collector_type IN (SELECT value FROM json_each(?8)))
                   AND (?9 IS NULL OR incident_id IS NULL OR incident_id=?9)
             )
             WHERE (?3 IS NULL OR effective_status IN (SELECT value FROM json_each(?3)))
               AND (?6 IS NULL OR created_at<?6 OR (created_at=?6 AND rule_id>?7))
             ORDER BY created_at DESC, rule_id
             LIMIT ?5",
            params![host, capability.map(|cap| serde_json::to_string(&cap.allowed_hosts)).transpose()?,
                statuses.map(serde_json::to_string).transpose()?, stamp(self.now),
                limit + 1, before_time, before_id,
                capability.map(|cap| serde_json::to_string(&cap.allowed_collectors)).transpose()?,
                capability.and_then(|cap| cap.incident_id.as_deref())],
            |r| Ok(ExpectationRuleRecord {
                rule_id: r.get(0)?, status: r.get(1)?, origin: r.get(2)?, proposed_by: r.get(3)?,
                run_id: r.get(4)?, incident_id: r.get(5)?, spec: json_column(r, 6)?,
                backtest: optional_json(r, 7)?,
                created_at: parse_stamp(&r.get::<_, String>(8)?, 8)?, decided_by: r.get(9)?,
                decided_at: optional_stamp(r, 10)?, decision_note: r.get(11)?, hit_count: r.get(12)?,
                last_matched_at: optional_stamp(r, 13)?,
            }),
        )?;
        let next_before = if rules.len() > limit {
            rules.truncate(limit);
            rules
                .last()
                .map(|rule| serde_json::to_string(&(stamp(rule.created_at), &rule.rule_id)))
                .transpose()?
        } else {
            None
        };
        Ok((rules, next_before))
    }

    fn backtest(&self, rule: &ExpectationRuleSpec, incident: Option<&str>) -> Result<RuleBacktest> {
        // The ledger records receipt order and promotion time, but does not mark observations
        // received from historical sessions that did not advance watch_state. An earlier stored
        // successful sample can therefore differ from the prior live checkpoint. Promotion
        // timestamps use a strict comparison because timestamp ties have no common sequence.
        let fields = rule_field_registry(rule.scope.collector)
            .expect("backtest rules already passed collector validation");
        let samples = rows(
            self.db,
            "SELECT w.spec_json, o.status_json, o.sample_json,
                    (SELECT p.sample_json FROM observations p
                     WHERE p.host_id=o.host_id AND p.watch_id=o.watch_id
                       AND p.spec_version=o.spec_version AND p.observation_id<o.observation_id
                       AND p.sample_json IS NOT NULL ORDER BY p.observation_id DESC LIMIT 1),
                    CASE WHEN json_extract(w.spec_json,'$.trigger.compare_against')='accepted_baseline'
                         THEN (SELECT b.sample_json FROM baseline_revisions b
                               WHERE b.host_id=o.host_id AND b.watch_id=o.watch_id
                                 AND b.spec_version=o.spec_version AND b.approved_at<o.received_at
                               ORDER BY b.revision_id DESC LIMIT 1) END
             FROM observations o JOIN watch_specs w USING (host_id,watch_id,spec_version)
             WHERE o.host_id=?1 AND o.collector_type=?2 AND (?3 IS NULL OR o.watch_id=?3)
               AND o.sample_json IS NOT NULL AND json_extract(w.spec_json,'$.trigger.type')='set_diff'
               AND (?4 IS NULL OR w.incident_id IS NULL OR w.incident_id=?4)
               AND json_extract(w.spec_json,'$.trigger.set_field')=?5
               AND json_extract(w.spec_json,'$.trigger.identity_key')=?6
               AND json_type(o.sample_json, ?7)='array'
               AND NOT EXISTS (
                   SELECT 1 FROM json_each(o.sample_json, ?7) item
                   WHERE CASE WHEN item.type='object' THEN json_type(item.value, ?8) IS NULL ELSE 1 END
               )
             ORDER BY o.observation_id DESC LIMIT 50",
            params![
                rule.scope.host_id, rule.scope.collector.as_str(), rule.scope.watch_id, incident,
                fields.set_field, fields.identity_key, format!("$.{}", fields.set_field),
                format!("$.{}", fields.identity_key)
            ],
            |r| Ok((json_column::<WatchSpec>(r, 0)?, json_column::<ObservationStatus>(r, 1)?,
                json_column::<Value>(r, 2)?,
                optional_json::<Value>(r, 3)?, optional_json::<Value>(r, 4)?)),
        )?;
        let mut backtest = RuleBacktest {
            observations_scanned: samples.len() as u32,
            triggered_before: 0,
            triggered_after: 0,
            items_matched: 0,
            sample_keys: Vec::new(),
            currently_matching: 0,
        };
        let mut items = BTreeSet::new();
        let candidate = ActiveRule {
            rule_id: "backtest-candidate".into(),
            spec: rule.clone(),
        };
        let mut rules_by_watch = BTreeMap::new();
        for (index, (spec, status, sample, last, baseline)) in samples.into_iter().enumerate() {
            let TriggerPredicate::SetDiff {
                compare_against, ..
            } = spec.trigger
            else {
                continue;
            };
            let keys = matching_rule_keys(&spec.trigger, rule, &sample);
            if index == 0 {
                backtest.currently_matching = keys.len() as u32;
            }
            items.extend(keys);

            let reference = match compare_against {
                CompareTarget::LastObserved => last.as_ref(),
                CompareTarget::AcceptedBaseline => baseline.as_ref(),
            };
            let raw = evaluate_predicate(
                &spec.trigger,
                status,
                Some(&sample),
                last.as_ref(),
                baseline.as_ref(),
                None,
                0,
                0,
            );
            let active = match rules_by_watch.entry(spec.id.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(active_rules(
                    self.db,
                    &spec.host_id,
                    rule.scope.collector,
                    &spec.id,
                    self.now,
                )?),
            };
            let evaluate = |rules: &[ActiveRule]| {
                matches!(
                    apply_expectation_rules(
                        &spec.trigger,
                        rule.scope.collector,
                        raw.clone(),
                        status,
                        Some(&sample),
                        reference,
                        rules
                    )
                    .outcome,
                    PredicateOutcome::Triggered { .. }
                )
            };
            backtest.triggered_before += u32::from(evaluate(active));
            active.push(candidate.clone());
            backtest.triggered_after += u32::from(evaluate(active));
            active.pop();
        }
        backtest.items_matched = items.len() as u32;
        backtest.sample_keys = items.into_iter().take(10).collect();
        Ok(backtest)
    }

    fn gate_config(&self) -> RuleGateConfig {
        RuleGateConfig {
            policy_version: self.policy_version,
            ..Default::default()
        }
    }

    fn validate(
        &self,
        rule: &ExpectationRuleSpec,
        origin: RuleOrigin,
        cfg: &RuleGateConfig,
    ) -> Result<PolicyDecision> {
        let decision = validate_rule(rule, origin, self.now, cfg);
        if decision.allowed {
            if !is_valid_identifier(&rule.scope.host_id)
                || rule
                    .scope
                    .watch_id
                    .as_deref()
                    .is_some_and(|id| !is_valid_identifier(id))
            {
                return Ok(PolicyDecision {
                    allowed: false,
                    rule_id: "rule-gate/scope".into(),
                    reason: "invalid host or watch ID".into(),
                    policy_version: self.policy_version,
                });
            }
            require_host(self.db, &rule.scope.host_id)?;
        }
        Ok(decision)
    }

    fn record(&self, actor: &str, decision: &PolicyDecision, context: Value) -> Result<()> {
        record_decision(
            self.db,
            None,
            actor,
            self.request,
            decision,
            context,
            self.now,
        )
    }

    fn audit_activation(
        &self,
        id: &str,
        actor: &str,
        spec: &str,
        note: Option<&str>,
    ) -> Result<()> {
        audit(
            self.db,
            RuleActivated,
            actor,
            self.request,
            json!({"rule_id":id,"approver":actor,"spec_hash":sha256_hex(spec.as_bytes()),"note":note}),
        )
    }

    fn stored_rule(&self, id: &str) -> Result<(String, String)> {
        self.db
            .query_row(
                "SELECT status,spec_json FROM expectation_rules WHERE rule_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| ControlError::missing("expectation rule does not exist"))
    }

    fn set_status(&self, id: &str, status: &str, actor: &str, note: Option<&str>) -> Result<()> {
        self.db.execute(
            "UPDATE expectation_rules SET status=?2,decided_by=?3,decided_at=?4,decision_note=?5 WHERE rule_id=?1",
            params![id, status, actor, stamp(self.now), note],
        )?;
        Ok(())
    }
}

pub(crate) fn active_rules(
    db: &Connection,
    host: &str,
    collector: CollectorType,
    watch: &str,
    now: DateTime<Utc>,
) -> Result<Vec<ActiveRule>> {
    rows(
        db,
        "SELECT rule_id,spec_json FROM expectation_rules
        WHERE host_id=?1 AND collector_type=?2 AND status='active'
          AND (watch_id IS NULL OR watch_id=?3) AND (expires_at IS NULL OR expires_at>?4)
          AND NOT EXISTS (SELECT 1 FROM rule_maintenance_evidence e
                          WHERE e.rule_id=expectation_rules.rule_id AND e.activated=1)
        ORDER BY rule_id",
        params![host, collector.as_str(), watch, stamp(now)],
        |r| {
            Ok(ActiveRule {
                rule_id: r.get(0)?,
                spec: json_column(r, 1)?,
            })
        },
    )
}

pub(crate) fn record_rule_hits(db: &Connection, ids: &[String], now: DateTime<Utc>) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut update = db.prepare(
        "UPDATE expectation_rules SET hit_count=hit_count+1,last_matched_at=?2 WHERE rule_id=?1",
    )?;
    for id in ids {
        update.execute(params![id, stamp(now)])?;
    }
    Ok(())
}

fn optional_stamp(r: &Row<'_>, index: usize) -> rusqlite::Result<Option<DateTime<Utc>>> {
    r.get::<_, Option<String>>(index)?
        .map(|value| parse_stamp(&value, index))
        .transpose()
}

fn canonical_spec(rule: &ExpectationRuleSpec) -> Result<String> {
    Ok(String::from_utf8(to_canonical_json_bytes(rule)?).expect("canonical JSON is UTF-8"))
}

fn decision_error(decision: PolicyDecision) -> AdminResponse {
    AdminResponse::Error {
        code: decision.rule_id.clone(),
        message: decision.reason.clone(),
        decision: Some(decision),
    }
}

fn decided(rule_id: String, status: &str) -> AdminResponse {
    AdminResponse::RuleDecided {
        rule_id,
        status: status.into(),
    }
}

impl RuleStore<'_> {
    fn maintenance_decision(&self, allowed: bool, reason: &str) -> PolicyDecision {
        PolicyDecision {
            allowed,
            rule_id: "rule-gate/delegated-maintenance".into(),
            reason: reason.into(),
            policy_version: self.policy_version,
        }
    }

    pub fn maintenance_admin(&self, request: AdminRequest, actor: &str) -> Result<AdminResponse> {
        let context = serde_json::to_value(&request)?;
        let changed = match request {
            AdminRequest::SetRuleActivationGrant {
                host_id,
                collector,
                principal_id,
                enabled,
                rationale,
            } => {
                require_host(self.db, &host_id)?;
                require_text(&principal_id, "principal_id", 128)?;
                require_text(&rationale, "rationale", 1024)?;
                if enabled {
                    self.db.execute(
                        "INSERT OR IGNORE INTO rule_activation_grants VALUES (?1,?2,?3)",
                        params![host_id, collector.as_str(), principal_id],
                    )?;
                } else {
                    self.db.execute(
                        "DELETE FROM rule_activation_grants WHERE host_id=?1 AND collector_type=?2 AND principal_id=?3",
                        params![host_id, collector.as_str(), principal_id],
                    )?;
                    let revoked = rows(self.db,
                        "SELECT r.rule_id FROM expectation_rules r JOIN rule_maintenance_evidence e USING(rule_id)
                         WHERE e.activated=1 AND r.status='active' AND r.host_id=?1
                           AND r.collector_type=?2 AND r.proposed_by=?3",
                        params![host_id, collector.as_str(), principal_id], |r| r.get::<_, String>(0))?;
                    for id in revoked {
                        self.revoke(id, actor, &rationale)?;
                    }
                    self.db.execute(
                        "DELETE FROM rule_maintenance_evidence WHERE activated=0 AND rule_id IN (
                            SELECT rule_id FROM expectation_rules WHERE host_id=?1 AND collector_type=?2 AND proposed_by=?3)",
                        params![host_id, collector.as_str(), principal_id],
                    )?;
                }
                true
            }
            AdminRequest::CorroborateRuleMaintenance {
                rule_id,
                watch_version,
                before_id,
                after_id,
                rationale,
            } => {
                require_text(&rationale, "rationale", 1024)?;
                self.db.execute(
                    "INSERT INTO rule_maintenance_evidence
                     SELECT r.rule_id, ?2, ?3, ?4, ?5, ?6, ?7, 0
                     FROM expectation_rules r
                     JOIN observations b ON b.observation_id=?3
                     JOIN observations a ON a.observation_id=?4
                     WHERE r.rule_id=?1 AND r.origin='investigator' AND r.status='proposed'
                       AND r.expires_at>?7 AND a.observation_id>b.observation_id
                       AND a.host_id=r.host_id AND b.host_id=r.host_id
                       AND a.watch_id=r.watch_id AND b.watch_id=r.watch_id
                       AND a.spec_version=?2 AND b.spec_version=?2
                     ON CONFLICT(rule_id) DO UPDATE SET watch_version=excluded.watch_version,
                       before_id=excluded.before_id, after_id=excluded.after_id,
                       corroborated_by=excluded.corroborated_by, rationale=excluded.rationale,
                       corroborated_at=excluded.corroborated_at",
                    params![
                        rule_id,
                        watch_version,
                        before_id,
                        after_id,
                        actor,
                        rationale,
                        stamp(self.now)
                    ],
                )? == 1
            }
            _ => unreachable!("maintenance admin dispatch"),
        };
        let decision = self.maintenance_decision(
            changed,
            if changed {
                "maintenance administration recorded"
            } else {
                "corroboration requires a pending proposal and a distinct scoped evidence pair"
            },
        );
        self.record(actor, &decision, context)?;
        Ok(AdminResponse::RuleMaintenanceEvaluated { decision })
    }

    pub fn activate(
        &self,
        cap: &ScopedCapability,
        run: &str,
        id: &str,
    ) -> Result<InvestigationResponse> {
        let outcome = self.check_activation(cap, run, id)?;
        let (decision, backtest) = match outcome {
            Ok((spec, backtest)) => {
                let note = "fresh scoped backtest passed on corroborated maintenance transition";
                self.set_status(id, "active", &cap.principal_id, Some(note))?;
                self.db.execute(
                    "UPDATE rule_maintenance_evidence SET activated=1 WHERE rule_id=?1",
                    [id],
                )?;
                self.db.execute(
                    "UPDATE expectation_rules SET backtest_json=?2 WHERE rule_id=?1",
                    params![id, serde_json::to_string(&backtest)?],
                )?;
                self.audit_activation(id, &cap.principal_id, &spec, Some(note))?;
                (self.maintenance_decision(true, note), Some(backtest))
            }
            Err(reason) => (self.maintenance_decision(false, reason), None),
        };
        self.record(
            &cap.principal_id,
            &decision,
            json!({
                "operation":"activate", "rule_id":id, "run_id":run, "backtest":backtest
            }),
        )?;
        Ok(InvestigationResponse::RuleActivationEvaluated { decision, backtest })
    }

    fn check_activation(
        &self,
        cap: &ScopedCapability,
        run: &str,
        id: &str,
    ) -> Result<std::result::Result<(String, RuleBacktest), &'static str>> {
        if cap.role != defsec_protocol::rpc::PrincipalRole::Investigator
            || cap.run_id.as_deref() != Some(run)
        {
            return Ok(Err(
                "activation requires the authenticated investigator run",
            ));
        }
        let proposal = self.db.query_row(
            "SELECT r.spec_json FROM expectation_rules r
             JOIN incidents i ON i.incident_id=r.incident_id
             JOIN rule_activation_grants g ON g.host_id=r.host_id AND g.collector_type=r.collector_type
                 AND g.principal_id=r.proposed_by
             WHERE r.rule_id=?1 AND r.run_id=?2 AND r.proposed_by=?3 AND r.incident_id=?4
               AND r.status='proposed' AND r.origin='investigator' AND i.status='open'",
            params![id, run, cap.principal_id, cap.incident_id], |r| r.get::<_, String>(0),
        ).optional()?;
        let Some(encoded) = proposal else {
            return Ok(Err(
                "activation requires a pending own-run proposal and an explicit host and collector grant",
            ));
        };
        let rule: ExpectationRuleSpec = serde_json::from_str(&encoded)?;
        let Some(watch) = rule.scope.watch_id.as_deref() else {
            return Ok(Err("activation requires an explicit watch"));
        };
        let anchored = |name: &str| {
            rule.matches
                .iter()
                .any(|clause| matches!(clause, MatchClause::Eq { field, .. } if field == name))
        };
        if !cap.allowed_hosts.contains(&rule.scope.host_id)
            || !cap.allowed_collectors.contains(&rule.scope.collector)
            || rule.scope.collector != CollectorType::SocketsListening
            || rule.rationale.trim().is_empty()
            || rule.effect != RuleEffect::AllowOptional
            || !rule
                .matches
                .iter()
                .all(|clause| matches!(clause, MatchClause::Eq { .. }))
            || ![
                "protocol",
                "local_addr",
                "local_port",
                "uid",
                "systemd_unit",
            ]
            .into_iter()
            .all(anchored)
            || !self
                .validate(&rule, RuleOrigin::Investigator, &self.gate_config())?
                .allowed
            || rule
                .expires_at
                .is_none_or(|expiry| expiry > self.now + Duration::hours(1))
        {
            return Ok(Err(
                "activation requires an in-scope exact listener rule expiring within one hour",
            ));
        }
        let Some(spec) = crate::service::active_watches(self.db, &rule.scope.host_id, self.now)?
            .into_iter()
            .find(|spec| spec.id == watch)
        else {
            return Ok(Err("watch is no longer active"));
        };
        if spec.class != WatchClass::Ephemeral
            || spec.incident_id != cap.incident_id
            || spec.collector.collector_type() != rule.scope.collector
            || !matches!(
                spec.trigger,
                TriggerPredicate::SetDiff {
                    compare_against: CompareTarget::LastObserved,
                    ..
                }
            )
        {
            return Ok(Err(
                "protected coverage or an incompatible watch is outside delegated activation",
            ));
        }
        let conflict: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM incidents WHERE host_id=?1 AND status='open' AND incident_id<>?2)
                 OR EXISTS(SELECT 1 FROM expectation_rules WHERE host_id=?1 AND collector_type=?3
                     AND status='active' AND (watch_id IS NULL OR watch_id=?4)
                     AND (expires_at IS NULL OR expires_at>?5))",
            params![rule.scope.host_id, cap.incident_id, rule.scope.collector.as_str(), watch, stamp(self.now)],
            |r| r.get(0),
        )?;
        if conflict {
            return Ok(Err(
                "conflicting incident or active rule requires operator review",
            ));
        }
        let pair = self.db.query_row(
            "SELECT b.sample_json,a.sample_json FROM rule_maintenance_evidence e
             JOIN observations b ON b.observation_id=e.before_id
             JOIN observations a ON a.observation_id=e.after_id
             JOIN watch_state s ON s.host_id=a.host_id AND s.watch_id=a.watch_id AND s.spec_version=a.spec_version
             JOIN hosts h ON h.host_id=a.host_id AND h.session_id=a.session_id
             WHERE e.rule_id=?1 AND e.watch_version=?2 AND e.activated=0
               AND s.retired=0 AND s.last_observation_id=a.observation_id AND s.last_success_id=a.observation_id
               AND b.session_id=a.session_id AND a.seq_no>b.seq_no
               AND json_extract(b.record_json,'$.is_reconciliation') IS NOT 1
               AND json_extract(a.record_json,'$.is_reconciliation') IS NOT 1
               AND coalesce(json_array_length(b.record_json,'$.partial_reasons'),0)=0
               AND coalesce(json_array_length(a.record_json,'$.partial_reasons'),0)=0
               AND b.status_json=?3 AND a.status_json=?3
               AND a.collector_type=?6 AND b.collector_type=?6
               AND b.received_at>=?4 AND b.observed_at>=?4 AND a.observed_at>b.observed_at
               AND a.observed_at<=?5 AND e.corroborated_at>=a.received_at
               AND NOT EXISTS (SELECT 1 FROM observations p WHERE p.host_id=a.host_id AND p.watch_id=a.watch_id
                   AND p.spec_version=a.spec_version AND p.observation_id>b.observation_id AND p.observation_id<a.observation_id)",
            params![id, spec.version, serde_json::to_string(&ObservationStatus::Ok)?,
                stamp(self.now - Duration::minutes(15)), stamp(self.now), rule.scope.collector.as_str()],
            |r| Ok((optional_json::<Value>(r, 0)?, optional_json::<Value>(r, 1)?)),
        ).optional()?;
        let Some((Some(before), Some(after))) = pair else {
            return Ok(Err(
                "fresh corroborated evidence for the current watch checkpoint is required",
            ));
        };
        let Some(backtest) = maintenance_backtest(id, &rule, &spec, &before, &after) else {
            return Ok(Err(
                "scoped backtest must suppress exactly one corroborated loopback listener addition",
            ));
        };
        Ok(Ok((encoded, backtest)))
    }
}

fn maintenance_backtest(
    id: &str,
    rule: &ExpectationRuleSpec,
    spec: &WatchSpec,
    before: &Value,
    after: &Value,
) -> Option<RuleBacktest> {
    for snapshot in [before, after] {
        let decoded: defsec_protocol::observation::SocketsListeningSnapshot =
            serde_json::from_value(snapshot.clone()).ok()?;
        if decoded.partial_attribution || decoded.count != decoded.sockets.len() {
            return None;
        }
        let mut keys = BTreeSet::new();
        for item in decoded.sockets {
            let address: std::net::IpAddr = item.local_addr.parse().ok()?;
            let address = match address {
                std::net::IpAddr::V4(_) => item.local_addr,
                std::net::IpAddr::V6(_) => format!("[{}]", item.local_addr),
            };
            let expected = format!(
                "{}:{address}:{}:uid={}",
                item.protocol, item.local_port, item.uid
            );
            if item.socket_key != expected || !keys.insert(item.socket_key) {
                return None;
            }
        }
    }
    let keys = matching_rule_keys(&spec.trigger, rule, after);
    let [key] = keys.as_slice() else { return None };
    if !matching_rule_keys(&spec.trigger, rule, before).is_empty() {
        return None;
    }
    let item = after["sockets"]
        .as_array()?
        .iter()
        .find(|item| item["socket_key"] == *key)?;
    let address = item["local_addr"]
        .as_str()?
        .parse::<std::net::IpAddr>()
        .ok()?;
    let unit = item["systemd_unit"].as_str()?;
    if !address.is_loopback()
        || !(1024..=65535).contains(&item["local_port"].as_u64()?)
        || item["uid"].as_u64()? == 0
        || !unit.ends_with(".service")
        || defsec_policy::action_gate::ActionSafetyConfig::default()
            .protected_units
            .contains(unit)
        || !matches!(item["protocol"].as_str()?, "tcp" | "udp" | "tcp6" | "udp6")
    {
        return None;
    }
    let raw = evaluate_predicate(
        &spec.trigger,
        ObservationStatus::Ok,
        Some(after),
        Some(before),
        None,
        None,
        0,
        0,
    );
    let PredicateOutcome::Triggered { details, .. } = &raw else {
        return None;
    };
    if !details["added"]
        .as_array()?
        .iter()
        .any(|added| added == key)
    {
        return None;
    }
    let evaluation = apply_expectation_rules(
        &spec.trigger,
        rule.scope.collector,
        raw,
        ObservationStatus::Ok,
        Some(after),
        Some(before),
        &[ActiveRule {
            rule_id: id.into(),
            spec: rule.clone(),
        }],
    );
    if evaluation.suppressed_counts.get(id) != Some(&1) {
        return None;
    }
    Some(RuleBacktest {
        observations_scanned: 1,
        triggered_before: 1,
        triggered_after: u32::from(matches!(
            evaluation.outcome,
            PredicateOutcome::Triggered { .. }
        )),
        items_matched: 1,
        sample_keys: keys,
        currently_matching: 1,
    })
}

pub(crate) fn maintenance_rules(
    db: &Connection,
    spec: &WatchSpec,
    before: &Value,
    after: &Value,
    now: DateTime<Utc>,
) -> Result<Vec<ActiveRule>> {
    let candidates = rows(db,
        "SELECT r.rule_id,r.spec_json,b.sample_json,a.sample_json
         FROM expectation_rules r JOIN rule_maintenance_evidence e USING(rule_id)
         JOIN observations b ON b.observation_id=e.before_id
         JOIN observations a ON a.observation_id=e.after_id
         JOIN incidents i ON i.incident_id=r.incident_id
         JOIN rule_activation_grants g ON g.host_id=r.host_id AND g.collector_type=r.collector_type
             AND g.principal_id=r.proposed_by
         WHERE r.host_id=?1 AND r.watch_id=?2 AND e.watch_version=?3 AND r.expires_at>?4
           AND r.status='active' AND e.activated=1 AND i.status='open'
           AND NOT EXISTS (SELECT 1 FROM incidents c
                           WHERE c.host_id=r.host_id AND c.status='open' AND c.incident_id<>r.incident_id)",
        params![spec.host_id, spec.id, spec.version, stamp(now)],
        |r| Ok((ActiveRule { rule_id: r.get(0)?, spec: json_column(r,1)? },
            json_column::<Value>(r,2)?, json_column::<Value>(r,3)?)),
    )?;
    Ok(candidates
        .into_iter()
        .filter_map(|(rule, expected_before, expected_after)| {
            (before == &expected_before && after == &expected_after).then_some(rule)
        })
        .collect())
}
