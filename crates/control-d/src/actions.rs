use chrono::{DateTime, Duration, Utc};
use defsec_policy::{
    action_gate::{ActionProposalContext, evaluate_action_proposal},
    edge_floor::is_valid_identifier,
};
use defsec_protocol::{
    action::{
        ACTION_INTENT_SCHEMA_VERSION, ActionAuthMode, ActionIntentPayload, ActionIntentStatus,
        ActionReceipt, ActionSummary, ActionVerb, AuthorizedActionIntent,
    },
    audit::AuditEventType::{
        ActionApproved, ActionProposed, ActionReceiptRecorded, ActionRolledBack,
    },
    rpc::{AdminResponse, IncidentSummary, InvestigationResponse, ScopedCapability},
    signing::{DOMAIN_ACTION_APPROVAL_V1, DOMAIN_ACTION_INTENT_V1, SignedEnvelope},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{json, to_string};

use crate::{
    investigation::{require_text, scoped_evidence},
    ledger::{audit, json_column, rows},
    service::{ControlError, ControlService, Result, get_incident, parse_stamp, stamp, uuid},
};

pub(crate) struct ActionProposal<'a> {
    pub capability: &'a ScopedCapability,
    pub delegated: bool,
    pub request_id: &'a str,
    pub incident: &'a IncidentSummary,
    pub run_id: &'a str,
    pub idempotency_key: &'a str,
    pub verb: ActionVerb,
    pub evidence_observation_ids: Vec<i64>,
    pub expected_effect: &'a str,
    pub blast_radius: &'a str,
    pub rollback_plan: &'a str,
    pub now: DateTime<Utc>,
}

impl ControlService {
    pub fn register_operator_key(&self, key_id: impl Into<String>, pub_hex: &str) -> Result<()> {
        let key_id = key_id.into();
        if !is_valid_identifier(&key_id) {
            return Err(ControlError::invalid("invalid operator key ID"));
        }
        self.0
            .operator_keys
            .lock()
            .map_err(|_| std::io::Error::other("operator key store lock poisoned"))?
            .insert_public_hex(key_id, pub_hex)?;
        Ok(())
    }

    pub(crate) fn propose_action(
        &self,
        db: &Connection,
        mut proposal: ActionProposal<'_>,
    ) -> Result<InvestigationResponse> {
        require_text(proposal.idempotency_key, "idempotency_key", 128)?;
        require_text(proposal.expected_effect, "expected_effect", 4096)?;
        require_text(proposal.blast_radius, "blast_radius", 4096)?;
        require_text(proposal.rollback_plan, "rollback_plan", 4096)?;
        if proposal.evidence_observation_ids.len() > 100 {
            return Err(ControlError::invalid(
                "action proposals may cite at most 100 observations",
            ));
        }
        proposal.evidence_observation_ids.sort_unstable();
        proposal.evidence_observation_ids.dedup();
        let evidence_json = to_string(&proposal.evidence_observation_ids)?;
        let verb_json = to_string(&proposal.verb)?;
        let prior = db.query_row(
            "SELECT verb_json, expected_effect, blast_radius, rollback_plan, evidence_json, response_json
             FROM action_proposals WHERE run_id=?1 AND idempotency_key=?2",
            params![proposal.run_id, proposal.idempotency_key],
            |row| {
                let same_proposal =
                    row.get::<_, String>(0)? == verb_json
                    && row.get::<_, String>(1)? == proposal.expected_effect
                    && row.get::<_, String>(2)? == proposal.blast_radius
                    && row.get::<_, String>(3)? == proposal.rollback_plan
                    && row.get::<_, String>(4)? == evidence_json;
                Ok((same_proposal, json_column(row, 5)?))
            },
        ).optional()?;
        if let Some((same_proposal, response)) = prior {
            return if same_proposal {
                Ok(response)
            } else {
                Err(ControlError::invalid(
                    "idempotency key was reused with a different action proposal",
                ))
            };
        }

        let host = &proposal.incident.host_id;
        let incident = &proposal.incident.incident_id;
        let evidence = scoped_evidence(
            db,
            proposal.capability,
            proposal.incident,
            &proposal.evidence_observation_ids,
        )?;
        let mut cfg = std::borrow::Cow::Borrowed(&self.0.action_safety);
        if proposal.delegated {
            cfg.to_mut().allow_autonomous_verbs.clear();
        }
        let mut context = recent_actions(db, host, proposal.now, false)?;
        context.verified_evidence_count = evidence.as_ref().map_or(0, |verified| verified.len());
        let mut evaluation = evaluate_action_proposal(
            proposal.capability,
            host,
            incident,
            &proposal.verb,
            &context,
            &cfg,
            proposal.now,
        );
        if evidence.is_none() {
            evaluation.auth_mode = None;
            evaluation.decision.allowed = false;
            evaluation.decision.rule_id = "action.evidence_out_of_scope".into();
            evaluation.decision.reason =
                "observation evidence is missing or outside incident scope".into();
        }

        let decision_json = to_string(&evaluation.decision)?;
        let auth_mode_json = evaluation.auth_mode.as_ref().map(to_string).transpose()?;
        db.execute(
            "INSERT INTO action_proposals (run_id,idempotency_key,host_id,incident_id,verb_json,
                 expected_effect,blast_radius,rollback_plan,evidence_json,decision_json,auth_mode_json,
                 response_json,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'null',?12)",
            params![proposal.run_id, proposal.idempotency_key, host, incident, verb_json,
                proposal.expected_effect, proposal.blast_radius, proposal.rollback_plan,
                evidence_json, decision_json, auth_mode_json, stamp(proposal.now)],
        )?;
        let proposal_id = db.last_insert_rowid();
        let mut intent_id = None;
        let mut status = Some(ActionIntentStatus::Rejected);
        let mut authorized_intent = None;
        if let Some(mode) = evaluation.auth_mode {
            let id = uuid();
            let ttl_seconds = proposal
                .verb
                .ttl_seconds()
                .unwrap_or_else(|| cfg.max_dual_signed_ttl_seconds.min(900));
            let expires_at = i64::try_from(ttl_seconds)
                .ok()
                .and_then(Duration::try_seconds)
                .and_then(|ttl| proposal.now.checked_add_signed(ttl))
                .filter(|expiry| *expiry > proposal.now)
                .ok_or_else(|| ControlError::invalid("invalid action intent lifetime"))?;
            let payload = ActionIntentPayload {
                schema_version: ACTION_INTENT_SCHEMA_VERSION,
                intent_id: id.clone(),
                nonce: uuid(),
                host_id: host.clone(),
                incident_id: incident.clone(),
                proposal_id,
                auth_mode: mode,
                verb: proposal.verb.clone(),
                policy_version: evaluation.decision.policy_version,
                issued_at: proposal.now,
                expires_at,
                rollback_plan: proposal.rollback_plan.into(),
                evidence_observation_ids: proposal.evidence_observation_ids.clone(),
            };
            let control_envelope = self.0.key.sign_payload(DOMAIN_ACTION_INTENT_V1, &payload)?;
            let initial_status = match mode {
                ActionAuthMode::PolicyBoundedAutonomous => ActionIntentStatus::Authorized,
                ActionAuthMode::DualSignedOperator => ActionIntentStatus::PendingApproval,
            };
            db.execute(
                "INSERT INTO action_intents (intent_id,proposal_id,nonce,host_id,incident_id,
                     auth_mode_json,status_json,payload_json,control_envelope_json,created_at,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
                params![id, proposal_id, payload.nonce, host, incident, auth_mode_json,
                    to_string(&initial_status)?, to_string(&payload)?, to_string(&control_envelope)?,
                    stamp(proposal.now)],
            )?;
            if initial_status == ActionIntentStatus::Authorized {
                authorized_intent = Some(AuthorizedActionIntent {
                    control_envelope,
                    operator_approval: None,
                });
            }
            intent_id = Some(id);
            status = Some(initial_status);
        }
        let actor = &proposal.capability.principal_id;
        db.execute(
            "INSERT INTO policy_decisions (action_proposal_id,actor,request_id,decision_json,created_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![proposal_id, actor, proposal.request_id, decision_json, stamp(proposal.now)],
        )?;
        audit(
            db,
            ActionProposed,
            actor,
            proposal.request_id,
            json!({"proposal_id": proposal_id, "run_id": proposal.run_id, "host_id": host,
                "incident_id": incident, "intent_id": intent_id, "auth_mode": evaluation.auth_mode,
                "verb": proposal.verb, "evidence_observation_ids": proposal.evidence_observation_ids,
                "expected_effect": proposal.expected_effect, "blast_radius": proposal.blast_radius,
                "rollback_plan": proposal.rollback_plan, "decision": evaluation.decision, "status": status}),
        )?;
        let response = InvestigationResponse::ActionProposalEvaluated {
            decision: evaluation.decision,
            proposal_id: Some(proposal_id),
            intent_id,
            auth_mode: evaluation.auth_mode,
            status,
            authorized_intent,
        };
        db.execute(
            "UPDATE action_proposals SET response_json=?2 WHERE proposal_id=?1",
            params![proposal_id, to_string(&response)?],
        )?;
        Ok(response)
    }

    pub(super) fn approve_action(
        &self,
        db: &Connection,
        intent_id: &str,
        approver: &str,
        operator_approval: SignedEnvelope,
    ) -> Result<AdminResponse> {
        require_text(approver, "approver", 128)?;
        let intent = load_intent(db, intent_id)?;
        if intent.status != ActionIntentStatus::PendingApproval
            || intent.payload.auth_mode != ActionAuthMode::DualSignedOperator
        {
            return Err(ControlError::denied(
                "action intent is not pending dual approval",
            ));
        }
        let now = Utc::now();
        if intent.payload.expires_at <= now
            || get_incident(db, &intent.payload.incident_id)?.status != "open"
        {
            return Err(ControlError::denied(
                "action intent expired or its incident is closed",
            ));
        }
        if operator_approval.raw_payload != intent.authorization.control_envelope.raw_payload {
            return Err(ControlError::denied(
                "operator approval payload differs from control intent",
            ));
        }
        {
            let keys = self
                .0
                .operator_keys
                .lock()
                .map_err(|_| std::io::Error::other("operator key store lock poisoned"))?;
            let operator_id = &operator_approval.signing_key_id;
            if operator_id == self.0.key.key_id()
                || operator_id == &intent.authorization.control_envelope.signing_key_id
                || keys.get(operator_id) == Some(&self.0.key.verifying_key())
            {
                return Err(ControlError::denied(
                    "operator approval requires an independent signing key",
                ));
            }
            keys.verify_and_decode::<ActionIntentPayload>(
                DOMAIN_ACTION_APPROVAL_V1,
                &operator_approval,
            )
            .map_err(|error| ControlError::denied(format!("invalid operator approval: {error}")))?;
        }
        let recent = recent_actions(db, &intent.payload.host_id, now, true)?;
        let cfg = &self.0.action_safety;
        if recent.host_actions_last_hour >= cfg.max_actions_per_host_per_hour
            || recent.last_host_action_at.is_some_and(|last| {
                (now.signed_duration_since(last).num_seconds().max(0) as u64)
                    < cfg.causal_loop_cooldown_seconds
            })
        {
            return Err(ControlError::denied(
                "host action rate limit or cooldown is active",
            ));
        }

        db.execute(
            "UPDATE action_intents
             SET status_json=?2,operator_approval_json=?3,approver=?4,updated_at=?5
             WHERE intent_id=?1",
            params![
                intent_id,
                to_string(&ActionIntentStatus::Authorized)?,
                to_string(&operator_approval)?,
                approver,
                stamp(now)
            ],
        )?;
        audit(
            db,
            ActionApproved,
            approver,
            &uuid(),
            json!({
                "intent_id": intent_id, "host_id": intent.payload.host_id, "incident_id": intent.payload.incident_id,
                "operator_key_id": operator_approval.signing_key_id,
                "payload_digest": operator_approval.payload_sha256_hex(),
            }),
        )?;
        Ok(AdminResponse::ActionApproved {
            intent_id: intent_id.into(),
            authorized_intent: AuthorizedActionIntent {
                control_envelope: intent.authorization.control_envelope,
                operator_approval: Some(operator_approval),
            },
        })
    }
}

fn recent_actions(
    db: &Connection,
    host: &str,
    now: DateTime<Utc>,
    authorized_only: bool,
) -> Result<ActionProposalContext> {
    Ok(db.query_row(
        "SELECT COUNT(CASE WHEN updated_at > ?2 THEN 1 END), MAX(updated_at)
         FROM action_intents WHERE host_id=?1 AND (?3 IS NULL OR status_json != ?3)",
        params![
            host,
            stamp(now - Duration::hours(1)),
            authorized_only
                .then(|| to_string(&ActionIntentStatus::PendingApproval))
                .transpose()?
        ],
        |row| {
            Ok(ActionProposalContext {
                host_actions_last_hour: row.get(0)?,
                last_host_action_at: row
                    .get::<_, Option<String>>(1)?
                    .map(|time| parse_stamp(&time, 1))
                    .transpose()?,
                verified_evidence_count: 0,
            })
        },
    )?)
}

struct StoredIntent {
    payload: ActionIntentPayload,
    authorization: AuthorizedActionIntent,
    status: ActionIntentStatus,
}

fn load_intent(db: &Connection, intent_id: &str) -> Result<StoredIntent> {
    db.query_row(
        "SELECT payload_json,control_envelope_json,operator_approval_json,status_json
         FROM action_intents WHERE intent_id=?1",
        [intent_id],
        |row| {
            Ok(StoredIntent {
                payload: json_column(row, 0)?,
                authorization: AuthorizedActionIntent {
                    control_envelope: json_column(row, 1)?,
                    operator_approval: row
                        .get::<_, Option<String>>(2)?
                        .map(|_| json_column(row, 2))
                        .transpose()?,
                },
                status: json_column(row, 3)?,
            })
        },
    )
    .optional()?
    .ok_or_else(|| ControlError::missing("action intent not found"))
}

pub(super) fn get_action_intent(db: &Connection, intent_id: &str) -> Result<AdminResponse> {
    let intent = load_intent(db, intent_id)?;
    let authorized_intent = (intent.status == ActionIntentStatus::Authorized
        && intent.payload.expires_at > Utc::now())
    .then_some(intent.authorization);
    Ok(AdminResponse::ActionIntentDetail {
        payload: intent.payload,
        authorized_intent,
        status: intent.status,
    })
}

pub(crate) fn list_actions(
    db: &Connection,
    host: Option<&str>,
    incident: Option<&str>,
    allowed_hosts: Option<&[String]>,
) -> Result<Vec<ActionSummary>> {
    rows(
        db,
        "SELECT p.proposal_id,i.intent_id,p.host_id,p.incident_id,i.auth_mode_json,i.status_json,
                p.verb_json,p.expected_effect,p.blast_radius,p.rollback_plan,p.created_at,i.approver
         FROM action_intents i JOIN action_proposals p USING (proposal_id)
         WHERE (?1 IS NULL OR p.host_id=?1) AND (?2 IS NULL OR p.incident_id=?2)
           AND (?3 IS NULL OR p.host_id IN (SELECT value FROM json_each(?3)))
         ORDER BY p.proposal_id DESC",
        params![host, incident, allowed_hosts.map(to_string).transpose()?],
        |row| {
            Ok(ActionSummary {
                proposal_id: row.get(0)?,
                intent_id: row.get(1)?,
                host_id: row.get(2)?,
                incident_id: row.get(3)?,
                auth_mode: json_column(row, 4)?,
                status: json_column(row, 5)?,
                verb: json_column(row, 6)?,
                expected_effect: row.get(7)?,
                blast_radius: row.get(8)?,
                rollback_plan: row.get(9)?,
                created_at: parse_stamp(&row.get::<_, String>(10)?, 10)?,
                approver: row.get(11)?,
            })
        },
    )
}

pub(super) fn record_receipt(db: &Connection, receipt: ActionReceipt) -> Result<AdminResponse> {
    use ActionIntentStatus::*;
    let intent = load_intent(db, &receipt.intent_id)?;
    if receipt.intent_id != intent.payload.intent_id
        || receipt.host_id != intent.payload.host_id
        || receipt.nonce != intent.payload.nonce
    {
        return Err(ControlError::denied(
            "receipt intent, host, or nonce binding mismatch",
        ));
    }
    let receipt_json = to_string(&receipt)?;
    let duplicate: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM action_receipts WHERE intent_id=?1 AND receipt_json=?2)",
        params![receipt.intent_id, receipt_json],
        |row| row.get(0),
    )?;
    if !duplicate {
        match (intent.status, receipt.status) {
            (
                Authorized,
                Executed | DryRunSimulated | RolledBack | Rejected | VerificationFailed | Expired,
            )
            | (Executed | DryRunSimulated | VerificationFailed, RolledBack) => {}
            _ => return Err(ControlError::denied("invalid receipt status transition")),
        }
        let now = stamp(Utc::now());
        let status_json = to_string(&receipt.status)?;
        db.execute(
            "INSERT INTO action_receipts (intent_id,host_id,status_json,receipt_json,recorded_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                receipt.intent_id,
                receipt.host_id,
                status_json,
                receipt_json,
                now
            ],
        )?;
        db.execute(
            "UPDATE action_intents SET status_json=?2,updated_at=?3 WHERE intent_id=?1",
            params![receipt.intent_id, status_json, now],
        )?;
        let event = if receipt.status == RolledBack {
            ActionRolledBack
        } else {
            ActionReceiptRecorded
        };
        audit(db, event, "admin", &uuid(), serde_json::to_value(&receipt)?)?;
    }
    Ok(AdminResponse::ActionReceiptAck {
        intent_id: receipt.intent_id,
        status: receipt.status,
    })
}
