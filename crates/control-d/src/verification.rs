//! Independent observations for the effect of a receipt. This module never dispatches actions.
use chrono::{DateTime, Duration, Utc};
use defsec_protocol::{
    action::{ActionIntentPayload, ActionIntentStatus, ActionReceipt, ActionVerb},
    audit::AuditEventType::ActionEffectObserved,
    observation::ObservationRecord,
    rpc::{AdminResponse, InvestigationResponse, ScopedCapability},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::net::IpAddr;

use crate::{
    ledger::{audit, rows},
    service::{ControlError, Result, stamp, uuid},
};

fn target(verb: &ActionVerb) -> String {
    match verb {
        ActionVerb::SystemdStopUnit { unit, .. } => format!("systemd:{unit}"),
        ActionVerb::HostIsolate { .. } => "host:isolation".into(),
        ActionVerb::NftBlockIp { ip, .. } => format!(
            "nft:{}",
            ip.parse::<IpAddr>()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| ip.clone())
        ),
    }
}

/// TTL and a new idempotency key do not establish the effect of the previous execution.
pub(crate) fn outstanding(db: &Connection, host: &str, verb: &ActionVerb) -> Result<bool> {
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM action_verification_plans p JOIN action_intents i USING(intent_id)
        WHERE p.host_id=?1 AND p.target_key=?2 AND NOT EXISTS (
            SELECT 1 FROM action_reconciliations a WHERE a.intent_id=i.intent_id AND a.receipt_cursor=
                COALESCE((SELECT MAX(receipt_id) FROM action_receipts WHERE intent_id=i.intent_id),0))
        AND (
            json_extract(i.status_json,'$')='authorized'
            OR (json_extract(i.status_json,'$') IN ('executed','verification_failed','rolled_back')
                AND COALESCE((SELECT c.result FROM action_effect_checks c WHERE c.intent_id=i.intent_id
                    AND c.receipt_id=(SELECT MAX(receipt_id) FROM action_receipts WHERE intent_id=i.intent_id)),
                    'indeterminate') IN ('indeterminate','awaiting_evidence'))))",
        params![host,target(verb)],|r|r.get(0))?)
}

pub(crate) fn active_service_precondition(
    db: &Connection, host: &str, unit: &str, evidence: &[i64], now: DateTime<Utc>,
) -> Result<Option<i64>> {
    Ok(db.query_row(
        "SELECT o.observation_id FROM observations o
         JOIN watch_state s ON s.last_observation_id=o.observation_id
         JOIN watch_specs w ON w.host_id=o.host_id AND w.watch_id=o.watch_id AND w.spec_version=o.spec_version
         JOIN hosts h ON h.host_id=o.host_id AND h.session_id=o.session_id
         WHERE o.host_id=?1 AND o.observation_id IN (SELECT value FROM json_each(?2))
           AND o.collector_type='systemd.unit_state' AND w.active=1 AND s.retired=0
           AND json_extract(w.spec_json,'$.collector.parameters.unit')=?3
           AND o.status_json='\"ok\"' AND json_extract(o.sample_json,'$.unit')=?3
           AND json_extract(o.sample_json,'$.active_state')='active'
           AND o.observed_at BETWEEN ?4 AND ?5 ORDER BY o.observation_id DESC LIMIT 1",
        params![host, serde_json::to_string(evidence)?, unit, stamp(now-Duration::minutes(5)), stamp(now)],
        |row| row.get(0),
    ).optional()?)
}

pub(crate) fn precondition_still_active(db: &Connection, intent: &str, now: DateTime<Utc>) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM action_verification_plans p
         JOIN observations pre ON pre.observation_id=p.precondition_id
         JOIN watch_state w USING(host_id,watch_id,spec_version)
         JOIN watch_specs spec USING(host_id,watch_id,spec_version)
         JOIN observations latest ON latest.observation_id=w.last_observation_id
         JOIN hosts h ON h.host_id=p.host_id AND h.session_id=pre.session_id
         WHERE p.intent_id=?1 AND spec.active=1 AND w.retired=0
           AND latest.session_id=pre.session_id AND latest.observed_at BETWEEN ?2 AND ?3
           AND NOT EXISTS (SELECT 1 FROM observations changed
             WHERE changed.host_id=pre.host_id AND changed.watch_id=pre.watch_id AND changed.spec_version=pre.spec_version
               AND changed.observation_id BETWEEN pre.observation_id AND latest.observation_id
               AND (changed.session_id<>pre.session_id OR changed.status_json<>'\"ok\"'
                    OR json_extract(changed.sample_json,'$.unit') IS NOT json_extract(pre.sample_json,'$.unit')
                    OR json_extract(changed.sample_json,'$.active_state') IS NOT 'active')))",
        params![intent, stamp(now-Duration::minutes(5)), stamp(now)], |r| r.get(0),
    )?)
}

pub(crate) fn prepare(db: &Connection, intent: &ActionIntentPayload, precondition: Option<i64>) -> Result<()> {
    db.execute(
        "INSERT INTO action_verification_plans(intent_id,host_id,target_key,precondition_id) VALUES(?1,?2,?3,?4)",
        params![intent.intent_id, intent.host_id, target(&intent.verb), precondition],
    )?;
    Ok(())
}

pub(crate) fn open_check(
    db: &Connection,
    receipt_id: i64,
    receipt: &ActionReceipt,
    intent: &ActionIntentPayload,
    now: DateTime<Utc>,
) -> Result<()> {
    use ActionIntentStatus::*;
    // Older ledgers have no pre-dispatch plan. Record the uncertainty explicitly.
    register_legacy(db, intent)?;
    let pre: Option<i64> = db.query_row(
        "SELECT precondition_id FROM action_verification_plans WHERE intent_id=?1",
        [&intent.intent_id],
        |r| r.get(0),
    )?;
    let deadline = if receipt.status == RolledBack {
        now + Duration::minutes(5)
    } else {
        intent.expires_at.min(now + Duration::minutes(5))
    };
    let (expected, reason) = if receipt.dry_run || receipt.status == DryRunSimulated {
        (None, "Simulation has no measurable host effect")
    } else if receipt.executed_at > now || receipt.executed_at < intent.issued_at || now >= deadline
    {
        (
            None,
            "Execution or collection falls outside the verification window",
        )
    } else if pre.is_none() {
        (
            None,
            "No matching pre-dispatch service-state evidence or supported effect sensor",
        )
    } else {
        match receipt.status {
            Executed | VerificationFailed => {
                (Some("inactive"), "Awaiting independent service state")
            }
            RolledBack => (Some("active"), "Awaiting restoration of pre-dispatch state"),
            _ => (None, "Receipt does not establish an executed change"),
        }
    };
    db.execute("UPDATE action_effect_checks SET result='indeterminate', reason='Superseded by a later receipt'
        WHERE intent_id=?1 AND result='awaiting_evidence'",[&intent.intent_id])?;
    db.execute("INSERT INTO action_effect_checks(receipt_id,intent_id,opened_at,deadline,expected_state,result,reason)
        VALUES(?1,?2,?3,?4,?5,?6,?7)",params![receipt_id,intent.intent_id,stamp(now),stamp(deadline),expected,
            if expected.is_some() {"awaiting_evidence"} else {"indeterminate"},reason])?;
    Ok(())
}

/// Called only for a complete, current, contiguous sample on an enabled service watch.
pub(crate) fn observe(
    db: &Connection,
    observation: &ObservationRecord,
    id: i64,
    unit: &str,
    sample: &Value,
    now: DateTime<Utc>,
) -> Result<()> {
    if sample["unit"].as_str() != Some(unit) || observation.observed_at > now {
        return Ok(());
    }
    let Some(active_state) = sample["active_state"].as_str() else {
        return Ok(());
    };
    if !matches!(active_state, "active" | "inactive" | "failed") {
        return Ok(());
    }
    let checks=rows(db,"SELECT c.receipt_id,c.intent_id,c.expected_state FROM action_effect_checks c
        JOIN action_verification_plans p USING(intent_id) JOIN observations pre ON pre.observation_id=p.precondition_id
        WHERE p.host_id=?1 AND p.target_key=?2 AND c.result='awaiting_evidence' AND pre.watch_id=?3 AND pre.spec_version=?4
          AND c.opened_at<?5 AND ?6<c.deadline AND pre.session_id=?7",
        params![observation.host_id,format!("systemd:{unit}"),observation.watch_id,observation.spec_version,
            stamp(observation.observed_at),stamp(now),observation.session_id],
        |r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))?;
    for (receipt, intent, expected) in checks {
        let result = if active_state == expected {
            "verified"
        } else {
            "contradicted"
        };
        db.execute("UPDATE action_effect_checks SET result=?1,observation_id=?2,reason='Observed service state' WHERE receipt_id=?3",
            params![result,id,receipt])?;
        audit(
            db,
            ActionEffectObserved,
            "control",
            &uuid(),
            json!({"receipt_id":receipt,"intent_id":intent,
            "observation_id":id,"state_hash":observation.state_hash,"expected":expected,"observed":active_state,"result":result}),
        )?;
    }
    Ok(())
}

fn receipt_detail(db: &Connection, intent: &str) -> Result<Value> {
    let (expected_effect,rollback_plan,pre): (String,String,Option<i64>)=db.query_row(
        "SELECT a.expected_effect,a.rollback_plan,p.precondition_id FROM action_intents i JOIN action_proposals a USING(proposal_id)
         LEFT JOIN action_verification_plans p USING(intent_id) WHERE i.intent_id=?1",[intent],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or_else(||ControlError::missing("action intent not found"))?;
    let receipts=rows(db,"SELECT r.receipt_id,r.status_json,c.expected_state,c.result,c.reason,c.deadline,c.observation_id,o.state_hash
        FROM action_receipts r LEFT JOIN action_effect_checks c USING(receipt_id) LEFT JOIN observations o ON o.observation_id=c.observation_id
        WHERE r.intent_id=?1 ORDER BY r.receipt_id",[intent],|r|{
            let result=r.get::<_,Option<String>>(3)?.unwrap_or_else(||"indeterminate".into());
            let deadline:Option<String>=r.get(5)?;
            let expired=result=="awaiting_evidence" && deadline.as_ref().is_some_and(|end|end<=&stamp(Utc::now()));
            Ok(json!({"receipt_id":r.get::<_,i64>(0)?,"receipt_status":crate::ledger::json_column::<Value>(r,1)?,
                "expected_state":r.get::<_,Option<String>>(2)?,"result":if expired {"indeterminate"} else {&result},
                "reason":if expired {Some("Evidence deadline elapsed".into())} else {r.get::<_,Option<String>>(4)?},
                "deadline":deadline,"observation_id":r.get::<_,Option<i64>>(6)?,"state_hash":r.get::<_,Option<String>>(7)?}))
        })?;
    Ok(json!({
        "intent_id": intent,
        "precondition_observation_id": pre,
        "expected_effect": expected_effect,
        "recovery_plan": rollback_plan,
        "receipt_checks": receipts,
    }))
}

pub(crate) fn detail(db: &Connection, intent: &str) -> Result<AdminResponse> {
    let mut detail = receipt_detail(db, intent)?;
    // Changes to other monitored units in the receipt window are collateral
    // evidence for an operator, with no assumption about causality.
    let concurrent = rows(db, "SELECT c.receipt_id,b.observation_id,o.observation_id,o.watch_id,o.state_hash
        FROM action_effect_checks c JOIN action_verification_plans p USING(intent_id)
        JOIN observations o ON o.host_id=p.host_id AND o.collector_type='systemd.unit_state'
        JOIN observations b ON b.observation_id=(SELECT MAX(prior.observation_id) FROM observations prior
            WHERE prior.host_id=o.host_id AND prior.watch_id=o.watch_id AND prior.spec_version=o.spec_version
              AND prior.session_id=o.session_id AND prior.observation_id<o.observation_id
              AND prior.observed_at<o.observed_at AND prior.status_json='\"ok\"')
        WHERE c.intent_id=?1 AND c.expected_state IS NOT NULL AND o.status_json='\"ok\"'
          AND o.observed_at>c.opened_at AND o.observed_at<=o.received_at AND o.received_at<c.deadline
          AND json_extract(o.sample_json,'$.unit')=json_extract(b.sample_json,'$.unit')
          AND ('systemd:' || json_extract(o.sample_json,'$.unit'))<>p.target_key
          AND json_extract(o.sample_json,'$.active_state')<>json_extract(b.sample_json,'$.active_state')
        ORDER BY c.receipt_id,o.observation_id LIMIT 20", [intent], |r| Ok(json!({
            "receipt_id":r.get::<_,i64>(0)?, "before":r.get::<_,i64>(1)?, "after":r.get::<_,i64>(2)?,
            "watch_id":r.get::<_,String>(3)?, "state_hash":r.get::<_,String>(4)?
        })))?;
    let reconciliations = rows(
        db,
        "SELECT receipt_cursor,evidence_ref,rationale,recorded_at FROM action_reconciliations
        WHERE intent_id=?1 ORDER BY receipt_cursor",
        [intent],
        |row| {
            Ok(json!({
                "receipt_id":row.get::<_,i64>(0)?, "evidence_ref":row.get::<_,String>(1)?,
                "rationale":row.get::<_,String>(2)?, "recorded_at":row.get::<_,String>(3)?
            }))
        },
    )?;
    detail["concurrent_service_changes"] = json!(concurrent);
    detail["collateral_coverage"] =
        json!("Up to 20 transitions on other monitored units. Causation unassessed.");
    detail["operator_reconciliations"] = json!(reconciliations);
    Ok(AdminResponse::ActionVerification { detail })
}

pub(crate) fn scoped_detail(
    db: &Connection,
    intent: &str,
    cap: &ScopedCapability,
) -> Result<InvestigationResponse> {
    let allowed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM action_intents i JOIN action_proposals p USING(proposal_id)
        JOIN agent_runs r ON r.run_id=p.run_id JOIN capability_tokens g ON r.token_hash=g.token_hash
        WHERE i.intent_id=?1 AND i.host_id IN (SELECT value FROM json_each(?2))
          AND (?3 IS NULL OR i.incident_id=?3)
          AND NOT EXISTS (SELECT value FROM json_each(g.capability_json,'$.allowed_collectors')
                          EXCEPT SELECT value FROM json_each(?4)))",
        params![
            intent,
            serde_json::to_string(&cap.allowed_hosts)?,
            cap.incident_id,
            serde_json::to_string(&cap.allowed_collectors)?
        ],
        |r| r.get(0),
    )?;
    if !allowed {
        return Err(ControlError::denied(
            "verification outside capability scope",
        ));
    }
    Ok(InvestigationResponse::ActionVerification {
        detail: receipt_detail(db, intent)?,
    })
}

pub(crate) fn register_legacy(db: &Connection, intent: &ActionIntentPayload) -> Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO action_verification_plans VALUES(?1,?2,?3,NULL)",
        params![intent.intent_id, intent.host_id, target(&intent.verb)],
    )?;
    Ok(())
}

/// Only the administrative interface can attest recovery using independent evidence.
/// A later receipt invalidates this attestation for the purpose of retry admission.
pub(crate) fn reconcile(
    db: &Connection,
    intent: &str,
    expected: Option<i64>,
    evidence: &str,
    rationale: &str,
    now: DateTime<Utc>,
) -> Result<AdminResponse> {
    crate::investigation::require_text(evidence, "evidence_ref", 512)?;
    crate::investigation::require_text(rationale, "rationale", 2048)?;
    let (payload,status,last):(ActionIntentPayload,ActionIntentStatus,Option<i64>)=db.query_row(
        "SELECT payload_json,status_json,(SELECT MAX(receipt_id) FROM action_receipts WHERE intent_id=i.intent_id)
         FROM action_intents i WHERE i.intent_id=?1",[intent],|r| Ok((crate::ledger::json_column(r,0)?,crate::ledger::json_column(r,1)?,r.get(2)?)))
        .optional()?.ok_or_else(||ControlError::missing("action intent not found"))?;
    if expected != last
        || !matches!(
            status,
            ActionIntentStatus::Authorized
                | ActionIntentStatus::Executed
                | ActionIntentStatus::VerificationFailed
                | ActionIntentStatus::RolledBack
        )
        || (last.is_none() && payload.expires_at > now)
    {
        return Err(ControlError::denied(
            "latest receipt or expired unreceipted authorization required",
        ));
    }
    let cursor = last.unwrap_or(0);
    let inserted = db.execute(
        "INSERT INTO action_reconciliations VALUES(?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING",
        params![intent, cursor, evidence, rationale, stamp(now)],
    )?;
    if inserted == 1 {
        audit(
            db,
            defsec_protocol::audit::AuditEventType::ActionOutcomeReconciled,
            "operator",
            &uuid(),
            json!({"intent_id":intent,"receipt_id":last,"evidence_ref":evidence,"rationale":rationale}),
        )?;
    } else {
        let same: bool = db.query_row(
            "SELECT evidence_ref=?3 AND rationale=?4 FROM action_reconciliations
            WHERE intent_id=?1 AND receipt_cursor=?2",
            params![intent, cursor, evidence, rationale],
            |r| r.get(0),
        )?;
        if !same {
            return Err(ControlError::invalid(
                "the reviewed result already has another reconciliation",
            ));
        }
    }
    detail(db, intent)
}
