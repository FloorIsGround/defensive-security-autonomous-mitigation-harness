//! Pure expectation rule evaluation for normalized set observations.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use defsec_protocol::{
    rules::{ExpectationRuleSpec, MatchClause, RuleEffect, RuleValue},
    watch::{CollectorType, TriggerPredicate},
};
use serde_json::{Value, json};

pub use defsec_protocol::rules::ActiveRule;

use crate::{
    predicate::{PredicateOutcome, extract_keyed_set},
    rule_gate::rule_field_registry,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleEvaluation {
    pub outcome: PredicateOutcome,
    pub suppressed: BTreeMap<String, Vec<String>>,
    pub missing_required: Vec<String>,
    pub matched_rule_ids: Vec<String>,
}

pub fn apply_expectation_rules(
    predicate: &TriggerPredicate,
    collector: CollectorType,
    raw: PredicateOutcome,
    current: Option<&Value>,
    reference: Option<&Value>,
    rules: &[ActiveRule],
) -> RuleEvaluation {
    let mut result = RuleEvaluation {
        outcome: raw,
        suppressed: BTreeMap::new(),
        missing_required: Vec::new(),
        matched_rule_ids: Vec::new(),
    };
    if rules.is_empty()
        || !matches!(
            result.outcome,
            PredicateOutcome::Triggered { .. } | PredicateOutcome::NotTriggered
        )
    {
        return result;
    }
    let Some((set_field, identity_key)) = rule_set(predicate, collector) else {
        return result;
    };
    let Some(current) =
        current.and_then(|sample| extract_keyed_set(sample, set_field, identity_key))
    else {
        return result;
    };
    let reference = match reference {
        Some(sample) => {
            let Some(items) = extract_keyed_set(sample, set_field, identity_key) else {
                return result;
            };
            items
        }
        None => BTreeMap::new(),
    };

    let [mut added, mut removed, mut modified]: [Vec<String>; 3] = match &result.outcome {
        PredicateOutcome::Triggered { details, .. } => {
            let parse = |name| serde_json::from_value(details[name].clone());
            let (Ok(added), Ok(removed), Ok(modified)) =
                (parse("added"), parse("removed"), parse("modified"))
            else {
                return result;
            };
            [added, removed, modified]
        }
        PredicateOutcome::NotTriggered => Default::default(),
        _ => return result,
    };
    let original_removed = removed.clone();
    let mut sorted = rules.iter().collect::<Vec<_>>();
    sorted.sort_unstable_by(|a, b| a.rule_id.cmp(&b.rule_id));

    let mut suppressed_count = 0;
    for rule in sorted {
        let matching_current: BTreeSet<_> = current
            .iter()
            .filter(|(_, item)| item_matches(&rule.spec, item))
            .map(|(key, _)| key)
            .collect();
        let matches_reference = |key: &String| {
            reference
                .get(key)
                .is_some_and(|item| item_matches(&rule.spec, item))
        };
        if !matching_current.is_empty()
            || (rule.spec.effect == RuleEffect::AllowOptional
                && original_removed.iter().any(matches_reference))
        {
            result.matched_rule_ids.push(rule.rule_id.clone());
        }
        if rule.spec.effect == RuleEffect::RequirePresent {
            if matching_current.is_empty() {
                result.missing_required.push(rule.rule_id.clone());
            }
            continue;
        }

        let mut suppressed = BTreeSet::new();
        let mut retain = |keys: &mut Vec<String>, matches: &dyn Fn(&String) -> bool| {
            keys.retain(|key| {
                if matches(key) {
                    suppressed_count += 1;
                    suppressed.insert(key.clone());
                    false
                } else {
                    true
                }
            });
        };
        if rule.spec.effect == RuleEffect::AllowOptional {
            retain(&mut added, &|key| matching_current.contains(key));
            retain(&mut removed, &matches_reference);
        }
        retain(&mut modified, &|key| matching_current.contains(key));
        if !suppressed.is_empty() {
            result.suppressed.insert(
                rule.rule_id.clone(),
                suppressed.into_iter().take(50).collect(),
            );
        }
    }

    if added.is_empty()
        && removed.is_empty()
        && modified.is_empty()
        && result.missing_required.is_empty()
    {
        result.outcome = PredicateOutcome::NotTriggered;
        return result;
    }
    added.sort_unstable();
    removed.sort_unstable();
    modified.sort_unstable();
    let mut reason = format!(
        "set '{set_field}' diff: +{} -{} ~{}",
        added.len(),
        removed.len(),
        modified.len()
    );
    let mut details = json!({"added": added, "removed": removed, "modified": modified});
    if suppressed_count != 0 {
        reason.push_str(&format!(" ({suppressed_count} suppressed by rules)"));
        details["suppressed_by_rules"] = json!(result.suppressed);
    }
    if !result.missing_required.is_empty() {
        reason.push_str(&format!(
            " missing required: {}",
            result.missing_required.len()
        ));
        details["missing_required"] = json!(result.missing_required);
    }
    result.outcome = PredicateOutcome::Triggered { reason, details };
    result
}

/// Keys of matching items in a current sample, used to summarize a backtest.
pub fn matching_rule_keys(
    predicate: &TriggerPredicate,
    spec: &ExpectationRuleSpec,
    sample: &Value,
) -> Vec<String> {
    rule_set(predicate, spec.scope.collector)
        .and_then(|(field, identity)| extract_keyed_set(sample, field, identity))
        .into_iter()
        .flatten()
        .filter(|(_, item)| item_matches(spec, item))
        .map(|(key, _)| key)
        .collect()
}

fn rule_set(
    predicate: &TriggerPredicate,
    collector: CollectorType,
) -> Option<(&'static str, &'static str)> {
    let fields = rule_field_registry(collector)?;
    match predicate {
        TriggerPredicate::SetDiff {
            set_field,
            identity_key,
            ..
        } if set_field == fields.set_field && identity_key == fields.identity_key => {
            Some((fields.set_field, fields.identity_key))
        }
        _ => None,
    }
}

fn item_matches(spec: &ExpectationRuleSpec, item: &Value) -> bool {
    spec.matches.iter().all(|clause| {
        let scope = match clause.field() {
            "bind_scope" => item.get("local_addr").and_then(address).map(bind_scope),
            "remote_scope" => item.get("remote_addr").and_then(address).map(remote_scope),
            field => {
                return item
                    .get(field)
                    .is_some_and(|sample| clause_matches(clause, sample));
            }
        };
        scope.is_some_and(|value| clause_matches(clause, &Value::from(value)))
    })
}

pub(crate) fn clause_matches(clause: &MatchClause, sample: &Value) -> bool {
    let equals = |value: &RuleValue| match value {
        RuleValue::Int(value) => sample.as_i64() == Some(*value),
        RuleValue::Bool(value) => sample.as_bool() == Some(*value),
        RuleValue::Text(value) => sample.as_str() == Some(value),
    };
    match clause {
        MatchClause::Eq { value, .. } => equals(value),
        MatchClause::In { values, .. } => values.iter().any(equals),
        MatchClause::Range { min, max, .. } => {
            sample.as_i64().is_some_and(|n| (*min..=*max).contains(&n))
        }
        MatchClause::Prefix { value, .. } => {
            sample.as_str().is_some_and(|text| text.starts_with(value))
        }
    }
}

fn address(value: &Value) -> Option<IpAddr> {
    value.as_str()?.parse().ok()
}

fn bind_scope(addr: IpAddr) -> &'static str {
    if addr.is_loopback() {
        "loopback"
    } else if addr.is_unspecified() {
        "any"
    } else {
        "specific"
    }
}

fn remote_scope(addr: IpAddr) -> &'static str {
    if addr.is_loopback() {
        return "loopback";
    }
    let private = match addr {
        IpAddr::V4(addr) => {
            let [first, second, ..] = addr.octets();
            addr.is_private() || (first == 100 && (64..=127).contains(&second))
        }
        IpAddr::V6(addr) => addr.is_unique_local() || addr.is_unicast_link_local(),
    };
    if private { "private" } else { "public" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predicate::evaluate_predicate;
    use defsec_protocol::{observation::ObservationStatus, watch::CompareTarget};

    fn predicate() -> TriggerPredicate {
        TriggerPredicate::SetDiff {
            compare_against: CompareTarget::LastObserved,
            set_field: "sockets".into(),
            identity_key: "socket_key".into(),
            ignore_fields: vec![],
        }
    }

    fn rule(id: &str, effect: RuleEffect, clauses: Value) -> ActiveRule {
        ActiveRule {
            rule_id: id.into(),
            spec: serde_json::from_value(json!({
                "scope": {"host_id":"edge","collector":"sockets.listening"},
                "matches":clauses, "effect":effect, "rationale":"test rule"
            }))
            .unwrap(),
        }
    }

    fn sample(items: &[(&str, &str, u16)]) -> Value {
        let sockets: Vec<_> = items
            .iter()
            .map(|(key, unit, port)| {
                json!({
                    "socket_key":key,"systemd_unit":unit,"local_port":port,"local_addr":"127.0.0.5"
                })
            })
            .collect();
        json!({"sockets":sockets})
    }

    fn apply(current: &Value, reference: &Value, rules: &[ActiveRule]) -> RuleEvaluation {
        let predicate = predicate();
        let raw = evaluate_predicate(
            &predicate,
            ObservationStatus::Ok,
            Some(current),
            Some(reference),
            None,
            None,
            0,
            0,
        );
        apply_expectation_rules(
            &predicate,
            CollectorType::SocketsListening,
            raw,
            Some(current),
            Some(reference),
            rules,
        )
    }

    #[test]
    fn allow_optional_uses_current_for_add_and_modify_and_reference_for_remove() {
        let reference = sample(&[
            ("removed", "allowed", 4000),
            ("changed", "different", 4000),
            ("now-other", "allowed", 4000),
        ]);
        let current = sample(&[
            ("added", "allowed", 4001),
            ("changed", "allowed", 4001),
            ("now-other", "different", 4001),
        ]);
        let rule = rule(
            "allow",
            RuleEffect::AllowOptional,
            json!([
                {"op":"eq","field":"systemd_unit","value":"allowed"},
                {"op":"in","field":"bind_scope","values":["loopback"]},
                {"op":"range","field":"local_port","min":4000,"max":4001}
            ]),
        );
        let evaluation = apply(&current, &reference, &[rule]);
        assert_eq!(evaluation.matched_rule_ids, ["allow"]);
        assert_eq!(
            evaluation.suppressed["allow"],
            ["added", "changed", "removed"]
        );
        assert_eq!(
            evaluation.outcome,
            PredicateOutcome::Triggered {
                reason: "set 'sockets' diff: +0 -0 ~1 (3 suppressed by rules)".into(),
                details: json!({"added":[],"removed":[],"modified":["now-other"],"suppressed_by_rules":{"allow":["added","changed","removed"]}}),
            }
        );
    }

    #[test]
    fn ignore_modified_keeps_additions_and_removals() {
        let reference = sample(&[("removed", "unit", 1), ("modified", "unit", 2)]);
        let current = sample(&[("added", "unit", 3), ("modified", "unit", 4)]);
        let eval = apply(
            &current,
            &reference,
            &[rule(
                "ignore",
                RuleEffect::IgnoreModified,
                json!([{"op":"prefix","field":"systemd_unit","value":"un"}]),
            )],
        );
        let PredicateOutcome::Triggered { details, .. } = eval.outcome else {
            panic!()
        };
        assert_eq!(
            details,
            json!({"added":["added"],"removed":["removed"],"modified":[],"suppressed_by_rules":{"ignore":["modified"]}})
        );
    }

    #[test]
    fn require_present_triggers_an_empty_diff_and_reports_sorted_ids() {
        let required = rule(
            "b",
            RuleEffect::RequirePresent,
            json!([{"op":"eq","field":"local_port","value":22}]),
        );
        let mut earlier = required.clone();
        earlier.rule_id = "a".into();
        let absent = sample(&[]);
        let eval = apply(&absent, &absent, &[required.clone(), earlier.clone()]);
        assert_eq!(eval, apply(&absent, &absent, &[earlier, required.clone()]));
        assert_eq!(eval.missing_required, ["a", "b"]);
        assert_eq!(
            eval.outcome,
            PredicateOutcome::Triggered {
                reason: "set 'sockets' diff: +0 -0 ~0 missing required: 2".into(),
                details: json!({"added":[],"removed":[],"modified":[],"missing_required":["a","b"]}),
            }
        );
        let present = sample(&[("ssh", "ssh", 22)]);
        let eval = apply(&present, &present, &[required]);
        assert_eq!(eval.outcome, PredicateOutcome::NotTriggered);
        assert_eq!(eval.matched_rule_ids, ["b"]);
    }

    #[test]
    fn suppression_is_deterministic_capped_and_can_clear_every_change() {
        let sockets = (0..60)
            .rev()
            .map(|i| json!({"socket_key":format!("key-{i:02}"),"uid":1}))
            .collect::<Vec<_>>();
        let current = json!({"sockets": sockets});
        let reference = sample(&[]);
        let mut rules = vec![
            rule(
                "z",
                RuleEffect::AllowOptional,
                json!([{"op":"eq","field":"uid","value":1}]),
            ),
            rule(
                "a",
                RuleEffect::AllowOptional,
                json!([{"op":"eq","field":"uid","value":1}]),
            ),
        ];
        let eval = apply(&current, &reference, &rules);
        rules.reverse();
        assert_eq!(eval, apply(&current, &reference, &rules));
        assert_eq!(eval.outcome, PredicateOutcome::NotTriggered);
        assert_eq!(eval.suppressed.len(), 1);
        assert_eq!(
            eval.suppressed["a"],
            (0..50).map(|i| format!("key-{i:02}")).collect::<Vec<_>>()
        );
        assert_eq!(eval.matched_rule_ids, ["a", "z"]);
    }

    #[test]
    fn scope_is_derived_and_missing_address_does_not_match() {
        for (addr, expected) in [
            ("127.0.0.5", "loopback"),
            ("::1", "loopback"),
            ("0.0.0.0", "any"),
            ("::", "any"),
            ("192.168.1.5", "specific"),
        ] {
            let spec = rule(
                "bind",
                RuleEffect::RequirePresent,
                json!([{"op":"eq","field":"bind_scope","value":expected}]),
            )
            .spec;
            assert!(item_matches(
                &spec,
                &json!({"local_addr":addr, "bind_scope":"spoofed"})
            ));
            assert!(!item_matches(&spec, &json!({"bind_scope":expected})));
        }
        for (addr, expected) in [
            ("::1", "loopback"),
            ("127.9.1.3", "loopback"),
            ("10.1.2.3", "private"),
            ("172.31.0.1", "private"),
            ("192.168.3.5", "private"),
            ("100.64.0.0", "private"),
            ("100.127.255.255", "private"),
            ("fc00::1", "private"),
            ("fe80::2", "private"),
            ("100.128.0.0", "public"),
            ("203.0.113.1", "public"),
            ("2001:db8::4", "public"),
        ] {
            let spec = rule(
                "remote",
                RuleEffect::RequirePresent,
                json!([{"op":"eq","field":"remote_scope","value":expected}]),
            )
            .spec;
            assert!(item_matches(&spec, &json!({"remote_addr":addr})), "{addr}");
        }
    }

    #[test]
    fn ignores_other_predicates_and_invalid_samples() {
        let current = sample(&[]);
        let rules = [rule(
            "required",
            RuleEffect::RequirePresent,
            json!([{"op":"eq","field":"local_port","value":22}]),
        )];
        for (predicate, raw, sample) in [
            (
                TriggerPredicate::CollectorStaleOrError {
                    max_stale_seconds: 60,
                    consecutive_errors: 2,
                },
                PredicateOutcome::Triggered {
                    reason: "stale".into(),
                    details: json!({}),
                },
                Some(&current),
            ),
            (
                predicate(),
                PredicateOutcome::BaselineUnavailable,
                Some(&current),
            ),
            (
                predicate(),
                PredicateOutcome::SampleInvalid {
                    reason: "timeout".into(),
                },
                None,
            ),
            (predicate(), PredicateOutcome::NotTriggered, None),
            (
                predicate(),
                PredicateOutcome::NotTriggered,
                Some(&Value::Null),
            ),
        ] {
            let eval = apply_expectation_rules(
                &predicate,
                CollectorType::SocketsListening,
                raw.clone(),
                sample,
                None,
                &rules,
            );
            assert_eq!(eval.outcome, raw);
            assert!(eval.matched_rule_ids.is_empty());
            assert!(eval.missing_required.is_empty());
        }
    }

    #[test]
    fn ignore_fields_preserves_identity_and_compares_other_fields() {
        let mut predicate = predicate();
        let TriggerPredicate::SetDiff { ignore_fields, .. } = &mut predicate else {
            panic!()
        };
        *ignore_fields = vec!["pid".into(), "inode".into(), "pid_start_time_ticks".into()];
        let before = json!({"sockets":[{"socket_key":"x","comm":"old","pid":11,"inode":12}]});
        let restarted = json!({"sockets":[{"socket_key":"x","comm":"old","pid":17,"pid_start_time_ticks":412}]});
        let evaluate = |current| {
            evaluate_predicate(
                &predicate,
                ObservationStatus::Ok,
                Some(current),
                Some(&before),
                None,
                None,
                0,
                0,
            )
        };
        assert_eq!(evaluate(&restarted), PredicateOutcome::NotTriggered);
        let changed = json!({"sockets":[{"socket_key":"x","comm":"new","pid":17}]});
        assert!(
            matches!(evaluate(&changed), PredicateOutcome::Triggered { details, .. } if details["modified"] == json!(["x"]))
        );
    }
}
