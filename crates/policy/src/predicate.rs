//! Deterministic predicate evaluation for Watch DSL triggers, including
//! edge-side sustained sample counting and three-state baseline comparisons.

use std::collections::BTreeMap;

use defsec_protocol::canonical::{sha256_hex, value_to_canonical_json};
use defsec_protocol::observation::ObservationStatus;
use defsec_protocol::watch::{CompareTarget, ThresholdOp, TriggerPredicate};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PredicateOutcome {
    Triggered { reason: String, details: Value },
    NotTriggered,
    /// Explicitly returned when a predicate requires `accepted_baseline` and
    /// none has been promoted yet (never silently treated as healthy).
    BaselineUnavailable,
    /// Explicitly returned when the incoming sample is non-valid or lacks
    /// required structured fields.
    SampleInvalid { reason: String },
}

/// Edge-side deterministic counter state for `threshold_sustained` predicates.
/// Reset explicitly on spec change, sample gap, or non-valid observation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SustainedCounterState {
    pub spec_version: u32,
    pub consecutive_matches: u32,
    pub active: bool,
}

impl SustainedCounterState {
    pub fn reset(&mut self, spec_version: u32) {
        self.spec_version = spec_version;
        self.consecutive_matches = 0;
        self.active = false;
    }

    /// Advance counter with one actual completed sample.
    /// Returns `true` if `active` transitioned (false->true or true->false).
    #[allow(clippy::too_many_arguments)]
    pub fn record_sample(
        &mut self,
        spec_version: u32,
        status: ObservationStatus,
        sample_value: Option<&Value>,
        field: &str,
        op: ThresholdOp,
        threshold: i64,
        required_consecutive: u32,
    ) -> bool {
        let was_active = self.active;
        if self.spec_version != spec_version {
            self.reset(spec_version);
        }
        if !status.is_valid_sample() {
            self.reset(spec_version);
            return was_active != self.active;
        }
        let matched = sample_value
            .and_then(|v| lookup_field(v, field))
            .and_then(value_as_i64)
            .map(|n| compare_threshold(n, op, threshold))
            .unwrap_or(false);

        if matched {
            self.consecutive_matches = self.consecutive_matches.saturating_add(1);
            if self.consecutive_matches >= required_consecutive {
                self.active = true;
            }
        } else {
            self.consecutive_matches = 0;
            self.active = false;
        }
        was_active != self.active
    }
}

/// Only complete snapshots provide evidence that an omitted key is absent.
pub(crate) fn snapshot_has_absence_evidence(status: ObservationStatus, sample: &Value) -> bool {
    status == ObservationStatus::Ok && !snapshot_is_truncated(sample)
}

fn snapshot_is_truncated(sample: &Value) -> bool {
    sample.get("truncated").and_then(Value::as_bool) == Some(true)
}

const OMITTED_COUNT_FIELDS: [&str; 2] = ["omitted_flows", "omitted_packages"];

pub(crate) fn append_truncation_reason(reason: &mut String, counts: &Value) {
    let known: Vec<_> = OMITTED_COUNT_FIELDS
        .into_iter()
        .filter_map(|field| counts[field].as_u64().map(|count| format!("{field}={count}")))
        .collect();
    reason.push_str(" truncation_began (");
    if known.is_empty() {
        reason.push_str("omitted count unknown");
    } else {
        reason.push_str(&known.join(", "));
    }
    reason.push(')');
}

/// Evaluate a watch trigger predicate against `current`, `last_observed`, and
/// `accepted_baseline`.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_predicate(
    predicate: &TriggerPredicate,
    status: ObservationStatus,
    current: Option<&Value>,
    last_observed: Option<&Value>,
    accepted_baseline: Option<&Value>,
    sustained_count: Option<u32>,
    consecutive_errors: u32,
    stale_seconds: u64,
) -> PredicateOutcome {
    match predicate {
        TriggerPredicate::CollectorStaleOrError {
            max_stale_seconds,
            consecutive_errors: err_threshold,
        } => {
            if !status.is_valid_sample() && consecutive_errors >= *err_threshold {
                return PredicateOutcome::Triggered {
                    reason: format!(
                        "collector error status {:?} persisted for {} consecutive runs",
                        status, consecutive_errors
                    ),
                    details: serde_json::json!({
                        "status": status,
                        "consecutive_errors": consecutive_errors
                    }),
                };
            }
            if stale_seconds >= *max_stale_seconds {
                return PredicateOutcome::Triggered {
                    reason: format!(
                        "collector stale for {}s (threshold {}s)",
                        stale_seconds, max_stale_seconds
                    ),
                    details: serde_json::json!({ "stale_seconds": stale_seconds }),
                };
            }
            PredicateOutcome::NotTriggered
        }
        TriggerPredicate::FieldChanged {
            compare_against,
            fields,
        } => {
            if !status.is_valid_sample() {
                return PredicateOutcome::SampleInvalid {
                    reason: format!("observation status {:?} is not a valid sample", status),
                };
            }
            let Some(cur) = current else {
                return PredicateOutcome::SampleInvalid {
                    reason: "missing observation data".into(),
                };
            };
            let reference = match compare_against {
                CompareTarget::LastObserved => match last_observed {
                    Some(prev) => prev,
                    None => return PredicateOutcome::NotTriggered, // first observation establishes last_observed
                },
                CompareTarget::AcceptedBaseline => match accepted_baseline {
                    Some(base) => base,
                    None => return PredicateOutcome::BaselineUnavailable,
                },
            };

            let mut changed = serde_json::Map::new();
            for field in fields {
                let prev_val = lookup_field(reference, field);
                let cur_val = lookup_field(cur, field);
                if prev_val != cur_val {
                    changed.insert(
                        field.clone(),
                        serde_json::json!({
                            "before": bounded_diff_value(prev_val),
                            "after": bounded_diff_value(cur_val),
                        }),
                    );
                }
            }

            if changed.is_empty() {
                PredicateOutcome::NotTriggered
            } else {
                let count = changed.len();
                let mut details = Value::Object(changed);
                let encoded = details.to_string();
                if encoded.len() > 64 * 1024 {
                    details = serde_json::json!({
                        "truncated": true,
                        "changed_fields": count,
                        "sha256": sha256_hex(encoded.as_bytes()),
                    });
                }
                PredicateOutcome::Triggered {
                    reason: format!("{count} watched field(s) changed"),
                    details,
                }
            }
        }
        TriggerPredicate::SetDiff {
            compare_against,
            set_field,
            identity_key,
            ignore_fields,
        } => {
            if !status.is_valid_sample() {
                return PredicateOutcome::SampleInvalid {
                    reason: format!("observation status {:?} is not a valid sample", status),
                };
            }
            let Some(cur) = current else {
                return PredicateOutcome::SampleInvalid {
                    reason: "missing observation data".into(),
                };
            };
            let reference = match compare_against {
                CompareTarget::LastObserved => match last_observed {
                    Some(prev) => prev,
                    None => return PredicateOutcome::NotTriggered,
                },
                CompareTarget::AcceptedBaseline => match accepted_baseline {
                    Some(base) => base,
                    None => return PredicateOutcome::BaselineUnavailable,
                },
            };

            let prev_map = extract_keyed_set(reference, set_field, identity_key);
            let cur_map = extract_keyed_set(cur, set_field, identity_key);
            let (Some(prev_map), Some(cur_map)) = (prev_map, cur_map) else {
                return PredicateOutcome::SampleInvalid {
                    reason: format!("set_field '{set_field}' is missing or not an array of objects"),
                };
            };

            let mut added = Vec::new();
            let mut removed = Vec::new();
            let mut modified = Vec::new();

            for (k, cur_item) in &cur_map {
                match prev_map.get(k) {
                    None => added.push(k.clone()),
                    Some(prev_item)
                        if comparable_item(prev_item, ignore_fields)
                            != comparable_item(cur_item, ignore_fields) =>
                    {
                        modified.push(k.clone());
                    }
                    Some(_) => {}
                }
            }
            if snapshot_has_absence_evidence(status, cur) {
                for k in prev_map.keys() {
                    if !cur_map.contains_key(k) {
                        removed.push(k.clone());
                    }
                }
            }

            // A baseline stays fixed across runs. Use the previous valid
            // sample as well to distinguish onset from continuing truncation.
            let truncation_began = snapshot_is_truncated(cur)
                && !snapshot_is_truncated(reference)
                && !last_observed.is_some_and(snapshot_is_truncated);
            if added.is_empty() && removed.is_empty() && modified.is_empty() && !truncation_began {
                PredicateOutcome::NotTriggered
            } else {
                let mut reason = format!(
                    "set '{set_field}' diff: +{} -{} ~{}",
                    added.len(),
                    removed.len(),
                    modified.len()
                );
                let mut details = serde_json::json!({
                    "added": added,
                    "removed": removed,
                    "modified": modified,
                });
                if truncation_began {
                    let counts = Value::Object(
                        OMITTED_COUNT_FIELDS
                            .into_iter()
                            .filter_map(|field| {
                                let count = cur.get(field)?.as_u64()?;
                                Some((field.into(), Value::from(count)))
                            })
                            .collect(),
                    );
                    append_truncation_reason(&mut reason, &counts);
                    details["truncation_began"] = counts;
                }
                PredicateOutcome::Triggered { reason, details }
            }
        }
        TriggerPredicate::ThresholdSustained {
            field,
            operator,
            threshold,
            consecutive_samples,
        } => {
            if !status.is_valid_sample() {
                return PredicateOutcome::SampleInvalid {
                    reason: format!("observation status {:?} resets sustained evaluation", status),
                };
            }
            let count = sustained_count.unwrap_or(0);
            if count >= *consecutive_samples {
                PredicateOutcome::Triggered {
                    reason: format!(
                        "field '{field}' met {:?} {threshold} for {count} consecutive valid samples",
                        operator
                    ),
                    details: serde_json::json!({
                        "field": field,
                        "consecutive_samples": count,
                        "threshold": threshold,
                    }),
                }
            } else {
                PredicateOutcome::NotTriggered
            }
        }
    }
}

// Full values stay with the evidence observations.
fn bounded_diff_value(value: Option<&Value>) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };
    let canonical = value_to_canonical_json(value).unwrap_or_else(|_| value.to_string());
    if canonical.len() <= 4096 && value.to_string().len() <= 4096 {
        return value.clone();
    }
    serde_json::json!({
        "truncated": true,
        "bytes": canonical.len(),
        "sha256": sha256_hex(canonical.as_bytes()),
        "preview": &canonical[..canonical.floor_char_boundary(256)],
    })
}

pub fn lookup_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = value;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn value_as_i64(val: &Value) -> Option<i64> {
    val.as_i64()
        .or_else(|| val.as_u64().and_then(|u| i64::try_from(u).ok()))
}

fn compare_threshold(n: i64, op: ThresholdOp, threshold: i64) -> bool {
    match op {
        ThresholdOp::Gt => n > threshold,
        ThresholdOp::Gte => n >= threshold,
        ThresholdOp::Lt => n < threshold,
        ThresholdOp::Lte => n <= threshold,
        ThresholdOp::Eq => n == threshold,
        ThresholdOp::Neq => n != threshold,
    }
}

pub(crate) fn extract_keyed_set<'a>(
    root: &'a Value,
    set_field: &str,
    identity_key: &str,
) -> Option<BTreeMap<String, &'a Value>> {
    let arr = lookup_field(root, set_field)?.as_array()?;
    let mut map = BTreeMap::new();
    for item in arr {
        let key_val = lookup_field(item, identity_key)?;
        let key = match key_val {
            Value::String(s) => s.clone(),
            other => value_to_canonical_json(other).ok()?,
        };
        map.insert(key, item);
    }
    Some(map)
}

fn comparable_item(item: &Value, ignore_fields: &[String]) -> Option<String> {
    if !ignore_fields.is_empty()
        && let Some(fields) = item.as_object()
    {
        let mut fields = fields.clone();
        for field in ignore_fields {
            fields.remove(field);
        }
        return value_to_canonical_json(&Value::Object(fields)).ok();
    }
    value_to_canonical_json(item).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sustained_counter_counts_identical_samples_and_resets_on_error_or_spec_change() {
        let mut st = SustainedCounterState::default();
        let sample = json!({ "count": 12 });

        // 1st valid sample -> count 1, not active
        assert!(!st.record_sample(1, ObservationStatus::Ok, Some(&sample), "count", ThresholdOp::Gte, 10, 3));
        assert_eq!(st.consecutive_matches, 1);
        assert!(!st.active);

        // 2nd valid sample -> count 2, not active
        assert!(!st.record_sample(1, ObservationStatus::Ok, Some(&sample), "count", ThresholdOp::Gte, 10, 3));
        assert_eq!(st.consecutive_matches, 2);

        // 3rd valid sample -> transitions active = true!
        assert!(st.record_sample(1, ObservationStatus::Ok, Some(&sample), "count", ThresholdOp::Gte, 10, 3));
        assert_eq!(st.consecutive_matches, 3);
        assert!(st.active);

        // Error sample resets counter and transitions active = false!
        assert!(st.record_sample(1, ObservationStatus::Timeout, None, "count", ThresholdOp::Gte, 10, 3));
        assert_eq!(st.consecutive_matches, 0);
        assert!(!st.active);

        // Spec change resets prior accumulated count before evaluating new sample.
        st.record_sample(1, ObservationStatus::Ok, Some(&sample), "count", ThresholdOp::Gte, 10, 3);
        st.record_sample(1, ObservationStatus::Ok, Some(&sample), "count", ThresholdOp::Gte, 10, 3);
        assert_eq!(st.consecutive_matches, 2);
        assert!(!st.record_sample(2, ObservationStatus::Ok, Some(&sample), "count", ThresholdOp::Gte, 10, 3));
        assert_eq!(st.spec_version, 2);
        assert_eq!(st.consecutive_matches, 1);
        assert!(!st.active);
    }

    #[test]
    fn missing_accepted_baseline_returns_explicit_unavailable() {
        let pred = TriggerPredicate::FieldChanged {
            compare_against: CompareTarget::AcceptedBaseline,
            fields: vec!["active_state".into()],
        };
        let cur = json!({ "active_state": "active" });
        let out = evaluate_predicate(&pred, ObservationStatus::Ok, Some(&cur), None, None, None, 0, 0);
        assert_eq!(out, PredicateOutcome::BaselineUnavailable);
    }

    #[test]
    fn incomplete_set_diff_keeps_additions_but_suppresses_removals() {
        let pred = TriggerPredicate::SetDiff {
            compare_against: CompareTarget::LastObserved,
            set_field: "packages".into(),
            identity_key: "package_key".into(),
            ignore_fields: vec![],
        };
        let previous = json!({"packages": [{"package_key": "z:all"}]});
        for (status, truncated) in [
            (ObservationStatus::Partial, false),
            (ObservationStatus::Ok, true),
        ] {
            let current = json!({"truncated": truncated, "packages": [{"package_key": "a:all"}]});
            let outcome = evaluate_predicate(
                &pred,
                status,
                Some(&current),
                Some(&previous),
                None,
                None,
                0,
                0,
            );
            assert!(
                matches!(outcome, PredicateOutcome::Triggered { details, .. }
                if details["added"] == json!(["a:all"]) && details["removed"] == json!([]))
            );
        }
    }

    #[test]
    fn set_diff_signals_truncation_onset_for_both_comparison_targets() {
        let complete = json!({"packages": [{"package_key": "a:all"}]});
        let mut truncated = complete.clone();
        truncated["truncated"] = json!(true);
        truncated["omitted_packages"] = json!(17);
        for compare_against in [CompareTarget::LastObserved, CompareTarget::AcceptedBaseline] {
            let pred = TriggerPredicate::SetDiff {
                compare_against,
                set_field: "packages".into(),
                identity_key: "package_key".into(),
                ignore_fields: vec![],
            };
            let evaluate = |status, current, last, baseline| {
                evaluate_predicate(
                    &pred,
                    status,
                    Some(current),
                    Some(last),
                    Some(baseline),
                    None,
                    0,
                    0,
                )
            };
            assert_eq!(
                evaluate(ObservationStatus::Partial, &truncated, &complete, &complete),
                PredicateOutcome::Triggered {
                    reason: "set 'packages' diff: +0 -0 ~0 truncation_began (omitted_packages=17)".into(),
                    details: json!({"added": [], "removed": [], "modified": [],
                        "truncation_began": {"omitted_packages": 17}}),
                }
            );
            assert_eq!(
                evaluate(ObservationStatus::Partial, &truncated, &truncated, &complete),
                PredicateOutcome::NotTriggered
            );
            assert_eq!(
                evaluate(ObservationStatus::Ok, &complete, &truncated, &complete),
                PredicateOutcome::NotTriggered
            );
            if compare_against == CompareTarget::AcceptedBaseline {
                assert_eq!(
                    evaluate(ObservationStatus::Partial, &truncated, &complete, &truncated),
                    PredicateOutcome::NotTriggered
                );
            }
        }
    }

    #[test]
    fn set_diff_detects_added_removed_and_modified_entries() {
        let pred = TriggerPredicate::SetDiff {
            compare_against: CompareTarget::AcceptedBaseline,
            set_field: "sockets".into(),
            identity_key: "socket_key".into(),
            ignore_fields: vec![],
        };
        let base = json!({
            "sockets": [
                { "socket_key": "tcp:0.0.0.0:22", "uid": 0 },
                { "socket_key": "tcp:127.0.0.1:5432", "uid": 100 }
            ]
        });
        let cur = json!({
            "sockets": [
                { "socket_key": "tcp:0.0.0.0:22", "uid": 0 },
                { "socket_key": "tcp:0.0.0.0:4444", "uid": 1000 }
            ]
        });
        let out = evaluate_predicate(
            &pred,
            ObservationStatus::Ok,
            Some(&cur),
            None,
            Some(&base),
            None,
            0,
            0,
        );
        match out {
            PredicateOutcome::Triggered { details, .. } => {
                assert_eq!(details["added"], json!(["tcp:0.0.0.0:4444"]));
                assert_eq!(details["removed"], json!(["tcp:127.0.0.1:5432"]));
            }
            other => panic!("expected Triggered, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod field_change_limits {
    use super::*;
    use serde_json::json;

    #[test]
    fn field_changes_bound_each_value_and_total_serialized_details() {
        let old = json!({"field": "界".repeat(1700), "small": 1});
        let new = json!({"field": "\u{0001}".repeat(900), "small": 2});
        let evaluate = |fields, before: &Value, after: &Value| {
            let predicate = TriggerPredicate::FieldChanged {
                compare_against: CompareTarget::LastObserved,
                fields,
            };
            let PredicateOutcome::Triggered { details, .. } = evaluate_predicate(
                &predicate,
                ObservationStatus::Ok,
                Some(after),
                Some(before),
                None,
                None,
                0,
                0,
            ) else {
                panic!("expected a field change");
            };
            details
        };
        let details = evaluate(vec!["field".into(), "small".into()], &old, &new);
        for (side, input) in [("before", &old["field"]), ("after", &new["field"])] {
            let canonical = value_to_canonical_json(input).unwrap();
            let truncated = &details["field"][side];
            assert_eq!(truncated["truncated"], true);
            assert_eq!(truncated["bytes"], canonical.len());
            assert_eq!(truncated["sha256"], sha256_hex(canonical.as_bytes()));
            assert!(truncated["preview"].as_str().unwrap().len() <= 256);
            assert!(truncated.to_string().len() <= 4096);
        }
        assert_eq!(details["small"], json!({"before":1,"after":2}));

        let many: serde_json::Map<String, Value> = (0..40)
            .map(|i| (format!("field_{i}"), json!("x".repeat(4000))))
            .collect();
        let details = evaluate(
            many.keys().cloned().collect(),
            &json!({}),
            &Value::Object(many),
        );
        assert_eq!(details["truncated"], true);
        assert_eq!(details["changed_fields"], 40);
        assert!(details.to_string().len() <= 64 * 1024);
    }
}
