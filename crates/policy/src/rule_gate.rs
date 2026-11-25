//! Collectors and constraints supported by the expectation rule gate.

use chrono::{DateTime, Duration, Utc};
use defsec_protocol::{
    rpc::PolicyDecision,
    rules::{ExpectationRuleSpec, MatchClause, RuleEffect, RuleValue},
    watch::CollectorType,
};
use serde_json::Value;

pub use defsec_protocol::rules::RuleOrigin;

use crate::{control_gate::DEFAULT_POLICY_VERSION, rules::clause_matches};

#[derive(Debug, Clone)]
pub struct RuleGateConfig {
    pub policy_version: u32,
    pub prior_run_proposals: usize,
    pub pending_host_proposals: usize,
}

impl Default for RuleGateConfig {
    fn default() -> Self {
        Self {
            policy_version: DEFAULT_POLICY_VERSION,
            prior_run_proposals: 0,
            pending_host_proposals: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldType {
    Int,
    Text,
}

#[derive(Debug, Clone, Copy)]
enum CollectorConstraints {
    Sockets,
    Connections,
    Packages,
}

pub struct CollectorRuleFields {
    pub set_field: &'static str,
    pub identity_key: &'static str,
    fields: &'static [(&'static str, FieldType)],
    constraints: CollectorConstraints,
}

use FieldType::{Int, Text};

// P11 entries become reachable when the corresponding CollectorType variants land.
const REGISTRY: &[(&str, CollectorRuleFields)] = &[
    (
        "sockets.listening",
        CollectorRuleFields {
            set_field: "sockets",
            identity_key: "socket_key",
            fields: &[
                ("protocol", Text),
                ("local_addr", Text),
                ("local_port", Int),
                ("uid", Int),
                ("comm", Text),
                ("systemd_unit", Text),
                ("bind_scope", Text),
            ],
            constraints: CollectorConstraints::Sockets,
        },
    ),
    (
        "connections.outbound",
        CollectorRuleFields {
            set_field: "flows",
            identity_key: "flow_key",
            fields: &[
                ("protocol", Text),
                ("remote_addr", Text),
                ("remote_port", Int),
                ("uid", Int),
                ("comm", Text),
                ("systemd_unit", Text),
                ("remote_scope", Text),
            ],
            constraints: CollectorConstraints::Connections,
        },
    ),
    (
        "packages.inventory",
        CollectorRuleFields {
            set_field: "packages",
            identity_key: "package_key",
            fields: &[("name", Text), ("arch", Text)],
            constraints: CollectorConstraints::Packages,
        },
    ),
];

pub fn rule_field_registry(collector: CollectorType) -> Option<&'static CollectorRuleFields> {
    registry_entry(collector.as_str())
}

fn registry_entry(name: &str) -> Option<&'static CollectorRuleFields> {
    REGISTRY
        .iter()
        .find_map(|(id, entry)| (*id == name).then_some(entry))
}

pub fn validate_rule(
    spec: &ExpectationRuleSpec,
    origin: RuleOrigin,
    now: DateTime<Utc>,
    cfg: &RuleGateConfig,
) -> PolicyDecision {
    validate_with_registry(
        spec,
        origin,
        now,
        cfg,
        rule_field_registry(spec.scope.collector),
    )
}

fn validate_with_registry(
    spec: &ExpectationRuleSpec,
    origin: RuleOrigin,
    now: DateTime<Utc>,
    cfg: &RuleGateConfig,
    entry: Option<&CollectorRuleFields>,
) -> PolicyDecision {
    let deny = |id: &str, reason: &str| PolicyDecision {
        allowed: false,
        rule_id: format!("rule-gate/{id}"),
        reason: reason.into(),
        policy_version: cfg.policy_version,
    };

    if !(1..=8).contains(&spec.matches.len())
        || spec.rationale.is_empty()
        || spec.rationale.len() > 1024
        || !spec.matches.iter().all(valid_clause)
    {
        return deny("shape", "rule clauses or rationale exceed schema bounds");
    }
    let Some(entry) = entry else {
        return deny("fields", "collector does not support expectation rules");
    };
    let clauses = &spec.matches;
    if clauses.iter().any(|clause| {
        !entry
            .fields
            .iter()
            .any(|(field, kind)| *field == clause.field() && well_typed(clause, *kind))
    }) {
        return deny(
            "fields",
            "match field or value type is unsupported by this collector",
        );
    }

    if spec.effect != RuleEffect::RequirePresent
        && matches!(
            entry.constraints,
            CollectorConstraints::Sockets | CollectorConstraints::Connections
        )
        && !clauses.iter().any(|clause| {
            matches!(clause.field(), "systemd_unit" | "comm" | "uid")
                && matches!(clause, MatchClause::Eq { .. } | MatchClause::In { .. })
        })
    {
        return deny(
            "identity-anchor",
            "rule must constrain systemd_unit, comm, or uid with eq or in",
        );
    }

    if spec.effect == RuleEffect::AllowOptional {
        match entry.constraints {
            CollectorConstraints::Sockets => {
                let allows_scope = |value| allows_value(clauses, "bind_scope", value);
                let loopback_only =
                    allows_scope("loopback") && !allows_scope("any") && !allows_scope("specific");
                if !clauses.iter().any(|clause| {
                    clause.field() == "local_port"
                        && match clause {
                            MatchClause::Eq { .. } | MatchClause::In { .. } => true,
                            MatchClause::Range { min, max, .. } => {
                                max.saturating_sub(*min) <= 1024
                                    || (loopback_only && *min >= 1024 && *max <= 65535)
                            }
                            MatchClause::Prefix { .. } => false,
                        }
                }) {
                    return deny(
                        "port-bounds",
                        "socket rule must constrain local_port within the allowed bounds",
                    );
                }
                if allows_scope("any")
                    && !(clauses.iter().any(|clause| {
                        clause.field() == "systemd_unit" && matches!(clause, MatchClause::Eq { .. })
                    }) && clauses.iter().any(|clause| {
                        clause.field() == "local_port"
                            && match clause {
                                MatchClause::Eq { .. } => true,
                                MatchClause::In { values, .. } => values.len() <= 8,
                                _ => false,
                            }
                    }))
                {
                    return deny(
                        "wildcard-bind",
                        "wildcard bind requires systemd_unit eq and at most 8 explicit ports",
                    );
                }
            }
            CollectorConstraints::Connections => {
                if allows_value(clauses, "remote_scope", "public")
                    && !clauses.iter().any(|clause| match clause {
                        MatchClause::Prefix { field, value } => {
                            field == "remote_addr" && !value.is_empty()
                        }
                        other => matches!(other.field(), "remote_addr" | "remote_port"),
                    })
                {
                    return deny(
                        "public-remote",
                        "public connections require a remote_addr or remote_port constraint",
                    );
                }
            }
            CollectorConstraints::Packages => {
                if !clauses.iter().any(|clause| {
                    clause.field() == "name"
                        && match clause {
                            MatchClause::Eq { .. } | MatchClause::In { .. } => true,
                            MatchClause::Prefix { value, .. } => value.chars().count() >= 3,
                            MatchClause::Range { .. } => false,
                        }
                }) {
                    return deny(
                        "package-name",
                        "package rule requires a name eq, in, or prefix of at least 3 characters",
                    );
                }
            }
        }
    }

    if origin == RuleOrigin::Investigator {
        if spec
            .expires_at
            .is_none_or(|expiry| expiry.signed_duration_since(now) > Duration::days(30))
        {
            return deny(
                "investigator-expiry",
                "investigator rule must expire within 30 days",
            );
        }
        if cfg.prior_run_proposals >= 3 {
            return deny("run-quota", "run already proposed 3 expectation rules");
        }
        if cfg.pending_host_proposals >= 20 {
            return deny(
                "host-quota",
                "host already has 20 pending expectation rules",
            );
        }
    }
    if spec.expires_at.is_some_and(|expiry| expiry <= now) {
        return deny("expired", "rule expiry must be in the future");
    }
    PolicyDecision {
        allowed: true,
        rule_id: "rule-gate/accepted".into(),
        reason: "expectation rule satisfies policy".into(),
        policy_version: cfg.policy_version,
    }
}

fn valid_clause(clause: &MatchClause) -> bool {
    fn bounded(value: &RuleValue) -> bool {
        !matches!(value, RuleValue::Text(text) if text.len() > 256)
    }
    match clause {
        MatchClause::Eq { value, .. } => bounded(value),
        MatchClause::In { values, .. } => {
            (1..=32).contains(&values.len()) && values.iter().all(bounded)
        }
        MatchClause::Range { min, max, .. } => min <= max,
        MatchClause::Prefix { value, .. } => value.len() <= 256,
    }
}

fn well_typed(clause: &MatchClause, kind: FieldType) -> bool {
    let matches_type = |value: &RuleValue| {
        matches!(
            (kind, value),
            (Int, RuleValue::Int(_)) | (Text, RuleValue::Text(_))
        )
    };
    match clause {
        MatchClause::Eq { value, .. } => matches_type(value),
        MatchClause::In { values, .. } => values.iter().all(matches_type),
        MatchClause::Range { .. } => kind == Int,
        MatchClause::Prefix { .. } => kind == Text,
    }
}

fn allows_value(clauses: &[MatchClause], field: &str, value: &str) -> bool {
    let value = Value::from(value);
    clauses
        .iter()
        .filter(|clause| clause.field() == field)
        .all(|clause| clause_matches(clause, &value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use defsec_protocol::rules::RuleScope;

    fn rule(effect: RuleEffect, clauses: Value) -> ExpectationRuleSpec {
        ExpectationRuleSpec {
            scope: RuleScope {
                host_id: "edge".into(),
                collector: CollectorType::SocketsListening,
                watch_id: None,
            },
            matches: serde_json::from_value(clauses).unwrap(),
            effect,
            rationale: "expected listener".into(),
            expires_at: None,
        }
    }

    fn check(spec: &ExpectationRuleSpec, expected: &str) {
        let decision = validate_rule(
            spec,
            RuleOrigin::Operator,
            Utc::now(),
            &RuleGateConfig::default(),
        );
        assert_eq!(
            decision.rule_id,
            format!("rule-gate/{expected}"),
            "{decision:?}"
        );
        assert_eq!(decision.allowed, expected == "accepted");
    }

    use serde_json::json;

    #[test]
    fn shape_bounds_have_inclusive_positive_controls() {
        let base = rule(
            RuleEffect::RequirePresent,
            json!([{"op":"eq","field":"comm","value":"a"}]),
        );
        check(&base, "accepted");
        for size in [0, 8, 9] {
            let mut spec = base.clone();
            spec.matches = vec![base.matches[0].clone(); size];
            check(&spec, if size == 8 { "accepted" } else { "shape" });
        }

        for size in [0, 32, 33] {
            let spec = rule(
                RuleEffect::RequirePresent,
                json!([{"op":"in","field":"uid","values":vec![1; size]}]),
            );
            check(&spec, if size == 32 { "accepted" } else { "shape" });
        }
        for min in [1, 2] {
            let spec = rule(
                RuleEffect::RequirePresent,
                json!([{"op":"range","field":"uid","min":min,"max":1}]),
            );
            check(&spec, if min == 1 { "accepted" } else { "shape" });
        }
        for size in [128, 129] {
            for op in ["eq", "prefix"] {
                let spec = rule(
                    RuleEffect::RequirePresent,
                    json!([{"op":op,"field":"comm","value":"é".repeat(size)}]),
                );
                check(&spec, if size == 128 { "accepted" } else { "shape" });
            }
            let spec = rule(
                RuleEffect::RequirePresent,
                json!([{"op":"in","field":"comm","values":["é".repeat(size)]}]),
            );
            check(&spec, if size == 128 { "accepted" } else { "shape" });
        }
        for size in [0, 1024, 1025] {
            let mut spec = base.clone();
            spec.rationale = "a".repeat(size);
            check(&spec, if size == 1024 { "accepted" } else { "shape" });
        }
    }

    #[test]
    fn fields_and_value_types_are_closed_by_collector() {
        for (clause, expected) in [
            (json!({"op":"eq","field":"pid","value":1}), "fields"),
            (json!({"op":"eq","field":"uid","value":"1"}), "fields"),
            (json!({"op":"in","field":"uid","values":[1,true]}), "fields"),
            (json!({"op":"prefix","field":"uid","value":"1"}), "fields"),
            (
                json!({"op":"range","field":"comm","min":0,"max":1}),
                "fields",
            ),
            (json!({"op":"eq","field":"uid","value":1}), "accepted"),
        ] {
            check(&rule(RuleEffect::RequirePresent, json!([clause])), expected);
        }
        let mut unsupported = rule(
            RuleEffect::RequirePresent,
            json!([{"op":"eq","field":"uid","value":1}]),
        );
        unsupported.scope.collector = CollectorType::FilesMetadata;
        check(&unsupported, "fields");
    }

    #[test]
    fn suppression_requires_an_exact_identity_anchor() {
        for effect in [RuleEffect::AllowOptional, RuleEffect::IgnoreModified] {
            let mut spec = rule(
                effect,
                json!([
                    {"op":"prefix","field":"comm","value":"nx"},
                    {"op":"eq","field":"bind_scope","value":"loopback"},
                    {"op":"eq","field":"local_port","value":4000}
                ]),
            );
            check(&spec, "identity-anchor");
            spec.matches.push(MatchClause::In {
                field: "uid".into(),
                values: vec![RuleValue::Int(12)],
            });
            check(&spec, "accepted");
        }
    }

    #[test]
    fn socket_port_range_and_loopback_exception_are_bounded() {
        for (scope, min, max, expected) in [
            ("specific", 5000, 6024, "accepted"),
            ("specific", 5000, 6025, "port-bounds"),
            ("loopback", 1024, 65535, "accepted"),
            ("loopback", 1023, 65535, "port-bounds"),
            ("loopback", 1024, 65536, "port-bounds"),
            ("specific", i64::MIN, i64::MAX, "port-bounds"),
        ] {
            let spec = rule(
                RuleEffect::AllowOptional,
                json!([
                    {"op":"eq","field":"comm","value":"nx"},
                    {"op":"eq","field":"bind_scope","value":scope},
                    {"op":"range","field":"local_port","min":min,"max":max}
                ]),
            );
            check(&spec, expected);
        }
        check(
            &rule(
                RuleEffect::AllowOptional,
                json!([{"op":"eq","field":"comm","value":"nx"}]),
            ),
            "port-bounds",
        );
    }

    #[test]
    fn wildcard_binds_require_unit_eq_and_no_more_than_eight_explicit_ports() {
        for (anchor, count, expected) in [
            (
                json!({"op":"eq","field":"systemd_unit","value":"nx.service"}),
                8,
                "accepted",
            ),
            (
                json!({"op":"eq","field":"systemd_unit","value":"nx.service"}),
                9,
                "wildcard-bind",
            ),
            (
                json!({"op":"in","field":"systemd_unit","values":["nx.service"]}),
                8,
                "wildcard-bind",
            ),
        ] {
            let mut spec = rule(
                RuleEffect::AllowOptional,
                json!([
                    anchor, {"op":"in","field":"local_port","values":(4000..4000+count).collect::<Vec<_>>()}
                ]),
            );
            check(&spec, expected);
            spec.matches.push(MatchClause::In {
                field: "bind_scope".into(),
                values: vec![
                    RuleValue::Text("any".into()),
                    RuleValue::Text("loopback".into()),
                ],
            });
            check(&spec, expected);
        }
    }

    #[test]
    fn public_connections_require_a_destination_constraint() {
        let registry = registry_entry("connections.outbound");
        let mut spec = rule(
            RuleEffect::AllowOptional,
            json!([
                {"op":"eq","field":"uid","value":12}
            ]),
        );
        let check = |spec: &ExpectationRuleSpec, id: &str| {
            let result = validate_with_registry(
                spec,
                RuleOrigin::Operator,
                Utc::now(),
                &RuleGateConfig::default(),
                registry,
            );
            assert_eq!(result.rule_id, format!("rule-gate/{id}"));
            assert_eq!(result.allowed, id == "accepted");
        };
        check(&spec, "public-remote");
        spec.matches.push(MatchClause::Eq {
            field: "remote_port".into(),
            value: RuleValue::Int(443),
        });
        check(&spec, "accepted");
        spec.matches[1] = MatchClause::Eq {
            field: "remote_scope".into(),
            value: RuleValue::Text("private".into()),
        };
        check(&spec, "accepted");
    }

    #[test]
    fn package_allow_optional_pins_name() {
        for (clause, expected) in [
            (
                json!({"op":"eq","field":"arch","value":"x86_64"}),
                "package-name",
            ),
            (
                json!({"op":"prefix","field":"name","value":"py"}),
                "package-name",
            ),
            (
                json!({"op":"prefix","field":"name","value":"pyt"}),
                "accepted",
            ),
            (json!({"op":"eq","field":"name","value":"sh"}), "accepted"),
        ] {
            let spec = rule(RuleEffect::AllowOptional, json!([clause]));
            let decision = validate_with_registry(
                &spec,
                RuleOrigin::Operator,
                Utc::now(),
                &RuleGateConfig::default(),
                registry_entry("packages.inventory"),
            );
            assert_eq!(decision.rule_id, format!("rule-gate/{expected}"));
            assert_eq!(decision.allowed, expected == "accepted");
        }
    }

    #[test]
    fn investigator_expiry_and_quotas_apply_at_boundaries() {
        let now = Utc::now();
        let mut spec = rule(
            RuleEffect::RequirePresent,
            json!([{"op":"eq","field":"local_port","value":22}]),
        );
        let mut cfg = RuleGateConfig {
            policy_version: 3,
            prior_run_proposals: 2,
            pending_host_proposals: 19,
        };
        let check = |spec: &ExpectationRuleSpec, cfg: &RuleGateConfig, id: &str| {
            let result = validate_rule(spec, RuleOrigin::Investigator, now, cfg);
            assert_eq!(result.rule_id, format!("rule-gate/{id}"));
            assert_eq!(result.allowed, id == "accepted");
            assert_eq!(result.policy_version, 3);
        };
        check(&spec, &cfg, "investigator-expiry");
        spec.expires_at = Some(now + Duration::days(30) + Duration::nanoseconds(1));
        check(&spec, &cfg, "investigator-expiry");
        spec.expires_at = Some(now + Duration::days(30));
        check(&spec, &cfg, "accepted");
        cfg.prior_run_proposals = 3;
        check(&spec, &cfg, "run-quota");
        cfg.prior_run_proposals = 2;
        cfg.pending_host_proposals = 20;
        check(&spec, &cfg, "host-quota");
    }

    #[test]
    fn expired_rule_is_rejected() {
        let mut spec = rule(
            RuleEffect::RequirePresent,
            json!([{"op":"eq","field":"local_port","value":22}]),
        );
        let now = Utc::now();
        for (expiry, allowed) in [
            (now - Duration::seconds(1), false),
            (now, false),
            (now + Duration::seconds(1), true),
        ] {
            spec.expires_at = Some(expiry);
            let result =
                validate_rule(&spec, RuleOrigin::Operator, now, &RuleGateConfig::default());
            assert_eq!(result.allowed, allowed);
            if !allowed {
                assert_eq!(result.rule_id, "rule-gate/expired");
            }
        }
    }
}
