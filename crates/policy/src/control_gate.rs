//! Central Control-Plane Policy Validator Gate, Quotas, and Wake Circuit Breaker.
//!
//! Every watch proposal passes through this deterministic validator regardless
//! of whether it originated from `reasoner-d`, an MCP client, or an operator
//! acting as an investigator.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use defsec_protocol::canonical::canonical_sha256_hex;
use defsec_protocol::rpc::{PolicyDecision, PrincipalRole, ScopedCapability};
use defsec_protocol::watch::{WatchClass, WatchSpec};
use serde::{Deserialize, Serialize};

use crate::edge_floor::{EdgeSafetyConfig, validate_watch_spec};

pub(crate) const DEFAULT_POLICY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPolicyConfig {
    pub policy_version: u32,
    pub max_ephemeral_per_incident: usize,
    pub max_ephemeral_per_host: usize,
    pub max_proposals_per_incident: usize,
    pub max_equivalent_renewals_per_incident: usize,
    pub edge_floor: EdgeSafetyConfig,
}

impl Default for ControlPolicyConfig {
    fn default() -> Self {
        Self {
            policy_version: DEFAULT_POLICY_VERSION,
            max_ephemeral_per_incident: 5,
            max_ephemeral_per_host: 10,
            max_proposals_per_incident: 25,
            max_equivalent_renewals_per_incident: 1,
            edge_floor: EdgeSafetyConfig::default(),
        }
    }
}

/// Snapshot of existing state needed to evaluate a watch proposal deterministically.
#[derive(Debug, Clone, Default)]
pub struct ProposalContext {
    pub active_host_watches: Vec<WatchSpec>,
    pub active_incident_watches: Vec<WatchSpec>,
    pub prior_incident_proposal_count: usize,
    pub prior_equivalent_fingerprints_in_incident: HashMap<String, usize>,
}

/// Compute a deterministic target fingerprint for a watch spec so equivalent
/// ephemeral watches (same host + collector parameters) cannot be duplicated or
/// renewed indefinitely via watch replacement.
pub fn watch_target_fingerprint(spec: &WatchSpec) -> String {
    let key = serde_json::json!({
        "host_id": spec.host_id,
        "collector": spec.collector,
    });
    canonical_sha256_hex(&key).unwrap_or_else(|_| format!("{}:err", spec.host_id))
}

/// Evaluate a watch proposal under a `ScopedCapability` and `ControlPolicyConfig`.
pub fn evaluate_watch_proposal(
    capability: &ScopedCapability,
    spec: &WatchSpec,
    ctx: &ProposalContext,
    cfg: &ControlPolicyConfig,
    now: DateTime<Utc>,
) -> PolicyDecision {
    let deny = |rule_id: &str, reason: String| PolicyDecision {
        allowed: false,
        rule_id: rule_id.into(),
        reason,
        policy_version: cfg.policy_version,
    };

    // 1. Capability expiry & role authorization
    if capability.expires_at <= now {
        return deny("cap.expired", "capability token has expired".into());
    }

    match (capability.role, spec.class) {
        (PrincipalRole::Observer, _) => {
            return deny(
                "role.observer_readonly",
                "observer role cannot submit watch proposals".into(),
            );
        }
        (PrincipalRole::Investigator, WatchClass::Baseline) => {
            return deny(
                "baseline.protected",
                "reasoning/investigator identities cannot create or modify baseline watches".into(),
            );
        }
        (PrincipalRole::Investigator, WatchClass::Ephemeral) => {}
        (PrincipalRole::Admin, _) => {}
    }

    // 2. Host & collector scope checks (never trust model-provided IDs as authority)
    if capability.role != PrincipalRole::Admin {
        if !capability.allowed_hosts.iter().any(|h| h == &spec.host_id) {
            return deny(
                "scope.host_denied",
                format!("host '{}' is outside capability scope", spec.host_id),
            );
        }
        if !capability
            .allowed_collectors
            .contains(&spec.collector.collector_type())
        {
            return deny(
                "scope.collector_denied",
                format!(
                    "collector '{}' is outside capability scope",
                    spec.collector.collector_type().as_str()
                ),
            );
        }
        let Some(cap_inc) = &capability.incident_id else {
            return deny(
                "scope.missing_incident",
                "ephemeral watch proposal requires an incident-scoped capability".into(),
            );
        };
        if spec.incident_id.as_deref() != Some(cap_inc.as_str()) {
            return deny(
                "scope.incident_mismatch",
                "watch incident_id must match capability incident scope".into(),
            );
        }
    }

    // 3. Enforce at least the edge safety floor centrally before signing/dispatching
    if let Err(e) = validate_watch_spec(spec, &cfg.edge_floor, now) {
        return deny("spec.safety_floor", e.to_string());
    }

    // 4. Ephemeral quotas, duplicate suppression, and renewal-loop prevention
    if spec.class == WatchClass::Ephemeral {
        if ctx.active_incident_watches.len() >= cfg.max_ephemeral_per_incident {
            return deny(
                "quota.incident_ephemeral_cap",
                format!(
                    "incident already has {} active ephemeral watches (cap {})",
                    ctx.active_incident_watches.len(),
                    cfg.max_ephemeral_per_incident
                ),
            );
        }
        let active_host_ephemeral = ctx
            .active_host_watches
            .iter()
            .filter(|w| w.class == WatchClass::Ephemeral)
            .count();
        if active_host_ephemeral >= cfg.max_ephemeral_per_host {
            return deny(
                "quota.host_ephemeral_cap",
                format!(
                    "host '{}' already has {} active ephemeral watches (cap {})",
                    spec.host_id, active_host_ephemeral, cfg.max_ephemeral_per_host
                ),
            );
        }
        if ctx.prior_incident_proposal_count >= cfg.max_proposals_per_incident {
            return deny(
                "quota.incident_proposal_cap",
                format!(
                    "incident proposal limit ({}) reached",
                    cfg.max_proposals_per_incident
                ),
            );
        }

        let fp = watch_target_fingerprint(spec);
        if ctx
            .active_host_watches
            .iter()
            .any(|w| watch_target_fingerprint(w) == fp)
        {
            return deny(
                "dedup.equivalent_active_watch",
                "an equivalent watch with the same host and collector target is already active".into(),
            );
        }
        let prior_equiv = ctx
            .prior_equivalent_fingerprints_in_incident
            .get(&fp)
            .copied()
            .unwrap_or(0);
        if prior_equiv > cfg.max_equivalent_renewals_per_incident {
            return deny(
                "quota.renewal_loop_blocked",
                "equivalent ephemeral watch renewal limit exceeded for this incident".into(),
            );
        }
    }

    PolicyDecision {
        allowed: true,
        rule_id: "policy.accepted".into(),
        reason: "watch specification satisfies central policy and safety floor".into(),
        policy_version: cfg.policy_version,
    }
}

/// Durable wake circuit breaker enforcing cooldowns, per-watch/host/global
/// budgets, and reserved capacity for high-priority health/liveness alerts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeBudgetConfig {
    pub max_host_wakeups_per_hour: u32,
    pub max_global_wakeups_per_hour: u32,
    pub reserved_health_wakeups_per_hour: u32,
}

impl Default for WakeBudgetConfig {
    fn default() -> Self {
        Self {
            max_host_wakeups_per_hour: 12,
            max_global_wakeups_per_hour: 60,
            reserved_health_wakeups_per_hour: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeDecision {
    Allow,
    Suppress { reason: String },
}

#[allow(clippy::too_many_arguments)]
pub fn check_wake_budget(
    now: DateTime<Utc>,
    is_health_priority: bool,
    watch_cooldown_seconds: u64,
    watch_max_per_hour: u32,
    last_watch_wake: Option<DateTime<Utc>>,
    watch_wakes_last_hour: u32,
    host_wakes_last_hour: u32,
    global_wakes_last_hour: u32,
    cfg: &WakeBudgetConfig,
) -> WakeDecision {
    if !is_health_priority {
        if let Some(last) = last_watch_wake
            && now < last + Duration::seconds(watch_cooldown_seconds as i64)
        {
            return WakeDecision::Suppress {
                reason: "watch cooldown active".into(),
            };
        }
        if watch_wakes_last_hour >= watch_max_per_hour {
            return WakeDecision::Suppress {
                reason: "per-watch hourly wake budget exhausted".into(),
            };
        }
        if host_wakes_last_hour >= cfg.max_host_wakeups_per_hour {
            return WakeDecision::Suppress {
                reason: "per-host hourly wake budget exhausted".into(),
            };
        }
        let non_health_cap = cfg
            .max_global_wakeups_per_hour
            .saturating_sub(cfg.reserved_health_wakeups_per_hour);
        if global_wakes_last_hour >= non_health_cap {
            return WakeDecision::Suppress {
                reason: "global non-health wake budget exhausted (capacity reserved for health events)".into(),
            };
        }
    } else if global_wakes_last_hour >= cfg.max_global_wakeups_per_hour {
        return WakeDecision::Suppress {
            reason: "global hard wake circuit breaker tripped".into(),
        };
    }

    WakeDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use defsec_protocol::watch::{
        CollectorSpec, CollectorType, CompareTarget, SystemdUnitStateParams, TriggerPredicate,
        WakePolicy, WatchLifecycle, WatchSchedule,
    };

    fn make_cap(role: PrincipalRole, now: DateTime<Utc>) -> ScopedCapability {
        ScopedCapability {
            principal_id: "reasoner-1".into(),
            role,
            run_id: Some("run-1".into()),
            incident_id: Some("inc-42".into()),
            allowed_hosts: vec!["edge-07".into()],
            allowed_collectors: vec![
                CollectorType::SystemdUnitState,
                CollectorType::SocketsListening,
            ],
            expires_at: now + Duration::minutes(15),
        }
    }

    fn make_spec(id: &str, class: WatchClass, host: &str, unit: &str, now: DateTime<Utc>) -> WatchSpec {
        WatchSpec {
            id: id.into(),
            version: 1,
            host_id: host.into(),
            class,
            incident_id: Some("inc-42".into()),
            collector: CollectorSpec::SystemdUnitState(SystemdUnitStateParams {
                unit: unit.into(),
                hash_unit_files: true,
            }),
            schedule: WatchSchedule {
                interval_seconds: 30,
                timeout_seconds: 5,
            },
            trigger: TriggerPredicate::FieldChanged {
                compare_against: CompareTarget::LastObserved,
                fields: vec!["active_state".into()],
            },
            wake_policy: WakePolicy {
                cooldown_seconds: 180,
                max_wakeups_per_hour: 4,
            },
            lifecycle: WatchLifecycle {
                enabled: true,
                expires_at: Some(now + Duration::hours(2)),
                max_runs: Some(240),
            },
        }
    }

    #[test]
    fn investigator_cannot_touch_baseline_or_cross_host_or_exceed_quota() {
        let now = Utc::now();
        let cfg = ControlPolicyConfig::default();
        let cap = make_cap(PrincipalRole::Investigator, now);
        let ctx = ProposalContext::default();

        // Baseline forbidden
        let baseline = make_spec("b1", WatchClass::Baseline, "edge-07", "sshd.service", now);
        let d = evaluate_watch_proposal(&cap, &baseline, &ctx, &cfg, now);
        assert!(!d.allowed);
        assert_eq!(d.rule_id, "baseline.protected");

        // Cross-host forbidden
        let cross = make_spec("e1", WatchClass::Ephemeral, "edge-99", "sshd.service", now);
        let d = evaluate_watch_proposal(&cap, &cross, &ctx, &cfg, now);
        assert!(!d.allowed);
        assert_eq!(d.rule_id, "scope.host_denied");

        // Valid ephemeral accepted
        let valid = make_spec("e2", WatchClass::Ephemeral, "edge-07", "nginx.service", now);
        let d = evaluate_watch_proposal(&cap, &valid, &ctx, &cfg, now);
        assert!(d.allowed);

        // Equivalent duplicate rejected
        let mut dup_ctx = ctx.clone();
        dup_ctx.active_host_watches.push(valid.clone());
        let dup = make_spec("e3", WatchClass::Ephemeral, "edge-07", "nginx.service", now);
        let d = evaluate_watch_proposal(&cap, &dup, &dup_ctx, &cfg, now);
        assert!(!d.allowed);
        assert_eq!(d.rule_id, "dedup.equivalent_active_watch");
    }

    #[test]
    fn set_diff_ignore_fields_share_edge_and_control_limits() {
        let now = Utc::now();
        let cfg = ControlPolicyConfig::default();
        let cap = make_cap(PrincipalRole::Investigator, now);
        let mut spec = make_spec("e1", WatchClass::Ephemeral, "edge-07", "sshd.service", now);
        spec.collector =
            CollectorSpec::SocketsListening(defsec_protocol::watch::SocketsListeningParams {
                include_tcp: true,
                include_udp: false,
                include_ipv6: true,
                resolve_process: true,
            });
        for (fields, allowed) in [
            (vec!["inode"; 8], true),
            (vec!["inode"; 9], false),
            (vec!["pid start"], false),
        ] {
            spec.trigger = TriggerPredicate::SetDiff {
                compare_against: CompareTarget::LastObserved,
                set_field: "sockets".into(),
                identity_key: "socket_key".into(),
                ignore_fields: fields.into_iter().map(String::from).collect(),
            };
            assert_eq!(
                validate_watch_spec(&spec, &cfg.edge_floor, now).is_ok(),
                allowed
            );
            let decision =
                evaluate_watch_proposal(&cap, &spec, &ProposalContext::default(), &cfg, now);
            assert_eq!(decision.allowed, allowed);
            if !allowed {
                assert_eq!(decision.rule_id, "spec.safety_floor");
                assert!(decision.reason.contains("ignore_fields"));
            }
        }
    }

    #[test]
    fn wake_circuit_breaker_reserves_capacity_for_health_events() {
        let now = Utc::now();
        let cfg = WakeBudgetConfig {
            max_host_wakeups_per_hour: 10,
            max_global_wakeups_per_hour: 20,
            reserved_health_wakeups_per_hour: 5,
        };
        // At 15 global wakes, non-health is suppressed, health still allowed.
        assert!(matches!(
            check_wake_budget(now, false, 60, 10, None, 0, 0, 15, &cfg),
            WakeDecision::Suppress { .. }
        ));
        assert_eq!(
            check_wake_budget(now, true, 60, 10, None, 0, 0, 15, &cfg),
            WakeDecision::Allow
        );
    }

    #[test]
    fn new_collectors_are_admissible_for_ephemeral_proposals_within_bounds() {
        use defsec_protocol::watch::{ConnectionsOutboundParams, PackagesInventoryParams};

        let now = Utc::now();
        let mut cfg = ControlPolicyConfig::default();
        let mut cap = make_cap(PrincipalRole::Investigator, now);
        cap.allowed_collectors = vec![
            CollectorType::ConnectionsOutbound,
            CollectorType::PackagesInventory,
        ];

        let mut outbound = make_spec("e-out", WatchClass::Ephemeral, "edge-07", "sshd.service", now);
        outbound.collector = CollectorSpec::ConnectionsOutbound(ConnectionsOutboundParams {
            include_tcp: true,
            include_udp: false,
            include_ipv6: true,
            resolve_process: true,
            exclude_loopback: true,
            max_flows: Some(256),
        });
        let d = evaluate_watch_proposal(&cap, &outbound, &ProposalContext::default(), &cfg, now);
        assert!(d.allowed, "valid outbound proposal must pass: {}", d.reason);

        // Out of local bounds: rejected through the shared safety floor.
        let mut over = outbound.clone();
        over.id = "e-out2".into();
        if let CollectorSpec::ConnectionsOutbound(p) = &mut over.collector {
            p.max_flows = Some(600);
        }
        let d = evaluate_watch_proposal(&cap, &over, &ProposalContext::default(), &cfg, now);
        assert!(!d.allowed);
        assert_eq!(d.rule_id, "spec.safety_floor");
        assert!(d.reason.contains("max_flows 600"));

        let mut packages = make_spec("e-pkg", WatchClass::Ephemeral, "edge-07", "sshd.service", now);
        packages.collector = CollectorSpec::PackagesInventory(PackagesInventoryParams {
            max_packages: Some(1024),
        });
        let d = evaluate_watch_proposal(&cap, &packages, &ProposalContext::default(), &cfg, now);
        assert!(d.allowed, "valid packages proposal must pass: {}", d.reason);

        let mut over_pkg = packages.clone();
        over_pkg.id = "e-pkg2".into();
        if let CollectorSpec::PackagesInventory(p) = &mut over_pkg.collector {
            p.max_packages = Some(0);
        }
        let d = evaluate_watch_proposal(&cap, &over_pkg, &ProposalContext::default(), &cfg, now);
        assert!(!d.allowed);
        assert_eq!(d.rule_id, "spec.safety_floor");
        assert!(d.reason.contains("max_packages 0"));

        // A capability scoped to other collectors denies both new types.
        let mut narrow_cap = cap.clone();
        narrow_cap.allowed_collectors = vec![CollectorType::SystemdUnitState];
        let d = evaluate_watch_proposal(&narrow_cap, &outbound, &ProposalContext::default(), &cfg, now);
        assert!(!d.allowed);
        assert_eq!(d.rule_id, "scope.collector_denied");

        // A host profile tightened floor is honored centrally as well: the
        // control gate mirrors the same bounds because it applies the edge
        // floor verbatim.
        cfg.edge_floor.max_outbound_flows = 32;
        let mut beyond = outbound.clone();
        beyond.id = "e-out3".into();
        if let CollectorSpec::ConnectionsOutbound(p) = &mut beyond.collector {
            p.max_flows = Some(33);
        }
        let d = evaluate_watch_proposal(&cap, &beyond, &ProposalContext::default(), &cfg, now);
        assert!(!d.allowed);
        assert_eq!(d.rule_id, "spec.safety_floor");
    }
}
