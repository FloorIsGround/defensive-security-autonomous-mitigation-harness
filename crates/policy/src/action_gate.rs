//! Deterministic Policy Gate & Edge Safety Floor for Phase 8 Mitigations.
//!
//! Enforces:
//! - Protected-unit & protected-CIDR denylists (prevents self-DoS / lockout)
//! - Explicit opt-in for Policy-Bounded Autonomous reversible verbs vs. Dual-Signed Operator verbs
//! - Strict TTL bounds, per-host hourly rate limits, and causal feedback-loop cooldowns
//! - Independent edge-executor verification of host binding, policy version, clock skew, and dual signatures

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Duration, Utc};
use defsec_protocol::action::{
    ACTION_INTENT_SCHEMA_VERSION, ActionAuthMode, ActionIntentPayload, ActionVerb, ActionVerbKind,
};
use defsec_protocol::rpc::{PolicyDecision, PrincipalRole, ScopedCapability};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::edge_floor::{is_valid_identifier, validate_systemd_unit_name};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSafetyConfig {
    pub expected_policy_version: u32,
    /// Opt-in reversible verbs allowed to auto-authorize without human dual-sign.
    /// Defaults to EMPTY (safe-by-default); operators explicitly enable low-blast-radius
    /// verbs such as `NftBlockIp` or `SystemdStopUnit`.
    pub allow_autonomous_verbs: BTreeSet<ActionVerbKind>,
    /// Verbs permitted when dual-signed by both `control-d` and an independent operator key.
    pub allow_dual_signed_verbs: BTreeSet<ActionVerbKind>,
    pub max_autonomous_ttl_seconds: u64,
    pub max_dual_signed_ttl_seconds: u64,
    pub max_actions_per_host_per_hour: u32,
    pub causal_loop_cooldown_seconds: u64,
    pub max_clock_skew_seconds: i64,
    /// Critical units that can NEVER be stopped by autonomous or dual-signed verbs.
    pub protected_units: BTreeSet<String>,
    /// Protected CIDRs (loopback, link-local, management/RFC1918) that can NEVER be blocked.
    pub protected_cidrs: Vec<String>,
}

impl Default for ActionSafetyConfig {
    fn default() -> Self {
        let mut allow_dual_signed_verbs = BTreeSet::new();
        allow_dual_signed_verbs.insert(ActionVerbKind::NftBlockIp);
        allow_dual_signed_verbs.insert(ActionVerbKind::SystemdStopUnit);
        allow_dual_signed_verbs.insert(ActionVerbKind::HostIsolate);

        let protected_units: BTreeSet<String> = [
            "sshd.service",
            "ssh.service",
            "systemd-journald.service",
            "systemd-networkd.service",
            "systemd-resolved.service",
            "NetworkManager.service",
            "dbus.service",
            "agent-d.service",
            "control-d.service",
            "action-exec-d.service",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            expected_policy_version: 1,
            allow_autonomous_verbs: BTreeSet::new(),
            allow_dual_signed_verbs,
            max_autonomous_ttl_seconds: 1800, // 30 minutes
            max_dual_signed_ttl_seconds: 86_400, // 24 hours
            max_actions_per_host_per_hour: 5,
            causal_loop_cooldown_seconds: 120,
            max_clock_skew_seconds: 300,
            protected_units,
            protected_cidrs: vec![
                "127.0.0.0/8".into(),
                "::1/128".into(),
                "169.254.0.0/16".into(),
                "fe80::/10".into(),
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
            ],
        }
    }
}

impl ActionSafetyConfig {
    /// Convenience profile enabling reversible, time-bounded autonomous containment
    /// (`NftBlockIp` and non-protected `SystemdStopUnit`) while keeping `HostIsolate`
    /// strictly dual-signed by an independent operator key.
    pub fn with_bounded_autonomous_containment() -> Self {
        let mut cfg = Self::default();
        cfg.allow_autonomous_verbs.insert(ActionVerbKind::NftBlockIp);
        cfg.allow_autonomous_verbs
            .insert(ActionVerbKind::SystemdStopUnit);
        cfg
    }
}

#[derive(Debug, Clone, Default)]
pub struct ActionProposalContext {
    pub host_actions_last_hour: u32,
    pub last_host_action_at: Option<DateTime<Utc>>,
    pub verified_evidence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionEvaluation {
    pub decision: PolicyDecision,
    pub auth_mode: Option<ActionAuthMode>,
}

/// Evaluate a proposed mitigation action against role scope, evidence binding,
/// protected assets, rate limits, causal-loop cooldown, and autonomous vs. dual-sign tier.
pub fn evaluate_action_proposal(
    capability: &ScopedCapability,
    host_id: &str,
    incident_id: &str,
    verb: &ActionVerb,
    ctx: &ActionProposalContext,
    cfg: &ActionSafetyConfig,
    now: DateTime<Utc>,
) -> ActionEvaluation {
    let deny = |rule_id: &str, reason: String| ActionEvaluation {
        decision: PolicyDecision {
            allowed: false,
            rule_id: rule_id.into(),
            reason,
            policy_version: cfg.expected_policy_version,
        },
        auth_mode: None,
    };

    if capability.expires_at <= now {
        return deny("cap.expired", "capability token has expired".into());
    }
    if capability.role == PrincipalRole::Observer {
        return deny(
            "action.observer_forbidden",
            "observer role cannot propose mitigation actions".into(),
        );
    }
    if capability.role != PrincipalRole::Admin {
        if !capability.allowed_hosts.iter().any(|h| h == host_id) {
            return deny(
                "action.scope_host_denied",
                format!("host '{host_id}' is outside capability scope"),
            );
        }
        if capability.incident_id.as_deref() != Some(incident_id) {
            return deny(
                "action.scope_incident_mismatch",
                "action proposal incident_id must match capability incident scope".into(),
            );
        }
    }

    if ctx.verified_evidence_count == 0 {
        return deny(
            "action.evidence_required",
            "action proposals must cite at least one verified observation ID".into(),
        );
    }

    if ctx.host_actions_last_hour >= cfg.max_actions_per_host_per_hour {
        return deny(
            "action.rate_limit",
            format!(
                "host '{host_id}' reached hourly action cap ({})",
                cfg.max_actions_per_host_per_hour
            ),
        );
    }
    if let Some(last) = ctx.last_host_action_at
        && now < last + Duration::seconds(cfg.causal_loop_cooldown_seconds as i64)
    {
        return deny(
            "action.causal_cooldown",
            format!(
                "causal feedback-loop cooldown ({}s) active after recent mitigation on host '{host_id}'",
                cfg.causal_loop_cooldown_seconds
            ),
        );
    }

    if let Err((rule_id, reason)) = validate_action_verb(verb, cfg) {
        return deny(rule_id, reason);
    }

    let kind = verb.kind();
    // HostIsolate is ALWAYS dual-signed regardless of config (defense in depth).
    let autonomous_eligible = kind != ActionVerbKind::HostIsolate
        && cfg.allow_autonomous_verbs.contains(&kind)
        && verb
            .ttl_seconds()
            .is_some_and(|ttl| ttl > 0 && ttl <= cfg.max_autonomous_ttl_seconds);

    if autonomous_eligible {
        return ActionEvaluation {
            decision: PolicyDecision {
                allowed: true,
                rule_id: "action.autonomous_authorized".into(),
                reason: format!(
                    "verb '{}' meets human-owned bounded autonomous containment policy",
                    kind.as_str()
                ),
                policy_version: cfg.expected_policy_version,
            },
            auth_mode: Some(ActionAuthMode::PolicyBoundedAutonomous),
        };
    }

    if cfg.allow_dual_signed_verbs.contains(&kind) {
        if let Some(ttl) = verb.ttl_seconds()
            && (ttl == 0 || ttl > cfg.max_dual_signed_ttl_seconds)
        {
            return deny(
                "action.ttl_exceeded",
                format!(
                    "TTL {ttl}s exceeds dual-signed ceiling {}s",
                    cfg.max_dual_signed_ttl_seconds
                ),
            );
        }
        return ActionEvaluation {
            decision: PolicyDecision {
                allowed: true,
                rule_id: "action.pending_dual_approval".into(),
                reason: format!(
                    "verb '{}' requires independent operator Ed25519 approval signature",
                    kind.as_str()
                ),
                policy_version: cfg.expected_policy_version,
            },
            auth_mode: Some(ActionAuthMode::DualSignedOperator),
        };
    }

    deny(
        "action.verb_disabled",
        format!("verb '{}' is disabled by policy", kind.as_str()),
    )
}

/// Validate verb syntax, protected asset denylists, and TTL bounds.
pub fn validate_action_verb(
    verb: &ActionVerb,
    cfg: &ActionSafetyConfig,
) -> Result<(), (&'static str, String)> {
    match verb {
        ActionVerb::NftBlockIp {
            ip, ttl_seconds, ..
        } => {
            let parsed: IpAddr = ip
                .parse()
                .map_err(|_| ("action.invalid_ip", format!("invalid IP address '{ip}'")))?;
            if parsed.is_unspecified() || parsed.is_multicast() {
                return Err((
                    "action.protected_ip",
                    format!("blocking unspecified or multicast IP '{ip}' is forbidden"),
                ));
            }
            for cidr in &cfg.protected_cidrs {
                if ip_in_cidr(parsed, cidr) {
                    return Err((
                        "action.protected_ip",
                        format!("IP '{ip}' falls inside protected CIDR '{cidr}'"),
                    ));
                }
            }
            if *ttl_seconds == 0 || *ttl_seconds > cfg.max_dual_signed_ttl_seconds {
                return Err((
                    "action.ttl_exceeded",
                    format!(
                        "nft_block_ip ttl_seconds {} must be within 1..={}",
                        ttl_seconds, cfg.max_dual_signed_ttl_seconds
                    ),
                ));
            }
            Ok(())
        }
        ActionVerb::SystemdStopUnit { unit, ttl_seconds } => {
            validate_systemd_unit_name(unit)
                .map_err(|reason| ("action.invalid_unit", reason))?;
            if cfg.protected_units.contains(unit) {
                return Err((
                    "action.protected_unit",
                    format!("unit '{unit}' is protected and cannot be stopped"),
                ));
            }
            if let Some(ttl) = ttl_seconds
                && (*ttl == 0 || *ttl > cfg.max_dual_signed_ttl_seconds)
            {
                return Err((
                    "action.ttl_exceeded",
                    format!(
                        "systemd_stop_unit ttl_seconds {} must be within 1..={}",
                        ttl, cfg.max_dual_signed_ttl_seconds
                    ),
                ));
            }
            Ok(())
        }
        ActionVerb::HostIsolate {
            preserve_mgmt_cidrs,
            ttl_seconds,
        } => {
            if preserve_mgmt_cidrs.is_empty() || preserve_mgmt_cidrs.len() > 16 {
                return Err((
                    "action.mgmt_cidr_required",
                    "host_isolate must preserve 1..=16 valid management CIDRs to prevent lockout"
                        .into(),
                ));
            }
            for cidr in preserve_mgmt_cidrs {
                if !is_valid_cidr(cidr) {
                    return Err((
                        "action.invalid_cidr",
                        format!("invalid management CIDR '{cidr}'"),
                    ));
                }
            }
            if *ttl_seconds == 0 || *ttl_seconds > cfg.max_dual_signed_ttl_seconds {
                return Err((
                    "action.ttl_exceeded",
                    format!(
                        "host_isolate ttl_seconds {} must be within 1..={}",
                        ttl_seconds, cfg.max_dual_signed_ttl_seconds
                    ),
                ));
            }
            Ok(())
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ActionEdgeError {
    #[error("unsupported action intent schema version: {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("policy version mismatch: expected {expected}, got {actual}")]
    PolicyVersionMismatch { expected: u32, actual: u32 },
    #[error("intent target host '{actual}' does not match local host '{expected}'")]
    HostMismatch { expected: String, actual: String },
    #[error("invalid intent or nonce identifier")]
    InvalidIdentifier,
    #[error("intent validity window is invalid or expired")]
    ExpiredOrInvalidWindow,
    #[error("action verb '{verb}' rejected locally ({rule_id}): {reason}")]
    LocalFloorRejected {
        verb: String,
        rule_id: String,
        reason: String,
    },
    #[error("autonomous execution of verb '{0}' is not enabled on this executor")]
    AutonomousNotEnabled(String),
    #[error("dual-signed operator approval signature is required for this intent")]
    OperatorApprovalRequired,
    #[error("intent nonce '{0}' was already executed (replay rejected)")]
    ReplayDetected(String),
}

/// Independent edge-executor validation of a cryptographically verified
/// `ActionIntentPayload` against local safety policy and auth-mode requirements.
pub fn validate_edge_action_intent(
    intent: &ActionIntentPayload,
    has_verified_operator_approval: bool,
    local_host_id: &str,
    cfg: &ActionSafetyConfig,
    now: DateTime<Utc>,
) -> Result<(), ActionEdgeError> {
    if intent.schema_version != ACTION_INTENT_SCHEMA_VERSION {
        return Err(ActionEdgeError::UnsupportedSchemaVersion(
            intent.schema_version,
        ));
    }
    if intent.policy_version != cfg.expected_policy_version {
        return Err(ActionEdgeError::PolicyVersionMismatch {
            expected: cfg.expected_policy_version,
            actual: intent.policy_version,
        });
    }
    if intent.host_id != local_host_id {
        return Err(ActionEdgeError::HostMismatch {
            expected: local_host_id.to_string(),
            actual: intent.host_id.clone(),
        });
    }
    if !is_valid_identifier(&intent.intent_id) || !is_valid_identifier(&intent.nonce) {
        return Err(ActionEdgeError::InvalidIdentifier);
    }
    let skew = Duration::seconds(cfg.max_clock_skew_seconds);
    if intent.expires_at <= intent.issued_at
        || intent.issued_at > now + skew
        || intent.expires_at + skew < now
    {
        return Err(ActionEdgeError::ExpiredOrInvalidWindow);
    }

    if let Err((rule_id, reason)) = validate_action_verb(&intent.verb, cfg) {
        return Err(ActionEdgeError::LocalFloorRejected {
            verb: intent.verb.kind().as_str().into(),
            rule_id: rule_id.into(),
            reason,
        });
    }

    let kind = intent.verb.kind();
    match intent.auth_mode {
        ActionAuthMode::PolicyBoundedAutonomous => {
            if kind == ActionVerbKind::HostIsolate
                || !cfg.allow_autonomous_verbs.contains(&kind)
            {
                return Err(ActionEdgeError::AutonomousNotEnabled(
                    kind.as_str().into(),
                ));
            }
            if !intent
                .verb
                .ttl_seconds()
                .is_some_and(|ttl| ttl > 0 && ttl <= cfg.max_autonomous_ttl_seconds)
            {
                return Err(ActionEdgeError::LocalFloorRejected {
                    verb: kind.as_str().into(),
                    rule_id: "action.ttl_exceeded".into(),
                    reason: format!(
                        "autonomous TTL exceeds local ceiling {}s",
                        cfg.max_autonomous_ttl_seconds
                    ),
                });
            }
        }
        ActionAuthMode::DualSignedOperator => {
            if !cfg.allow_dual_signed_verbs.contains(&kind) {
                return Err(ActionEdgeError::LocalFloorRejected {
                    verb: kind.as_str().into(),
                    rule_id: "action.verb_disabled".into(),
                    reason: "verb disabled in local executor config".into(),
                });
            }
            if !has_verified_operator_approval {
                return Err(ActionEdgeError::OperatorApprovalRequired);
            }
        }
    }

    Ok(())
}

pub fn is_valid_cidr(cidr: &str) -> bool {
    let Some((ip_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

pub fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix)
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

#[allow(dead_code)]
fn _assert_ip_types(_: Ipv4Addr, _: Ipv6Addr) {}

#[cfg(test)]
mod tests {
    use super::*;
    use defsec_protocol::action::TrafficDirection;
    use defsec_protocol::watch::CollectorType;

    fn inv_cap(now: DateTime<Utc>) -> ScopedCapability {
        ScopedCapability {
            principal_id: "reasoner-d".into(),
            role: PrincipalRole::Investigator,
            run_id: Some("run-1".into()),
            incident_id: Some("inc-1".into()),
            allowed_hosts: vec!["edge-01".into()],
            allowed_collectors: vec![CollectorType::SocketsListening],
            expires_at: now + Duration::minutes(15),
        }
    }

    #[test]
    fn blocks_protected_ips_and_critical_units() {
        let now = Utc::now();
        let cfg = ActionSafetyConfig::with_bounded_autonomous_containment();
        let cap = inv_cap(now);
        let ctx = ActionProposalContext {
            host_actions_last_hour: 0,
            last_host_action_at: None,
            verified_evidence_count: 1,
        };

        // Loopback & RFC1918 blocked
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.10", "::1", "fe80::1"] {
            let ev = evaluate_action_proposal(
                &cap,
                "edge-01",
                "inc-1",
                &ActionVerb::NftBlockIp {
                    ip: ip.into(),
                    direction: TrafficDirection::Inbound,
                    ttl_seconds: 600,
                },
                &ctx,
                &cfg,
                now,
            );
            assert!(!ev.decision.allowed, "protected IP {ip} must be denied");
            assert_eq!(ev.decision.rule_id, "action.protected_ip");
        }

        // sshd.service blocked
        let ev = evaluate_action_proposal(
            &cap,
            "edge-01",
            "inc-1",
            &ActionVerb::SystemdStopUnit {
                unit: "sshd.service".into(),
                ttl_seconds: Some(600),
            },
            &ctx,
            &cfg,
            now,
        );
        assert!(!ev.decision.allowed);
        assert_eq!(ev.decision.rule_id, "action.protected_unit");
    }

    #[test]
    fn classifies_bounded_autonomous_vs_dual_signed_and_enforces_cooldown() {
        let now = Utc::now();
        let cfg = ActionSafetyConfig::with_bounded_autonomous_containment();
        let cap = inv_cap(now);
        let ctx = ActionProposalContext {
            host_actions_last_hour: 0,
            last_host_action_at: None,
            verified_evidence_count: 2,
        };

        // Public attacker IP with 900s TTL -> PolicyBoundedAutonomous
        let ev = evaluate_action_proposal(
            &cap,
            "edge-01",
            "inc-1",
            &ActionVerb::NftBlockIp {
                ip: "203.0.113.42".into(),
                direction: TrafficDirection::Inbound,
                ttl_seconds: 900,
            },
            &ctx,
            &cfg,
            now,
        );
        assert!(ev.decision.allowed);
        assert_eq!(ev.auth_mode, Some(ActionAuthMode::PolicyBoundedAutonomous));

        // HostIsolate -> ALWAYS DualSignedOperator
        let ev = evaluate_action_proposal(
            &cap,
            "edge-01",
            "inc-1",
            &ActionVerb::HostIsolate {
                preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
                ttl_seconds: 900,
            },
            &ctx,
            &cfg,
            now,
        );
        assert!(ev.decision.allowed);
        assert_eq!(ev.auth_mode, Some(ActionAuthMode::DualSignedOperator));

        // Causal feedback-loop cooldown blocks rapid follow-up actions
        let cooldown_ctx = ActionProposalContext {
            host_actions_last_hour: 1,
            last_host_action_at: Some(now - Duration::seconds(30)),
            verified_evidence_count: 1,
        };
        let ev = evaluate_action_proposal(
            &cap,
            "edge-01",
            "inc-1",
            &ActionVerb::NftBlockIp {
                ip: "203.0.113.99".into(),
                direction: TrafficDirection::Inbound,
                ttl_seconds: 600,
            },
            &cooldown_ctx,
            &cfg,
            now,
        );
        assert!(!ev.decision.allowed);
        assert_eq!(ev.decision.rule_id, "action.causal_cooldown");
    }
}
