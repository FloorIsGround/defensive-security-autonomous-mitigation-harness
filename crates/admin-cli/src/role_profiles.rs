use clap::ValueEnum;
use defsec_policy::{edge_floor::EdgeSafetyConfig, host_profile::apply_host_profile};
use defsec_protocol::{
    profile::{HOST_PROFILE_SCHEMA_VERSION, HostProfile},
    watch::{
        CollectorSpec, CompareTarget, TriggerPredicate, WakePolicy, WatchClass, WatchLifecycle,
        WatchSchedule, WatchSpec,
    },
};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileRole {
    Desktop,
    Server,
    Bastion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchTemplate {
    roles: Vec<ProfileRole>,
    collector: CollectorSpec,
    interval_seconds: u64,
    set_field: String,
    identity_key: String,
    #[serde(default)]
    ignore_fields: Vec<String>,
}

impl ProfileRole {
    fn templates(self) -> impl Iterator<Item = WatchTemplate> {
        let templates: Vec<WatchTemplate> =
            serde_json::from_str(include_str!("role_templates.json"))
                .expect("embedded role templates must match their schema");
        templates
            .into_iter()
            .filter(move |t| t.roles.contains(&self))
    }

    pub(crate) fn profile(
        self,
        host_tags: Vec<String>,
        expected_services: Vec<String>,
    ) -> Result<HostProfile, String> {
        let profile = HostProfile {
            schema_version: HOST_PROFILE_SCHEMA_VERSION,
            host_tags,
            expected_services,
            approved_file_roots: vec![],
            enabled_collectors: Some(
                self.templates()
                    .map(|t| t.collector.collector_type())
                    .collect(),
            ),
            collector_caps: Default::default(),
        };
        apply_host_profile(&EdgeSafetyConfig::default(), &profile)?;
        Ok(profile)
    }

    pub(crate) fn specs(self, host: &str) -> Vec<WatchSpec> {
        self.templates()
            .map(|t| WatchSpec {
                id: format!("role-{}", t.collector.collector_type().as_str()),
                version: 1,
                host_id: host.into(),
                class: WatchClass::Baseline,
                incident_id: None,
                collector: t.collector,
                schedule: WatchSchedule {
                    interval_seconds: t.interval_seconds,
                    timeout_seconds: 10,
                },
                trigger: TriggerPredicate::SetDiff {
                    compare_against: CompareTarget::LastObserved,
                    set_field: t.set_field,
                    identity_key: t.identity_key,
                    ignore_fields: t.ignore_fields,
                },
                wake_policy: WakePolicy {
                    cooldown_seconds: 300,
                    max_wakeups_per_hour: 4,
                },
                lifecycle: WatchLifecycle {
                    enabled: true,
                    expires_at: None,
                    max_runs: None,
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, Utc};
    use defsec_policy::{
        control_gate::{ControlPolicyConfig, ProposalContext, evaluate_watch_proposal},
        edge_floor::validate_watch_spec,
    };
    use defsec_protocol::rpc::{PrincipalRole, ScopedCapability};

    use super::*;

    #[test]
    fn all_role_specs_pass_the_effective_edge_floor_and_control_gate() {
        let now = Utc::now();
        let policy = ControlPolicyConfig::default();
        let capability = ScopedCapability {
            may_spawn_runs: false,
            principal_id: "operator".into(),
            role: PrincipalRole::Admin,
            run_id: None,
            incident_id: None,
            allowed_hosts: vec![],
            allowed_purposes: None,
            allowed_collectors: vec![],
            expires_at: now + Duration::minutes(1),
        };
        for (role, count) in [
            (ProfileRole::Desktop, 3),
            (ProfileRole::Server, 4),
            (ProfileRole::Bastion, 5),
        ] {
            let profile = role
                .profile(vec!["prod".into()], vec!["ssh.service".into()])
                .unwrap();
            let profile: HostProfile =
                serde_json::from_str(&serde_json::to_string(&profile).unwrap()).unwrap();
            let (edge, _) = apply_host_profile(&policy.edge_floor, &profile).unwrap();
            let specs = role.specs("edge-01");
            assert_eq!(specs.len(), count, "{role:?}");
            let collectors: BTreeSet<_> = specs
                .iter()
                .map(|spec| spec.collector.collector_type())
                .collect();
            assert_eq!(collectors.len(), count, "{role:?}");
            assert_eq!(collectors, edge.allowed_collectors, "{role:?}");
            for spec in &specs {
                validate_watch_spec(spec, &edge, now).unwrap();
                let decision = evaluate_watch_proposal(
                    &capability,
                    spec,
                    &ProposalContext::default(),
                    &policy,
                    now,
                );
                assert!(decision.allowed, "{role:?}: {decision:?}");
            }
        }
    }
}
