use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use defsec_policy::{
    action_gate::ActionSafetyConfig,
    control_gate::{ControlPolicyConfig, ProposalContext, evaluate_watch_proposal},
    edge_floor::is_valid_identifier,
};
use defsec_protocol::{
    audit::AuditEventType::{
        BaselinePromoted, BundleIssued, CapabilityMinted, HostEnrolled, IncidentClosed,
        IncidentOpened, PolicyDecision as PolicyDecisionAudited, RunCompleted,
    },
    canonical::sha256_hex,
    rpc::*,
    signing::{DOMAIN_WATCH_BUNDLE_V1, SignedEnvelope, SigningKeyPair, VerifyingKeyStore},
    watch::*,
    wire::MAX_FRAME_BYTES,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::json;
use tokio::sync::watch;
use uuid::Uuid;

use crate::expectation_rules::RuleStore;
use crate::ledger::{self, audit, json_column, rows};
use crate::server::Registry;

#[path = "actions.rs"]
pub(crate) mod actions;

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("{message}")]
    Request { code: &'static str, message: String },
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Signing(#[from] defsec_protocol::signing::SigningError),
    #[error(transparent)]
    Canonical(#[from] defsec_protocol::canonical::CanonicalError),
}

impl ControlError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Request {
            code: "invalid_request",
            message: message.into(),
        }
    }

    pub(crate) fn denied(message: impl Into<String>) -> Self {
        Self::Request {
            code: "forbidden",
            message: message.into(),
        }
    }

    pub(crate) fn missing(message: impl Into<String>) -> Self {
        Self::Request {
            code: "not_found",
            message: message.into(),
        }
    }

    pub(crate) fn response_parts(self) -> (String, String) {
        match self {
            Self::Request { code, message } => (code.into(), message),
            error => {
                tracing::error!(%error, "control transaction failed");
                ("internal_error".into(), "control transaction failed".into())
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, ControlError>;

#[derive(Clone)]
pub struct ControlService(Arc<State>);

struct State {
    db: Mutex<Connection>,
    key: SigningKeyPair,
    policy: ControlPolicyConfig,
    action_safety: ActionSafetyConfig,
    operator_keys: Mutex<VerifyingKeyStore>,
    bundle_updates: watch::Sender<()>,
    agent_registry: Registry,
}

impl ControlService {
    pub fn open(
        data_dir: impl AsRef<Path>,
        key_id: impl Into<String>,
        policy_version: u32,
    ) -> Result<Self> {
        let mut policy = ControlPolicyConfig {
            policy_version,
            ..Default::default()
        };
        policy.edge_floor.expected_policy_version = policy_version;
        Self::open_with_policy(data_dir, key_id, policy)
    }

    pub fn open_with_policy(
        data_dir: impl AsRef<Path>,
        key_id: impl Into<String>,
        policy: ControlPolicyConfig,
    ) -> Result<Self> {
        let action_safety = ActionSafetyConfig {
            expected_policy_version: policy.policy_version,
            ..Default::default()
        };
        Self::open_with_policies(data_dir, key_id, policy, action_safety)
    }

    pub fn open_with_policies(
        data_dir: impl AsRef<Path>,
        key_id: impl Into<String>,
        mut policy: ControlPolicyConfig,
        action_safety: ActionSafetyConfig,
    ) -> Result<Self> {
        let dir = data_dir.as_ref();
        policy.edge_floor.expected_policy_version = policy.policy_version;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let key = load_key(dir, key_id.into())?;
        let ledger_path = dir.join("ledger.sqlite3");
        let ledger_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&ledger_path)?;
        let meta = ledger_file.metadata()?;
        if !meta.is_file()
            || meta.uid() != nix::unistd::geteuid().as_raw()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(ControlError::invalid(
                "ledger must be a private regular file owned by control-d",
            ));
        }
        let db = ledger::open(ledger_path)?;
        Ok(Self(Arc::new(State {
            db: Mutex::new(db),
            key,
            policy,
            action_safety,
            operator_keys: Mutex::new(VerifyingKeyStore::new()),
            bundle_updates: watch::channel(()).0,
            agent_registry: Registry::default(),
        })))
    }

    pub(crate) fn policy(&self) -> &ControlPolicyConfig {
        &self.0.policy
    }

    pub(crate) fn transaction<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let mut db = self
            .0
            .db
            .lock()
            .map_err(|_| io::Error::other("ledger lock poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn subscribe_bundles(&self) -> watch::Receiver<()> {
        self.0.bundle_updates.subscribe()
    }

    pub(crate) fn agent_registry(&self) -> Registry {
        self.0.agent_registry.clone()
    }

    /// Mark hosts offline when their last contact is strictly older than the grace window.
    pub fn sweep_stale_hosts(&self, now: DateTime<Utc>, grace_seconds: u64) -> Result<Vec<String>> {
        let Some(cutoff) = i64::try_from(grace_seconds)
            .ok()
            .and_then(Duration::try_seconds)
            .and_then(|grace| now.checked_sub_signed(grace))
        else {
            return Ok(vec![]);
        };
        self.transaction(|db| {
            let stale: Vec<(String, String)> = rows(
                db,
                "SELECT host_id,last_heartbeat_at FROM hosts
                 WHERE liveness_status='online' AND last_heartbeat_at<?1 ORDER BY host_id",
                [stamp(cutoff)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let mut offline = Vec::with_capacity(stale.len());
            for (host, last_heartbeat) in stale {
                db.execute("UPDATE hosts SET liveness_status='offline' WHERE host_id=?1", [&host])?;
                let existing: Option<String> = db.query_row(
                    "SELECT incident_id FROM incidents WHERE host_id=?1 AND status='open' AND is_liveness=1",
                    [&host],
                    |row| row.get(0),
                ).optional()?;
                let (incident, event) = if let Some(incident) = existing {
                    db.execute(
                        "UPDATE incidents SET updated_at=?2 WHERE incident_id=?1",
                        params![incident, stamp(now)],
                    )?;
                    (incident, PolicyDecisionAudited)
                } else {
                    let incident = uuid();
                    let summary = format!("Host {host} missed heartbeats beyond the {grace_seconds}-second grace window");
                    db.execute(
                        "INSERT INTO incidents
                         (incident_id,host_id,status,priority_json,summary,created_at,updated_at,is_liveness)
                         VALUES (?1,?2,'open',?3,?4,?5,?5,1)",
                        params![incident, host, serde_json::to_string(&Severity::High)?, summary, stamp(now)],
                    )?;
                    (incident, IncidentOpened)
                };
                audit(
                    db,
                    event,
                    "control",
                    &uuid(),
                    json!({
                        "action": "host_liveness_offline",
                        "host_id": host,
                        "incident_id": incident,
                        "last_heartbeat_at": last_heartbeat,
                        "grace_seconds": grace_seconds,
                        "swept_at": now,
                    }),
                )?;
                offline.push(host);
            }
            Ok(offline)
        })
    }

    pub(crate) fn bundle_changed(&self) {
        self.0.bundle_updates.send_replace(());
    }

    pub(crate) fn latest_bundle(&self, host: &str) -> Result<Option<(u64, SignedEnvelope)>> {
        self.transaction(|db| {
            Ok(bundle(db, host)?.map(|(version, _, envelope)| (version, envelope)))
        })
    }

    pub(crate) fn issue_bundle(
        &self,
        db: &Connection,
        host: &str,
        actor: &str,
        request: &str,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        let watches = active_watches(db, host, now)?;
        let ephemeral = watches
            .iter()
            .filter(|watch| watch.class == WatchClass::Ephemeral)
            .count();
        let floor = &self.policy().edge_floor;
        if watches.len() > floor.max_watches_total || ephemeral > floor.max_ephemeral_watches {
            return Err(ControlError::invalid(
                "host watch count exceeds bundle safety limits",
            ));
        }
        let version: u64 = db.query_row(
            "SELECT desired_bundle_version + 1 FROM hosts WHERE host_id=?1",
            [host],
            |r| r.get(0),
        )?;
        let payload = WatchBundlePayload {
            schema_version: WATCH_BUNDLE_SCHEMA_VERSION,
            bundle_id: uuid(),
            target_host_id: host.into(),
            bundle_version: version,
            issued_at: now,
            expires_at: now + Duration::days(1),
            policy_version: self.policy().policy_version,
            watches,
        };
        let envelope = self.0.key.sign_payload(DOMAIN_WATCH_BUNDLE_V1, &payload)?;
        let frame = defsec_protocol::wire::ControlToAgent::SyncWatchBundle {
            envelope: envelope.clone(),
        };
        if serde_json::to_vec(&frame)?.len() > MAX_FRAME_BYTES {
            return Err(ControlError::invalid(
                "signed bundle exceeds wire frame limit",
            ));
        }
        db.execute("INSERT INTO issued_bundles (host_id,bundle_version,bundle_id,payload_digest,envelope_json,issued_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![host, version, payload.bundle_id, envelope.payload_sha256_hex(), serde_json::to_string(&envelope)?, stamp(now), stamp(payload.expires_at)])?;
        db.execute(
            "UPDATE hosts SET desired_bundle_version=?2 WHERE host_id=?1",
            params![host, version],
        )?;
        audit(
            db,
            BundleIssued,
            actor,
            request,
            json!({"host_id": host, "bundle_id": payload.bundle_id, "version": version, "digest": envelope.payload_sha256_hex()}),
        )?;
        Ok(version)
    }

    pub fn handle_admin_request(&self, req: AdminRequest) -> AdminResponse {
        match self.transaction(|db| self.admin(db, req)) {
            Ok(response) => {
                if matches!(
                    response,
                    AdminResponse::WatchApplied { .. } | AdminResponse::IncidentClosed { .. }
                ) {
                    self.bundle_changed();
                }
                response
            }
            Err(error) => {
                let (code, message) = error.response_parts();
                AdminResponse::Error { code, message }
            }
        }
    }

    fn admin(&self, db: &Connection, req: AdminRequest) -> Result<AdminResponse> {
        let now = Utc::now();
        let request = uuid();
        let rule_store = RuleStore {
            db,
            now,
            request: &request,
            policy_version: self.policy().policy_version,
        };
        match req {
            AdminRequest::CreateExpectationRule { rule, actor } => rule_store.create(&rule, &actor),
            AdminRequest::DecideExpectationRule {
                rule_id,
                approve,
                actor,
                note,
            } => rule_store.decide(rule_id, approve, &actor, note.as_deref()),
            AdminRequest::RevokeExpectationRule {
                rule_id,
                actor,
                reason,
            } => rule_store.revoke(rule_id, &actor, &reason),
            AdminRequest::BacktestExpectationRule { rule } => rule_store.admin_backtest(&rule),
            AdminRequest::ListExpectationRules {
                host_id,
                statuses,
                limit,
            } => {
                let response = AdminResponse::ExpectationRules {
                    rules: rule_store.list(host_id.as_deref(), None, statuses.as_deref(), limit)?,
                };
                if serde_json::to_vec(&response)?.len() > MAX_FRAME_BYTES {
                    return Err(ControlError::invalid(
                        "rule list exceeds the frame limit; lower the limit or filter by host or status",
                    ));
                }
                Ok(response)
            }
            AdminRequest::EnrollHost {
                host_id,
                agent_public_key_hex,
            } => {
                if !is_valid_identifier(&host_id) {
                    return Err(ControlError::invalid("invalid host ID"));
                }
                if let Some(key) = &agent_public_key_hex {
                    VerifyingKeyStore::new().insert_public_hex("agent", key)?;
                }
                let inserted = db.execute("INSERT INTO hosts (host_id,agent_public_key_hex) VALUES (?1,?2) ON CONFLICT DO NOTHING", params![host_id, agent_public_key_hex])?;
                if inserted == 1 {
                    audit(
                        db,
                        HostEnrolled,
                        "operator",
                        &request,
                        json!({"host_id": host_id, "agent_public_key_hex": agent_public_key_hex}),
                    )?;
                } else {
                    let prior: Option<String> = db.query_row(
                        "SELECT agent_public_key_hex FROM hosts WHERE host_id=?1",
                        [&host_id],
                        |r| r.get(0),
                    )?;
                    if prior != agent_public_key_hex {
                        return Err(ControlError::invalid(
                            "host already enrolled with a different key",
                        ));
                    }
                }
                Ok(AdminResponse::HostEnrolled {
                    host_id,
                    control_signing_key_id: self.0.key.key_id().into(),
                    control_public_key_hex: self.0.key.public_hex(),
                })
            }
            AdminRequest::ApplyBaselineWatch {
                mut spec,
                actor,
                rationale,
            } => {
                require_host(db, &spec.host_id)?;
                if spec.class != WatchClass::Baseline || spec.incident_id.is_some() {
                    return Err(ControlError::invalid(
                        "apply-watch requires an incident-independent baseline watch",
                    ));
                }
                let previous = latest_spec(db, &spec.host_id, &spec.id)?;
                if previous
                    .as_ref()
                    .is_some_and(|w| w.class != WatchClass::Baseline)
                {
                    return Err(ControlError::invalid(
                        "watch ID belongs to an ephemeral watch",
                    ));
                }
                spec.version = previous
                    .map_or(Some(1), |spec| spec.version.checked_add(1))
                    .ok_or_else(|| ControlError::invalid("watch versions exhausted"))?;
                let capability = ScopedCapability {
                    principal_id: actor.clone(),
                    role: PrincipalRole::Admin,
                    run_id: None,
                    incident_id: None,
                    allowed_hosts: vec![],
                    allowed_collectors: vec![],
                    expires_at: now + Duration::seconds(1),
                };
                let decision = evaluate_watch_proposal(
                    &capability,
                    &spec,
                    &ProposalContext::default(),
                    self.policy(),
                    now,
                );
                record_decision(
                    db,
                    None,
                    &actor,
                    &request,
                    &decision,
                    json!({"spec": spec, "rationale": rationale}),
                    now,
                )?;
                if !decision.allowed {
                    return Ok(AdminResponse::Error {
                        code: decision.rule_id,
                        message: decision.reason,
                    });
                }
                insert_watch(db, &spec, &actor, now)?;
                let bundle_version = self.issue_bundle(db, &spec.host_id, &actor, &request, now)?;
                Ok(AdminResponse::WatchApplied {
                    watch_id: spec.id,
                    bundle_version,
                })
            }
            AdminRequest::PromoteBaseline {
                host_id,
                watch_id,
                observation_id,
                approver,
                rationale,
                ticket_ref,
            } => {
                let spec = latest_spec(db, &host_id, &watch_id)?
                    .filter(|s| s.class == WatchClass::Baseline)
                    .ok_or_else(|| ControlError::missing("baseline watch does not exist"))?;
                let (state_hash, sample): (String, String) = db.query_row(
                    "SELECT state_hash,sample_json FROM observations WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3 AND observation_id=?4 AND sample_json IS NOT NULL",
                    params![host_id,watch_id,spec.version,observation_id], |r| Ok((r.get(0)?,r.get(1)?))
                ).optional()?.ok_or_else(|| ControlError::invalid("observation is unavailable or lacks valid state for the current watch revision"))?;
                let predecessor: Option<i64> = db.query_row("SELECT baseline_revision_id FROM watch_state WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
                    params![host_id,watch_id,spec.version], |r| r.get(0))?;
                db.execute("INSERT INTO baseline_revisions (host_id,watch_id,spec_version,predecessor_id,observation_id,state_hash,sample_json,approver,approved_at,rationale,ticket_ref,policy_version) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![host_id,watch_id,spec.version,predecessor,observation_id,state_hash,sample,approver,stamp(now),rationale,ticket_ref,self.policy().policy_version])?;
                let revision_id = db.last_insert_rowid();
                db.execute("UPDATE watch_state SET baseline_revision_id=?4 WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3", params![host_id,watch_id,spec.version,revision_id])?;
                audit(
                    db,
                    BaselinePromoted,
                    &approver,
                    &request,
                    json!({"host_id":host_id,"watch_id":watch_id,"revision_id":revision_id,"predecessor_id":predecessor,"observation_id":observation_id,"state_hash":state_hash,"rationale":rationale,"ticket_ref":ticket_ref}),
                )?;
                Ok(AdminResponse::BaselinePromoted {
                    revision_id,
                    host_id,
                    watch_id,
                    state_hash,
                })
            }
            AdminRequest::MintCapabilityToken {
                principal_id,
                role,
                allowed_hosts,
                allowed_collectors,
                incident_id,
                ttl_seconds,
            } => {
                if role == PrincipalRole::Admin || principal_id.trim().is_empty() {
                    return Err(ControlError::invalid(
                        "a named observer or investigator is required",
                    ));
                }
                let ttl = i64::try_from(ttl_seconds)
                    .ok()
                    .and_then(Duration::try_seconds)
                    .and_then(|d| now.checked_add_signed(d))
                    .filter(|_| ttl_seconds > 0)
                    .ok_or_else(|| ControlError::invalid("invalid token TTL"))?;
                for host in &allowed_hosts {
                    require_host(db, host)?;
                }
                if let Some(id) = &incident_id {
                    let incident = get_incident(db, id)?;
                    if incident.status != "open" || !allowed_hosts.contains(&incident.host_id) {
                        return Err(ControlError::denied(
                            "token incident must be open and within host scope",
                        ));
                    }
                }
                let capability = ScopedCapability {
                    principal_id,
                    role,
                    run_id: None,
                    incident_id,
                    allowed_hosts,
                    allowed_collectors,
                    expires_at: ttl,
                };
                let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
                let hash = sha256_hex(token.as_bytes());
                db.execute(
                    "INSERT INTO capability_tokens VALUES (?1,?2)",
                    params![hash, serde_json::to_string(&capability)?],
                )?;
                audit(
                    db,
                    CapabilityMinted,
                    "operator",
                    &request,
                    json!({"token_hash": hash, "scope": capability}),
                )?;
                Ok(AdminResponse::TokenMinted {
                    token,
                    expires_at: ttl,
                })
            }
            AdminRequest::CloseIncident {
                incident_id,
                actor,
                resolution,
            } => {
                let incident = get_incident(db, &incident_id)?;
                if incident.status == "closed" {
                    return Ok(AdminResponse::IncidentClosed {
                        incident_id,
                        retired_ephemeral_watches: 0,
                    });
                }
                db.execute("UPDATE incidents SET status='closed',updated_at=?2,closed_by=?3,resolution=?4 WHERE incident_id=?1", params![incident_id,stamp(now),actor,resolution])?;
                let retired = db.execute(
                    "UPDATE watch_specs SET active=0 WHERE incident_id=?1 AND active=1",
                    [&incident_id],
                )?;
                db.execute("UPDATE trigger_events SET status='done' WHERE incident_id=?1 AND status='pending'", [&incident_id])?;
                let runs = rows(
                    db,
                    "SELECT run_id FROM agent_runs WHERE incident_id=?1 AND status='active'",
                    [&incident_id],
                    |r| r.get::<_, String>(0),
                )?;
                db.execute("UPDATE agent_runs SET status='cancelled',ended_at=?2 WHERE incident_id=?1 AND status='active'", params![incident_id,stamp(now)])?;
                for run_id in runs {
                    audit(
                        db,
                        RunCompleted,
                        &actor,
                        &request,
                        json!({"run_id":run_id,"incident_id":incident_id,"outcome":"incident_closed"}),
                    )?;
                }
                audit(
                    db,
                    IncidentClosed,
                    &actor,
                    &request,
                    json!({"incident_id":incident_id,"resolution":resolution,"retired_ephemeral_watches":retired}),
                )?;
                self.issue_bundle(db, &incident.host_id, &actor, &request, now)?;
                Ok(AdminResponse::IncidentClosed {
                    incident_id,
                    retired_ephemeral_watches: retired,
                })
            }
            AdminRequest::ListHosts => Ok(AdminResponse::Hosts {
                hosts: list_hosts(db)?,
            }),
            AdminRequest::ListIncidents => Ok(AdminResponse::Incidents {
                incidents: list_incidents(db)?,
            }),
            AdminRequest::ListActions {
                host_id,
                incident_id,
            } => {
                let response = AdminResponse::Actions {
                    actions: actions::list_actions(db, host_id.as_deref(), incident_id.as_deref())?,
                };
                if serde_json::to_vec(&response)?.len() > MAX_FRAME_BYTES {
                    return Err(ControlError::invalid(
                        "action list exceeds the frame limit; filter by host or incident",
                    ));
                }
                Ok(response)
            }
            AdminRequest::GetActionIntent { intent_id } => {
                actions::get_action_intent(db, &intent_id)
            }
            AdminRequest::ApproveAction {
                intent_id,
                approver,
                operator_approval,
            } => self.approve_action(db, &intent_id, &approver, operator_approval),
            AdminRequest::RecordActionReceipt { receipt } => actions::record_receipt(db, receipt),
            AdminRequest::VerifyAuditChain => ledger::verify(db),
            AdminRequest::ListAuditEntries { limit } => {
                let cap = limit.unwrap_or(100).clamp(1, 500) as i64;
                let mut entries: Vec<defsec_protocol::audit::AuditEntry> = rows(
                    db,
                    "SELECT entry_json FROM audit_outbox ORDER BY seq_no DESC LIMIT ?1",
                    [cap],
                    |r| json_column(r, 0),
                )?;
                entries.reverse();
                Ok(AdminResponse::AuditEntries { entries })
            }
            AdminRequest::ListPolicyDecisions { limit } => {
                let cap = limit.unwrap_or(100).clamp(1, 500) as i64;
                let decisions = rows(
                    db,
                    "SELECT decision_id, proposal_id, actor, request_id, decision_json, created_at
                     FROM policy_decisions
                     ORDER BY decision_id DESC
                     LIMIT ?1",
                    [cap],
                    |r| {
                        Ok(PolicyDecisionRecord {
                            decision_id: r.get(0)?,
                            proposal_id: r.get(1)?,
                            actor: r.get(2)?,
                            request_id: r.get(3)?,
                            decision: json_column(r, 4)?,
                            created_at: parse_stamp(&r.get::<_, String>(5)?, 5)?,
                        })
                    },
                )?;
                Ok(AdminResponse::PolicyDecisions { decisions })
            }
        }
    }
}

fn load_key(dir: &Path, key_id: String) -> Result<SigningKeyPair> {
    if !is_valid_identifier(&key_id) {
        return Err(ControlError::invalid("invalid signing key ID"));
    }
    let path = dir.join("control-signing-key.hex");
    if !path.try_exists()? {
        let key = SigningKeyPair::generate(&key_id);
        let temp = dir.join(format!(".signing-key-{}", uuid()));
        let installed = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(key.secret_hex().as_bytes())?;
            file.sync_all()?;
            match fs::hard_link(&temp, &path) {
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                result => result?,
            }
            fs::File::open(dir)?.sync_all()
        })();
        let removed = fs::remove_file(&temp);
        installed?;
        removed?;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.permissions().mode() & 0o777 != 0o600
    {
        return Err(ControlError::invalid(
            "signing key must be a regular file owned by control-d with mode 0600",
        ));
    }
    use std::io::Read;
    let mut secret = String::new();
    file.take(65).read_to_string(&mut secret)?;
    Ok(SigningKeyPair::from_secret_hex(key_id, &secret)?)
}

pub(crate) fn uuid() -> String {
    Uuid::new_v4().to_string()
}

pub(crate) fn stamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

pub(crate) fn require_host(db: &Connection, host: &str) -> Result<()> {
    if db
        .query_row("SELECT 1 FROM hosts WHERE host_id=?1", [host], |_| Ok(()))
        .optional()?
        .is_none()
    {
        return Err(ControlError::missing("host is not enrolled"));
    }
    Ok(())
}

pub(crate) fn bundle(db: &Connection, host: &str) -> Result<Option<(u64, String, SignedEnvelope)>> {
    Ok(db.query_row(
        "SELECT bundle_version,payload_digest,envelope_json FROM issued_bundles WHERE host_id=?1 ORDER BY bundle_version DESC LIMIT 1",
        [host], |r| Ok((r.get(0)?,r.get(1)?,json_column(r,2)?))
    ).optional()?)
}

pub(crate) fn active_watches(
    db: &Connection,
    host: &str,
    now: DateTime<Utc>,
) -> Result<Vec<WatchSpec>> {
    let watches: Vec<WatchSpec> = rows(
        db,
        "SELECT w.spec_json FROM watch_specs w JOIN watch_state s USING (host_id,watch_id,spec_version) WHERE w.host_id=?1 AND w.active=1 AND s.retired=0 ORDER BY w.watch_id",
        [host],
        |r| json_column(r, 0),
    )?;
    Ok(watches
        .into_iter()
        .filter(|w| w.lifecycle.enabled && w.lifecycle.expires_at.is_none_or(|expiry| expiry > now))
        .collect())
}

pub(crate) fn latest_spec(db: &Connection, host: &str, watch: &str) -> Result<Option<WatchSpec>> {
    Ok(db.query_row("SELECT spec_json FROM watch_specs WHERE host_id=?1 AND watch_id=?2 ORDER BY spec_version DESC LIMIT 1",
        params![host,watch], |r| json_column(r,0)).optional()?)
}

pub(crate) fn insert_watch(
    db: &Connection,
    spec: &WatchSpec,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    db.execute(
        "UPDATE watch_specs SET active=0 WHERE host_id=?1 AND watch_id=?2 AND active=1",
        params![spec.host_id, spec.id],
    )?;
    db.execute(
        "INSERT INTO watch_specs VALUES (?1,?2,?3,?4,?5,?6,1,?7)",
        params![
            spec.host_id,
            spec.id,
            spec.version,
            spec.incident_id,
            serde_json::to_string(spec)?,
            actor,
            stamp(now)
        ],
    )?;
    db.execute(
        "INSERT INTO watch_state (host_id,watch_id,spec_version) VALUES (?1,?2,?3)",
        params![spec.host_id, spec.id, spec.version],
    )?;
    Ok(())
}

pub(crate) fn list_hosts(db: &Connection) -> Result<Vec<HostSummary>> {
    rows(
        db,
        "SELECT host_id,agent_version,liveness_status,active_bundle_version,last_heartbeat_at FROM hosts ORDER BY host_id",
        [],
        |r| {
            Ok(HostSummary {
                host_id: r.get(0)?,
                agent_version: r.get(1)?,
                liveness_status: r.get(2)?,
                active_bundle_version: r.get(3)?,
                last_heartbeat_at: r
                    .get::<_, Option<String>>(4)?
                    .map(|value| parse_stamp(&value, 4))
                    .transpose()?,
            })
        },
    )
}

fn incident_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<IncidentSummary> {
    Ok(IncidentSummary {
        incident_id: r.get(0)?,
        host_id: r.get(1)?,
        status: r.get(2)?,
        priority: json_column(r, 3)?,
        summary: r.get(4)?,
        created_at: parse_stamp(&r.get::<_, String>(5)?, 5)?,
        updated_at: parse_stamp(&r.get::<_, String>(6)?, 6)?,
    })
}

pub(crate) fn list_incidents(db: &Connection) -> Result<Vec<IncidentSummary>> {
    rows(
        db,
        "SELECT incident_id,host_id,status,priority_json,summary,created_at,updated_at FROM incidents ORDER BY updated_at DESC,incident_id",
        [],
        incident_row,
    )
}

pub(crate) fn get_incident(db: &Connection, id: &str) -> Result<IncidentSummary> {
    db.query_row("SELECT incident_id,host_id,status,priority_json,summary,created_at,updated_at FROM incidents WHERE incident_id=?1",
        [id], incident_row).optional()?.ok_or_else(|| ControlError::missing("incident does not exist"))
}

pub(crate) fn record_decision(
    db: &Connection,
    proposal: Option<i64>,
    actor: &str,
    request: &str,
    decision: &PolicyDecision,
    context: serde_json::Value,
    now: DateTime<Utc>,
) -> Result<()> {
    db.execute("INSERT INTO policy_decisions (proposal_id,actor,request_id,decision_json,created_at) VALUES (?1,?2,?3,?4,?5)",
        params![proposal,actor,request,serde_json::to_string(decision)?,stamp(now)])?;
    audit(
        db,
        PolicyDecisionAudited,
        actor,
        request,
        json!({"proposal_id":proposal,"decision":decision,"context":context}),
    )
}

pub(crate) fn parse_stamp(value: &str, index: usize) -> rusqlite::Result<DateTime<Utc>> {
    value.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}
