use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand, ValueEnum};
use defsec_policy::edge_floor::is_valid_identifier;
use defsec_protocol::{
    action::ActionIntentStatus,
    rpc::{AdminRequest, AdminResponse, PrincipalRole},
    signing::{DOMAIN_ACTION_APPROVAL_V1, SigningKeyPair},
    watch::CollectorType,
    wire::{read_frame, write_frame},
};
use tokio::net::UnixStream;

mod pki;
mod role_profiles;
use pki::PkiCommand;
use role_profiles::ProfileRole;

#[derive(Parser)]
#[command(about = "DefSecAutMit operator CLI")]
struct Args {
    #[arg(long, global = true, default_value = "./control-data/admin.sock")]
    admin_sock: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Pki(PkiCommand),
    Enroll {
        host_id: String,
        #[arg(long)]
        agent_public_key_hex: Option<String>,
    },
    ApplyWatch {
        file: PathBuf,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        rationale: String,
    },
    /// Print a host profile JSON document to install on the agent.
    ProfileTemplate {
        #[arg(long, value_enum)]
        role: ProfileRole,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long = "expected-service")]
        expected_services: Vec<String>,
    },
    /// Apply one baseline watch per collector in a role.
    ApplyProfile {
        #[arg(long)]
        host: String,
        #[arg(long, value_enum)]
        role: ProfileRole,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "operator")]
        actor: String,
    },
    PromoteBaseline {
        host_id: String,
        watch_id: String,
        observation_id: i64,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        rationale: String,
        #[arg(long)]
        ticket_ref: Option<String>,
    },
    MintToken {
        principal_id: String,
        #[arg(long, value_enum)]
        role: Role,
        #[arg(long = "host", required = true)]
        allowed_hosts: Vec<String>,
        #[arg(long = "collector", value_parser = parse_collector)]
        allowed_collectors: Vec<CollectorType>,
        #[arg(long)]
        incident_id: Option<String>,
        #[arg(long, default_value_t = 3600)]
        ttl_seconds: u64,
        #[arg(long)]
        allow_run_spawn: bool,
    },
    CloseIncident {
        incident_id: String,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        resolution: String,
    },
    GenerateOperatorKey {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        out: PathBuf,
    },
    ListActions {
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        incident_id: Option<String>,
    },
    GetAction {
        intent_id: String,
    },
    ApproveAction {
        intent_id: String,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        operator_key_file: PathBuf,
        #[arg(long)]
        operator_key_id: String,
    },
    RecordReceipt {
        receipt_json_file: PathBuf,
    },
    ListRules {
        #[arg(long = "host")]
        host_id: Option<String>,
        #[arg(long = "status")]
        statuses: Vec<String>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        before: Option<String>,
    },
    CreateRule {
        rule_json_file: PathBuf,
        #[arg(long)]
        actor: String,
    },
    DecideRule {
        rule_id: String,
        #[arg(long, conflicts_with = "reject", required_unless_present = "reject")]
        approve: bool,
        #[arg(long, conflicts_with = "approve", required_unless_present = "approve")]
        reject: bool,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        note: Option<String>,
    },
    RevokeRule {
        rule_id: String,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        reason: String,
    },
    BacktestRule {
        rule_json_file: PathBuf,
    },
    ListHosts {
        #[arg(long)]
        tag: Option<String>,
    },
    ListIncidents,
    VerifyAudit,
}

#[derive(Clone, ValueEnum)]
enum Role {
    Observer,
    Investigator,
}

fn parse_collector(value: &str) -> Result<CollectorType, String> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(|e| e.to_string())
}

impl Command {
    fn into_request(self) -> Result<AdminRequest, Box<dyn std::error::Error>> {
        Ok(match self {
            Self::Enroll {
                host_id,
                agent_public_key_hex,
            } => AdminRequest::EnrollHost {
                host_id,
                agent_public_key_hex,
            },
            Self::ApplyWatch {
                file,
                actor,
                rationale,
            } => AdminRequest::ApplyBaselineWatch {
                spec: serde_json::from_slice(&fs::read(file)?)?,
                actor,
                rationale,
            },
            Self::PromoteBaseline {
                host_id,
                watch_id,
                observation_id,
                approver,
                rationale,
                ticket_ref,
            } => AdminRequest::PromoteBaseline {
                host_id,
                watch_id,
                observation_id,
                approver,
                rationale,
                ticket_ref,
            },
            Self::MintToken {
                principal_id,
                role,
                allowed_hosts,
                allowed_collectors,
                incident_id,
                ttl_seconds,
                allow_run_spawn,
            } => AdminRequest::MintCapabilityToken {
                may_spawn_runs: allow_run_spawn,
                principal_id,
                role: match role {
                    Role::Observer => PrincipalRole::Observer,
                    Role::Investigator => PrincipalRole::Investigator,
                },
                allowed_hosts,
                allowed_collectors,
                incident_id,
                ttl_seconds,
            },
            Self::CloseIncident {
                incident_id,
                actor,
                resolution,
            } => AdminRequest::CloseIncident {
                incident_id,
                actor,
                resolution,
            },
            Self::ListActions {
                host_id,
                incident_id,
            } => AdminRequest::ListActions {
                host_id,
                incident_id,
            },
            Self::GetAction { intent_id } => AdminRequest::GetActionIntent { intent_id },
            Self::RecordReceipt { receipt_json_file } => AdminRequest::RecordActionReceipt {
                receipt: serde_json::from_slice(&fs::read(receipt_json_file)?)?,
            },
            Self::GenerateOperatorKey { .. } | Self::ApproveAction { .. } => {
                return Err("command requires local operator key handling".into());
            }
            Self::Pki(_) => return Err("PKI commands operate on local files".into()),
            Self::ListRules {
                host_id,
                statuses,
                limit,
                before,
            } => AdminRequest::ListExpectationRules {
                host_id,
                statuses: (!statuses.is_empty()).then_some(statuses),
                limit,
                before,
            },
            Self::CreateRule {
                rule_json_file,
                actor,
            } => AdminRequest::CreateExpectationRule {
                rule: serde_json::from_slice(&fs::read(rule_json_file)?)?,
                actor,
            },
            Self::DecideRule {
                rule_id,
                approve,
                actor,
                note,
                ..
            } => AdminRequest::DecideExpectationRule {
                rule_id,
                approve,
                actor,
                note,
            },
            Self::RevokeRule {
                rule_id,
                actor,
                reason,
            } => AdminRequest::RevokeExpectationRule {
                rule_id,
                actor,
                reason,
            },
            Self::BacktestRule { rule_json_file } => AdminRequest::BacktestExpectationRule {
                rule: serde_json::from_slice(&fs::read(rule_json_file)?)?,
            },
            Self::ListHosts { tag } => AdminRequest::ListHosts { tag },
            Self::ProfileTemplate { .. } | Self::ApplyProfile { .. } => {
                return Err("profile commands require local template handling".into());
            }
            Self::ListIncidents => AdminRequest::ListIncidents,
            Self::VerifyAudit => AdminRequest::VerifyAuditChain,
        })
    }
}

fn generate_operator_key(
    key_id: &str,
    out: &Path,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if !is_valid_identifier(key_id) {
        return Err("invalid operator key ID".into());
    }
    let key = SigningKeyPair::generate(key_id);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(key.secret_hex().as_bytes())?;
    file.sync_all()?;
    Ok(serde_json::json!({"key_id": key.key_id(), "public_hex": key.public_hex()}))
}

fn load_operator_key(
    key_id: &str,
    path: &Path,
) -> Result<SigningKeyPair, Box<dyn std::error::Error>> {
    let check_permissions = |meta: fs::Metadata| {
        if meta.is_file() && meta.permissions().mode() & 0o777 == 0o600 {
            Ok(())
        } else {
            Err("operator key must be a regular file with mode 0600")
        }
    };
    check_permissions(fs::symlink_metadata(path)?)?;
    let file = File::open(path)?;
    check_permissions(file.metadata()?)?;
    let mut secret = String::new();
    file.take(65).read_to_string(&mut secret)?;
    Ok(SigningKeyPair::from_secret_hex(key_id, &secret)?)
}

async fn exchange(
    socket: &mut UnixStream,
    request: AdminRequest,
) -> Result<AdminResponse, Box<dyn std::error::Error>> {
    write_frame(socket, &request).await?;
    Ok(read_frame(socket)
        .await?
        .ok_or("control daemon closed the socket without a response")?)
}

async fn run(args: Args) -> Result<bool, Box<dyn std::error::Error>> {
    let response = match args.command {
        Command::Pki(command) => {
            println!("{}", serde_json::to_string_pretty(&command.run()?)?);
            return Ok(false);
        }
        Command::ProfileTemplate {
            role,
            tags,
            expected_services,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&role.profile(tags, expected_services)?)?
            );
            return Ok(false);
        }
        Command::ApplyProfile {
            host,
            role,
            dry_run,
            actor,
        } => {
            if !is_valid_identifier(&host) {
                return Err("invalid host ID".into());
            }
            let specs = role.specs(&host);
            if dry_run {
                println!("{}", serde_json::to_string_pretty(&specs)?);
                return Ok(false);
            }

            let mut socket = UnixStream::connect(args.admin_sock).await?;
            let role_name = role.to_possible_value().expect("named profile role");
            let rationale = format!("apply {} role profile", role_name.get_name());
            let mut responses = Vec::with_capacity(specs.len());
            for spec in specs {
                let watch_id = spec.id.clone();
                let response = exchange(
                    &mut socket,
                    AdminRequest::ApplyBaselineWatch {
                        spec,
                        actor: actor.clone(),
                        rationale: rationale.clone(),
                    },
                )
                .await;
                match response {
                    Ok(response @ AdminResponse::WatchApplied { .. }) => responses.push(response),
                    Ok(response @ AdminResponse::Error { .. }) => {
                        responses.push(response);
                        println!("{}", serde_json::to_string_pretty(&responses)?);
                        return Ok(true);
                    }
                    other => {
                        println!("{}", serde_json::to_string_pretty(&responses)?);
                        let detail = match other {
                            Err(error) => error.to_string(),
                            Ok(_) => "unexpected response".into(),
                        };
                        return Err(format!("{watch_id}: {detail}").into());
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&responses)?);
            return Ok(false);
        }
        Command::GenerateOperatorKey { key_id, out } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&generate_operator_key(&key_id, &out)?)?
            );
            return Ok(false);
        }
        Command::ApproveAction {
            intent_id,
            approver,
            operator_key_file,
            operator_key_id,
        } => {
            let mut socket = UnixStream::connect(args.admin_sock).await?;
            let detail = exchange(
                &mut socket,
                AdminRequest::GetActionIntent {
                    intent_id: intent_id.clone(),
                },
            )
            .await?;
            match detail {
                AdminResponse::Error { .. } => detail,
                AdminResponse::ActionIntentDetail {
                    payload,
                    status: ActionIntentStatus::PendingApproval,
                    ..
                } if payload.intent_id == intent_id => {
                    let key = load_operator_key(&operator_key_id, &operator_key_file)?;
                    let operator_approval =
                        key.sign_payload(DOMAIN_ACTION_APPROVAL_V1, &payload)?;
                    exchange(
                        &mut socket,
                        AdminRequest::ApproveAction {
                            intent_id,
                            approver,
                            operator_approval,
                        },
                    )
                    .await?
                }
                _ => {
                    return Err(
                        "control daemon did not return the requested pending action intent".into(),
                    );
                }
            }
        }
        command => {
            let request = command.into_request()?;
            let mut socket = UnixStream::connect(args.admin_sock).await?;
            exchange(&mut socket, request).await?
        }
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(matches!(
        response,
        AdminResponse::Error { .. } | AdminResponse::AuditChainStatus { valid: false, .. }
    ))
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = run(Args::parse()).await;
    match result {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_decisions_require_exactly_one_choice_and_list_status_flags_repeat() {
        let parse = |args: &[&str]| {
            Args::try_parse_from(std::iter::once("admin-cli").chain(args.iter().copied()))
        };
        assert!(parse(&["decide-rule", "rule-1", "--actor", "operator"]).is_err());
        assert!(
            parse(&[
                "decide-rule",
                "rule-1",
                "--actor",
                "operator",
                "--approve",
                "--reject"
            ])
            .is_err()
        );
        for (flag, approve) in [("--approve", true), ("--reject", false)] {
            let request = parse(&["decide-rule", "rule-1", "--actor", "operator", flag])
                .unwrap()
                .command
                .into_request()
                .unwrap();
            assert_eq!(
                request,
                AdminRequest::DecideExpectationRule {
                    rule_id: "rule-1".into(),
                    approve,
                    actor: "operator".into(),
                    note: None,
                }
            );
        }

        let request = parse(&[
            "list-rules",
            "--host",
            "edge",
            "--status",
            "proposed",
            "--status",
            "active",
        ])
        .unwrap()
        .command
        .into_request()
        .unwrap();
        assert_eq!(
            request,
            AdminRequest::ListExpectationRules {
                host_id: Some("edge".into()),
                statuses: Some(vec!["proposed".into(), "active".into()]),
                limit: None,
                before: None,
            }
        );
    }

    #[test]
    fn parses_action_commands() {
        let parse = |args: &[&str]| {
            Args::try_parse_from(std::iter::once("admin-cli").chain(args.iter().copied()))
                .unwrap()
                .command
        };
        assert!(matches!(
            parse(&["generate-operator-key", "--key-id", "operator", "--out", "key.hex"]),
            Command::GenerateOperatorKey { key_id, out }
                if key_id == "operator" && out == Path::new("key.hex")
        ));
        assert_eq!(
            parse(&[
                "list-actions",
                "--host-id",
                "edge",
                "--incident-id",
                "incident"
            ])
            .into_request()
            .unwrap(),
            AdminRequest::ListActions {
                host_id: Some("edge".into()),
                incident_id: Some("incident".into())
            }
        );
        assert_eq!(
            parse(&["list-actions"]).into_request().unwrap(),
            AdminRequest::ListActions {
                host_id: None,
                incident_id: None
            }
        );
        assert_eq!(
            parse(&["get-action", "intent"]).into_request().unwrap(),
            AdminRequest::GetActionIntent {
                intent_id: "intent".into()
            }
        );
        assert!(matches!(
            parse(&["approve-action", "intent", "--approver", "Alice", "--operator-key-file",
                "key.hex", "--operator-key-id", "operator"]),
            Command::ApproveAction { intent_id, approver, operator_key_file, operator_key_id }
                if intent_id == "intent" && approver == "Alice" && operator_key_id == "operator"
                && operator_key_file == Path::new("key.hex")
        ));
        assert!(matches!(
            parse(&["record-receipt", "receipt.json"]),
            Command::RecordReceipt { receipt_json_file } if receipt_json_file == Path::new("receipt.json")
        ));
        assert!(
            Args::try_parse_from([
                "admin-cli",
                "approve-action",
                "intent",
                "--approver",
                "Alice"
            ])
            .is_err()
        );
        assert!(
            Args::try_parse_from(["admin-cli", "generate-operator-key", "--key-id", "operator"])
                .is_err()
        );
    }

    #[tokio::test]
    async fn generates_private_operator_key_without_connecting() {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let dir = std::env::temp_dir().join(format!("d-{}", &id[..8]));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("operator.hex");
        let args = Args {
            admin_sock: dir.join("missing.sock"),
            command: Command::GenerateOperatorKey {
                key_id: "operator".into(),
                out: path.clone(),
            },
        };
        let result = run(args).await;
        let permissions = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let key = load_operator_key("operator", &path).unwrap();
        let overwrite = generate_operator_key("operator", &path);
        let remaining_key = load_operator_key("operator", &path).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert!(!result.unwrap());
        assert_eq!(permissions, 0o600);
        assert!(overwrite.is_err());
        assert_eq!(remaining_key.public_hex(), key.public_hex());
    }

    #[tokio::test]
    async fn approval_signs_the_pending_payload_locally() {
        use chrono::{Duration, Utc};
        use defsec_protocol::{
            action::{
                ACTION_INTENT_SCHEMA_VERSION, ActionAuthMode, ActionIntentPayload, ActionVerb,
            },
            signing::{DOMAIN_ACTION_INTENT_V1, VerifyingKeyStore},
        };
        use tokio::net::UnixListener;

        let id = uuid::Uuid::new_v4().simple().to_string();
        let dir = std::env::temp_dir().join(format!("d-{}", &id[..8]));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("operator.hex");
        let public = generate_operator_key("operator", &path).unwrap();
        let mut trust = VerifyingKeyStore::new();
        trust
            .insert_public_hex("operator", public["public_hex"].as_str().unwrap())
            .unwrap();
        let admin_sock = dir.join("admin.sock");
        let listener = UnixListener::bind(&admin_sock).unwrap();
        let now = Utc::now();
        let payload = ActionIntentPayload {
            schema_version: ACTION_INTENT_SCHEMA_VERSION,
            intent_id: "intent".into(),
            nonce: "nonce".into(),
            host_id: "edge".into(),
            incident_id: "incident".into(),
            proposal_id: 7,
            auth_mode: ActionAuthMode::DualSignedOperator,
            verb: ActionVerb::HostIsolate {
                preserve_mgmt_cidrs: vec!["10.0.0.0/24".into()],
                ttl_seconds: 60,
            },
            policy_version: 1,
            issued_at: now,
            expires_at: now + Duration::seconds(60),
            rollback_plan: "Restore connectivity".into(),
            evidence_observation_ids: vec![9],
        };
        let control_envelope = SigningKeyPair::generate("control")
            .sign_payload(DOMAIN_ACTION_INTENT_V1, &payload)
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            assert_eq!(
                read_frame(&mut socket).await.unwrap(),
                Some(AdminRequest::GetActionIntent {
                    intent_id: payload.intent_id.clone()
                })
            );
            write_frame(
                &mut socket,
                &AdminResponse::ActionIntentDetail {
                    payload: payload.clone(),
                    authorized_intent: None,
                    status: ActionIntentStatus::PendingApproval,
                },
            )
            .await
            .unwrap();
            let Some(AdminRequest::ApproveAction {
                intent_id,
                approver,
                operator_approval,
            }) = read_frame(&mut socket).await.unwrap()
            else {
                panic!("missing approval")
            };
            assert_eq!(intent_id, payload.intent_id);
            assert_eq!(approver, "Alice");
            assert_eq!(operator_approval.raw_payload, control_envelope.raw_payload);
            let (signed, _) = trust
                .verify_and_decode::<ActionIntentPayload>(
                    DOMAIN_ACTION_APPROVAL_V1,
                    &operator_approval,
                )
                .unwrap();
            assert_eq!(signed, payload);
            write_frame(
                &mut socket,
                &AdminResponse::ActionApproved {
                    intent_id,
                    authorized_intent: defsec_protocol::action::AuthorizedActionIntent {
                        control_envelope,
                        operator_approval: Some(operator_approval),
                    },
                },
            )
            .await
            .unwrap();
        });
        let result = run(Args {
            admin_sock,
            command: Command::ApproveAction {
                intent_id: "intent".into(),
                approver: "Alice".into(),
                operator_key_file: path,
                operator_key_id: "operator".into(),
            },
        })
        .await;
        let server_result = server.await;
        fs::remove_dir_all(&dir).unwrap();
        assert!(!result.unwrap());
        server_result.unwrap();
    }

    #[test]
    fn parses_scoped_token_and_global_socket() {
        let args = Args::try_parse_from([
            "admin-cli",
            "mint-token",
            "user",
            "--role",
            "investigator",
            "--allow-run-spawn",
            "--host",
            "edge",
            "--host",
            "edge2",
            "--collector",
            "files.metadata",
            "--incident-id",
            "inc",
            "--ttl-seconds",
            "60",
            "--admin-sock",
            "/tmp/operator.sock",
        ])
        .unwrap();
        assert_eq!(args.admin_sock, PathBuf::from("/tmp/operator.sock"));
        assert_eq!(
            args.command.into_request().unwrap(),
            AdminRequest::MintCapabilityToken {
                may_spawn_runs: true,
                principal_id: "user".into(),
                role: PrincipalRole::Investigator,
                allowed_hosts: vec!["edge".into(), "edge2".into()],
                allowed_collectors: vec![CollectorType::FilesMetadata],
                incident_id: Some("inc".into()),
                ttl_seconds: 60
            }
        );
        assert!(
            Args::try_parse_from([
                "admin-cli",
                "mint-token",
                "user",
                "--role",
                "admin",
                "--host",
                "edge"
            ])
            .is_err()
        );
        assert!(
            Args::try_parse_from([
                "admin-cli",
                "apply-watch",
                "watch.json",
                "--actor",
                "operator"
            ])
            .is_err()
        );
    }
}
