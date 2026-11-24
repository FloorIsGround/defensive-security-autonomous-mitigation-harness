use std::{fs, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};
use defsec_protocol::{
    rpc::{AdminRequest, AdminResponse, PrincipalRole},
    watch::CollectorType,
    wire::{read_frame, write_frame},
};
use tokio::net::UnixStream;

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
    },
    CloseIncident {
        incident_id: String,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        resolution: String,
    },
    ListHosts,
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
            } => AdminRequest::MintCapabilityToken {
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
            Self::ListHosts => AdminRequest::ListHosts,
            Self::ListIncidents => AdminRequest::ListIncidents,
            Self::VerifyAudit => AdminRequest::VerifyAuditChain,
        })
    }
}

async fn run(args: Args) -> Result<AdminResponse, Box<dyn std::error::Error>> {
    let request = args.command.into_request()?;
    let mut socket = UnixStream::connect(args.admin_sock).await?;
    write_frame(&mut socket, &request).await?;
    Ok(read_frame(&mut socket)
        .await?
        .ok_or("control daemon closed the socket without a response")?)
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = run(Args::parse()).await.and_then(|response| {
        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(matches!(
            response,
            AdminResponse::Error { .. } | AdminResponse::AuditChainStatus { valid: false, .. }
        ))
    });
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
    fn parses_scoped_token_and_global_socket() {
        let args = Args::try_parse_from([
            "admin-cli",
            "mint-token",
            "user",
            "--role",
            "investigator",
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
