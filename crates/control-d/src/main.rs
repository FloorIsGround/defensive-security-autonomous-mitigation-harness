use std::path::PathBuf;

use clap::Parser;
use control_d::{
    ControlService,
    server::{SocketPolicy, UnixServer},
};
use defsec_policy::{action_gate::ActionSafetyConfig, control_gate::ControlPolicyConfig};

#[derive(Parser)]
#[command(about = "DefSecAutMit control daemon")]
struct Args {
    #[arg(long, default_value = "./control-data")]
    data_dir: PathBuf,
    #[arg(long)]
    agent_sock: Option<PathBuf>,
    #[arg(long)]
    admin_sock: Option<PathBuf>,
    #[arg(long)]
    investigate_sock: Option<PathBuf>,
    #[arg(long, default_value = "control-key-01")]
    key_id: String,
    #[arg(long, default_value_t = 1)]
    policy_version: u32,
    /// Enable reversible, time-bounded autonomous containment.
    #[arg(long)]
    enable_autonomous_containment: bool,
    /// Trusted operator signing key ID.
    #[arg(long, requires = "operator_pub_hex")]
    operator_key_id: Option<String>,
    /// Trusted operator Ed25519 public key in hex.
    #[arg(long, requires = "operator_key_id")]
    operator_pub_hex: Option<String>,
    /// Octal filesystem mode applied to the local sockets.
    #[arg(long, default_value = "0600", value_parser = parse_socket_mode)]
    socket_mode: u32,
    /// Allow an agent peer UID. Repeat to allow several UIDs.
    #[arg(long)]
    agent_uid: Vec<u32>,
    /// Allow an operator peer UID. Repeat to allow several UIDs.
    #[arg(long)]
    admin_uid: Vec<u32>,
    /// Allow an investigation peer UID. Repeat to allow several UIDs.
    #[arg(long)]
    investigate_uid: Vec<u32>,
}

fn parse_socket_mode(raw: &str) -> Result<u32, String> {
    u32::from_str_radix(raw, 8)
        .ok()
        .filter(|mode| *mode <= 0o777)
        .ok_or_else(|| "expected an octal mode between 0000 and 0777".into())
}

fn socket_policy(mode: u32, allowed_uids: Vec<u32>) -> SocketPolicy {
    let allowed_uids = if allowed_uids.is_empty() {
        SocketPolicy::default().allowed_uids
    } else {
        allowed_uids
    };
    SocketPolicy { mode, allowed_uids }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let policy = ControlPolicyConfig {
        policy_version: args.policy_version,
        ..Default::default()
    };
    let mut action_safety = if args.enable_autonomous_containment {
        ActionSafetyConfig::with_bounded_autonomous_containment()
    } else {
        ActionSafetyConfig::default()
    };
    action_safety.expected_policy_version = args.policy_version;
    let service =
        ControlService::open_with_policies(&args.data_dir, args.key_id, policy, action_safety)?;
    if let (Some(id), Some(public_hex)) = (args.operator_key_id, args.operator_pub_hex) {
        service.register_operator_key(id, &public_hex)?;
    }
    let agent = UnixServer::bind(
        args.agent_sock
            .unwrap_or_else(|| args.data_dir.join("agent.sock")),
        socket_policy(args.socket_mode, args.agent_uid),
    )?;
    let admin = UnixServer::bind(
        args.admin_sock
            .unwrap_or_else(|| args.data_dir.join("admin.sock")),
        socket_policy(args.socket_mode, args.admin_uid),
    )?;
    let investigation = UnixServer::bind(
        args.investigate_sock
            .unwrap_or_else(|| args.data_dir.join("investigate.sock")),
        socket_policy(args.socket_mode, args.investigate_uid),
    )?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = agent.serve_agent(service.clone()) => result?,
        result = admin.serve_admin(service.clone()) => result?,
        result = investigation.serve_investigation(service) => result?,
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}
