use std::{future::pending, net::SocketAddr, path::PathBuf, time::Duration};

use chrono::Utc;
use clap::Parser;
use control_d::{
    ControlService,
    server::{MtlsAgentServer, SocketPolicy, UnixServer},
};
use defsec_mtls::MtlsAcceptor;
use defsec_policy::{action_gate::ActionSafetyConfig, control_gate::ControlPolicyConfig};

#[derive(Parser)]
#[command(about = "DefSecAutMit control daemon")]
struct Args {
    #[arg(long, default_value = "./control-data")]
    data_dir: PathBuf,
    #[arg(long)]
    agent_sock: Option<PathBuf>,
    /// Also accept outbound agents on this mTLS TCP address.
    #[arg(long, requires_all = ["tls_ca_cert", "tls_server_cert", "tls_server_key"])]
    agent_mtls_addr: Option<SocketAddr>,
    #[arg(long, requires = "agent_mtls_addr")]
    tls_ca_cert: Option<PathBuf>,
    #[arg(long, requires = "agent_mtls_addr")]
    tls_server_cert: Option<PathBuf>,
    #[arg(long, requires = "agent_mtls_addr")]
    tls_server_key: Option<PathBuf>,
    /// Revocation JSON file. Defaults to revoked_serials.json in the data directory.
    #[arg(long, requires = "agent_mtls_addr")]
    tls_revoked_file: Option<PathBuf>,
    /// Seconds of silence before a host is marked offline. Use 0 to disable.
    #[arg(long, default_value_t = 90)]
    liveness_grace_seconds: u64,
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

async fn watch_liveness(service: ControlService, grace_seconds: u64) {
    let period = Duration::from_secs((grace_seconds / 3).clamp(1, 15));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let service = service.clone();
        match tokio::task::spawn_blocking(move || {
            service.sweep_stale_hosts(Utc::now(), grace_seconds)
        })
        .await
        {
            Ok(Ok(hosts)) => {
                for host_id in hosts {
                    tracing::warn!(%host_id, "agent heartbeat grace window exceeded");
                }
            }
            Ok(Err(error)) => tracing::error!(%error, "host liveness sweep failed"),
            Err(error) => tracing::error!(%error, "host liveness sweep task failed"),
        }
    }
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
    let mtls = if let Some(addr) = args.agent_mtls_addr {
        let acceptor = MtlsAcceptor::from_pem_files(
            args.tls_ca_cert.expect("clap requires --tls-ca-cert"),
            args.tls_server_cert
                .expect("clap requires --tls-server-cert"),
            args.tls_server_key.expect("clap requires --tls-server-key"),
            Some(
                args.tls_revoked_file
                    .unwrap_or_else(|| args.data_dir.join("revoked_serials.json")),
            ),
        )?;
        Some(MtlsAgentServer::bind(addr, acceptor).await?)
    } else {
        None
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    if args.liveness_grace_seconds > 0 {
        tokio::spawn(watch_liveness(service.clone(), args.liveness_grace_seconds));
    }
    tokio::select! {
        result = agent.serve_agent(service.clone()) => result?,
        result = admin.serve_admin(service.clone()) => result?,
        result = investigation.serve_investigation(service.clone()) => result?,
        result = async {
            match mtls {
                Some(server) => server.serve_agent(service).await,
                None => pending().await,
            }
        } => result?,
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}
