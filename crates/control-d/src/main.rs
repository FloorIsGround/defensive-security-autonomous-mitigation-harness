use std::path::PathBuf;

use clap::Parser;
use control_d::{
    ControlService,
    server::{SocketPolicy, UnixServer},
};

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
    let service = ControlService::open(&args.data_dir, args.key_id, args.policy_version)?;
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
