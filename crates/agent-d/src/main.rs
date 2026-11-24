//! `agent-d` binary entrypoint: single-threaded Tokio runtime, clap CLI,
//! UDS connection to `control-d`'s `agent.sock` with bounded exponential
//! reconnect jitter, and a unified select loop that runs scheduled watches,
//! pumps spooled observations, and handles incoming control frames —
//! including while disconnected (observations spool for later delivery).

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::signing::VerifyingKeyStore;
use defsec_protocol::wire::{read_frame, write_frame, AgentToControl, ControlToAgent, WireError};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{Instant, MissedTickBehavior};

use agent_d::collectors::RealLinuxCollectors;
use agent_d::engine::AgentEngine;
use agent_d::spool::DurabilityProfile;

const MIN_HEARTBEAT_SECONDS: u64 = 5;
const RECONNECT_BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_CEILING: Duration = Duration::from_secs(30);
const MAX_RECONNECT_JITTER: u64 = 1500; // milliseconds

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DurabilityArg {
    Minimal,
    Durable,
}

#[derive(Debug, Parser)]
#[command(name = "agent-d", version, about = "DefSecAutMit edge agent")]
struct Args {
    /// Local host identity this agent is enrolled under.
    #[arg(long)]
    host_id: String,

    /// Local state directory for the bundle cache, spool, and cursors.
    #[arg(long, default_value = "/var/lib/defsecautmit/agent-d")]
    state_dir: PathBuf,

    /// Path to `control-d`'s agent socket.
    #[arg(long, default_value = "/run/defsecautmit/control-d/agent.sock")]
    control_sock: PathBuf,

    /// Signing key id the control plane uses for watch bundles.
    #[arg(long)]
    control_key_id: String,

    /// Ed25519 public key (hex) of the control signing key.
    #[arg(long)]
    control_pub_hex: String,

    /// Spool durability profile.
    #[arg(long, value_enum, default_value = "durable")]
    durability: DurabilityArg,

    /// Heartbeat period in seconds.
    #[arg(long, default_value = "30")]
    heartbeat_seconds: u64,

    /// RAM spool ceiling for the minimal profile.
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    max_ram_bytes: usize,

    /// Disk spool ceiling for the durable profile.
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    max_disk_bytes: usize,
}

/// Bounded, deterministic reconnect jitter derived from the session id and
/// the attempt counter (no RNG dependency on constrained edge nodes).
fn reconnect_jitter(session_id: &str, attempt: u64) -> Duration {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(&attempt.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let n = u64::from_be_bytes(digest[0..8].try_into().unwrap());
    Duration::from_millis(n % MAX_RECONNECT_JITTER)
}

async fn send_messages(
    writer: &mut OwnedWriteHalf,
    msgs: Vec<AgentToControl>,
) -> Result<(), WireError> {
    for msg in msgs {
        write_frame(writer, &msg).await?;
    }
    Ok(())
}

async fn setup(
    args: &Args,
) -> Result<AgentEngine<RealLinuxCollectors>, Box<dyn std::error::Error>> {
    // Trust store: strictly the pre-provisioned control signing key.
    let mut store = VerifyingKeyStore::new();
    store.insert_public_hex(&args.control_key_id, &args.control_pub_hex)?;

    let durability = match args.durability {
        DurabilityArg::Minimal => DurabilityProfile::Minimal {
            max_ram_bytes: args.max_ram_bytes,
        },
        DurabilityArg::Durable => DurabilityProfile::Durable {
            max_disk_bytes: args.max_disk_bytes,
        },
    };

    // MVP: the local safety floor uses its reviewed defaults. A separate
    // trusted administrative path (never the signed bundle) owns this config.
    let cfg = EdgeSafetyConfig::default();
    let collector = std::sync::Arc::new(RealLinuxCollectors::new());
    let engine = AgentEngine::new(
        cfg,
        args.host_id.clone(),
        durability,
        args.state_dir.clone(),
        store,
        collector,
    )?;
    Ok(engine)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut engine = setup(&args).await?;
    tracing::info!(
        host_id = %args.host_id,
        session_id = %engine.session_id(),
        boot_id = %engine.boot_id(),
        bundle_version = engine.active_bundle_version(),
        stale = engine.stale_desired_state(),
        "agent-d started"
    );

    let heartbeat_dur = Duration::from_secs(args.heartbeat_seconds.max(MIN_HEARTBEAT_SECONDS));
    main_loop(&mut engine, &args, heartbeat_dur).await
}

async fn main_loop(
    engine: &mut AgentEngine<RealLinuxCollectors>,
    args: &Args,
    heartbeat_dur: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    struct Connection {
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
    }

    let mut backoff = RECONNECT_BACKOFF_FLOOR;
    let mut reconnect_attempts: u64 = 0;
    let mut next_reconnect_at: Option<Instant> = None;
    let mut connection: Option<Connection> = None;
    let mut next_heartbeat = Instant::now() + heartbeat_dur;

    // Coarse 1s driver: watch deadlines are >= 15s, heartbeats >= 5s.
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        // (Re)connect when due.
        if connection.is_none()
            && next_reconnect_at
                .map(|t| Instant::now() >= t)
                .unwrap_or(true)
        {
            match tokio::net::UnixStream::connect(&args.control_sock).await {
                Ok(stream) => {
                    let (reader, mut writer) = stream.into_split();
                    tracing::info!(sock = %args.control_sock.display(), "connected to control-d");
                    let register = engine.make_register(chrono::Utc::now());
                    send_messages(&mut writer, vec![register]).await?;
                    // Retransmit pending spooled observations until durable
                    // acknowledgment.
                    let pending: Vec<AgentToControl> = engine
                        .pending_observations()
                        .into_iter()
                        .map(|o| AgentToControl::PushObservationDelta { observation: o })
                        .collect();
                    if !pending.is_empty() {
                        tracing::info!(count = pending.len(), "flushing spooled observations");
                    }
                    send_messages(&mut writer, pending).await?;
                    connection = Some(Connection { reader, writer });
                    backoff = RECONNECT_BACKOFF_FLOOR;
                    reconnect_attempts = 0;
                    next_heartbeat = Instant::now() + heartbeat_dur;
                }
                Err(e) => {
                    reconnect_attempts += 1;
                    let jitter = reconnect_jitter(engine.session_id(), reconnect_attempts);
                    next_reconnect_at = Some(Instant::now() + backoff + jitter);
                    tracing::warn!(
                        error = %e,
                        backoff_ms = (backoff + jitter).as_millis() as u64,
                        attempt = reconnect_attempts,
                        "control socket connect failed; will retry"
                    );
                    backoff = std::cmp::min(backoff * 2, RECONNECT_BACKOFF_CEILING);
                }
            }
        }

        let read_result = tokio::select! {
            _ = ticker.tick() => {
                let now = chrono::Utc::now();
                // Run scheduled watches — also while disconnected: pending
                // observations accumulate in the bounded spool.
                let outgoing = engine.run_due_watches(now).await;
                if let Some(conn) = connection.as_mut() {
                    if let Err(e) = send_messages(&mut conn.writer, outgoing).await {
                        tracing::warn!(error = %e, "socket write failed; reconnecting");
                        connection = None;
                        next_reconnect_at = Some(Instant::now() + backoff);
                    }
                }
                // Periodic heartbeat with per-watch run summaries + RSS.
                if Instant::now() >= next_heartbeat {
                    let heartbeat = engine.make_heartbeat(now);
                    if let Some(conn) = connection.as_mut() {
                        match send_messages(&mut conn.writer, vec![heartbeat]).await {
                            Ok(()) => next_heartbeat = Instant::now() + heartbeat_dur,
                            Err(e) => {
                                tracing::warn!(error = %e, "heartbeat write failed; reconnecting");
                                connection = None;
                                next_reconnect_at = Some(Instant::now() + backoff);
                            }
                        }
                    }
                }
                continue;
            }
            frame = async {
                match connection.as_mut() {
                    Some(conn) => read_frame::<_, ControlToAgent>(&mut conn.reader).await,
                    None => std::future::pending::<Result<Option<ControlToAgent>, WireError>>().await,
                }
            } => frame,
        };

        match read_result {
            Ok(Some(msg)) => {
                let now = chrono::Utc::now();
                let replies = engine.handle_control(msg, now).await;
                if let Some(conn) = connection.as_mut() {
                    if let Err(e) = send_messages(&mut conn.writer, replies).await {
                        tracing::warn!(error = %e, "reply write failed; reconnecting");
                        connection = None;
                        next_reconnect_at = Some(Instant::now() + backoff);
                    }
                }
            }
            Ok(None) => {
                tracing::warn!("control-d closed the connection");
                connection = None;
                next_reconnect_at = Some(Instant::now() + backoff);
            }
            Err(e) => {
                tracing::warn!(error = %e, "socket read failed; reconnecting");
                connection = None;
                next_reconnect_at = Some(Instant::now() + backoff);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_jitter_is_bounded_and_deterministic() {
        let a = reconnect_jitter("sess-1", 1);
        assert_eq!(a, reconnect_jitter("sess-1", 1));
        assert!(a < Duration::from_millis(MAX_RECONNECT_JITTER));
        // Different attempts produce (deterministically) different spread.
        let values: Vec<Duration> = (0..16)
            .map(|i| reconnect_jitter("sess-1", i))
            .collect();
        assert!(values.iter().any(|v| *v != values[0]));
    }
}
