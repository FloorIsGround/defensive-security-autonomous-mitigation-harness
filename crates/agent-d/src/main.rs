//! `agent-d` binary entrypoint: single-threaded Tokio runtime, clap CLI,
//! Outbound UDS or mTLS connection to `control-d` with bounded exponential
//! reconnect jitter, and a unified select loop that runs scheduled watches,
//! pumps spooled observations, and handles incoming control frames —
//! including while disconnected (observations spool for later delivery).

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use defsec_mtls::MtlsConnector;
use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::signing::VerifyingKeyStore;
use defsec_protocol::wire::{AgentToControl, ControlToAgent, WireError, read_frame, write_frame};
use tokio::{
    io::{AsyncRead, AsyncWrite, WriteHalf},
    net::UnixStream,
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, timeout},
};

use agent_d::collectors::RealLinuxCollectors;
use agent_d::engine::AgentEngine;
use agent_d::profile::load_profile;
use agent_d::spool::DurabilityProfile;

const MIN_HEARTBEAT_SECONDS: u64 = 5;
const RECONNECT_BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_CEILING: Duration = Duration::from_secs(30);
const MAX_RECONNECT_JITTER: u64 = 1500; // milliseconds
const IO_TIMEOUT: Duration = Duration::from_secs(15);

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

    /// Path to `control-d`'s agent socket (defaults to ./control-data/agent.sock for UDS).
    #[arg(long, conflicts_with = "control_mtls_addr")]
    control_sock: Option<PathBuf>,

    /// Address of the mTLS agent listener (host:port).
    #[arg(long, requires_all = ["tls_server_name", "tls_ca_cert", "tls_client_cert", "tls_client_key"])]
    control_mtls_addr: Option<String>,
    #[arg(long, requires = "control_mtls_addr")]
    tls_server_name: Option<String>,
    #[arg(long, requires = "control_mtls_addr")]
    tls_ca_cert: Option<PathBuf>,
    #[arg(long, requires = "control_mtls_addr")]
    tls_client_cert: Option<PathBuf>,
    #[arg(long, requires = "control_mtls_addr")]
    tls_client_key: Option<PathBuf>,

    /// Signing key id the control plane uses for watch bundles.
    #[arg(long)]
    control_key_id: String,

    /// Ed25519 public key (hex) of the control signing key.
    #[arg(long)]
    control_pub_hex: String,

    /// Optional admin-owned host profile JSON (see docs/operations-and-deployment.md).
    /// Can only tighten the local safety floor; load failures are fatal.
    #[arg(long)]
    profile: Option<PathBuf>,

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

enum ControlTransport {
    Unix(PathBuf),
    Mtls {
        addr: String,
        server_name: String,
        connector: MtlsConnector,
    },
}

impl ControlTransport {
    fn from_args(args: &Args) -> Result<Self, defsec_mtls::MtlsError> {
        if let Some(addr) = &args.control_mtls_addr {
            Ok(Self::Mtls {
                addr: addr.clone(),
                server_name: args
                    .tls_server_name
                    .clone()
                    .expect("clap requires --tls-server-name"),
                connector: MtlsConnector::from_pem_files(
                    args.tls_ca_cert
                        .as_ref()
                        .expect("clap requires --tls-ca-cert"),
                    args.tls_client_cert
                        .as_ref()
                        .expect("clap requires --tls-client-cert"),
                    args.tls_client_key
                        .as_ref()
                        .expect("clap requires --tls-client-key"),
                )?,
            })
        } else {
            Ok(Self::Unix(
                args.control_sock
                    .clone()
                    .unwrap_or_else(|| "./control-data/agent.sock".into()),
            ))
        }
    }

    async fn connect(&self) -> Result<Connection, Box<dyn std::error::Error>> {
        let stream: Box<dyn AgentIo> = match self {
            Self::Unix(path) => Box::new(UnixStream::connect(path).await?),
            Self::Mtls {
                addr,
                server_name,
                connector,
            } => Box::new(connector.connect(addr.as_str(), server_name).await?),
        };
        Ok(Connection::new(stream))
    }
}

trait AgentIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AgentIo for T {}

type IncomingFrame = Result<Option<ControlToAgent>, WireError>;

struct Connection {
    incoming: mpsc::Receiver<IncomingFrame>,
    reader_task: JoinHandle<()>,
    writer: WriteHalf<Box<dyn AgentIo>>,
}

impl Connection {
    fn new(stream: Box<dyn AgentIo>) -> Self {
        let (mut reader, writer) = tokio::io::split(stream);
        let (tx, incoming) = mpsc::channel(8);
        // Keep partial reads alive when the watch/heartbeat ticker fires.
        let reader_task = tokio::spawn(async move {
            loop {
                let frame = read_frame(&mut reader).await;
                let finished = !matches!(frame, Ok(Some(_)));
                if tx.send(frame).await.is_err() || finished {
                    break;
                }
            }
        });
        Self {
            incoming,
            reader_task,
            writer,
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

/// Bounded, deterministic reconnect jitter derived from the session id and
/// the attempt counter (no RNG dependency on constrained edge nodes).
fn reconnect_jitter(session_id: &str, attempt: u64) -> Duration {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(attempt.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let n = u64::from_be_bytes(digest[0..8].try_into().unwrap());
    Duration::from_millis(n % MAX_RECONNECT_JITTER)
}

struct Reconnect {
    backoff: Duration,
    attempts: u64,
    next: Instant,
}

impl Reconnect {
    fn new() -> Self {
        Self {
            backoff: RECONNECT_BACKOFF_FLOOR,
            attempts: 0,
            next: Instant::now(),
        }
    }

    fn failed(&mut self, session_id: &str) {
        self.attempts += 1;
        let delay = self.backoff + reconnect_jitter(session_id, self.attempts);
        self.next = Instant::now() + delay;
        self.backoff = (self.backoff * 2).min(RECONNECT_BACKOFF_CEILING);
        tracing::debug!(
            retry_ms = delay.as_millis() as u64,
            attempt = self.attempts,
            "scheduled control reconnect"
        );
    }
}

async fn send_messages(
    writer: &mut (impl AsyncWrite + Unpin),
    msgs: Vec<AgentToControl>,
) -> Result<(), WireError> {
    for msg in msgs {
        timeout(IO_TIMEOUT, write_frame(writer, &msg))
            .await
            .map_err(std::io::Error::from)??;
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
    // An optional admin-owned host profile can only tighten it.
    let base_cfg = EdgeSafetyConfig::default();
    let (cfg, profile_summary) = match &args.profile {
        None => (base_cfg, None),
        Some(path) => {
            let loaded = load_profile(path, &base_cfg)?;
            tracing::info!(
                profile = %path.display(),
                tags = ?loaded.summary.host_tags,
                expected_services = ?loaded.summary.expected_services,
                enabled_collectors = ?loaded
                    .summary
                    .enabled_collectors
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>(),
                "host profile applied; edge floor tightened"
            );
            (loaded.cfg, Some(loaded.summary))
        }
    };
    let collector = std::sync::Arc::new(RealLinuxCollectors::new());
    let mut engine = AgentEngine::new(
        cfg,
        args.host_id.clone(),
        durability,
        args.state_dir.clone(),
        store,
        collector,
    )?;
    engine.set_host_profile_summary(profile_summary);
    Ok(engine)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let transport = ControlTransport::from_args(&args)?;

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
    main_loop(&mut engine, &transport, heartbeat_dur).await
}

async fn main_loop(
    engine: &mut AgentEngine<RealLinuxCollectors>,
    transport: &ControlTransport,
    heartbeat_dur: Duration,
) -> ! {
    let mut reconnect = Reconnect::new();
    let mut connection: Option<Connection> = None;
    let mut next_heartbeat = Instant::now() + heartbeat_dur;

    // Coarse 1s driver: watch deadlines are >= 15s, heartbeats >= 5s.
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        // (Re)connect when due.
        if connection.is_none() && Instant::now() >= reconnect.next {
            let connecting = timeout(IO_TIMEOUT, transport.connect());
            tokio::pin!(connecting);
            let connected = loop {
                tokio::select! {
                    result = &mut connecting => break result,
                    _ = ticker.tick() => {
                        engine.run_due_watches(chrono::Utc::now()).await;
                    }
                }
            };
            let registered = async {
                let mut conn = connected??;
                let register = engine.make_register(chrono::Utc::now());
                send_messages(&mut conn.writer, vec![register]).await?;
                // Retransmit pending spooled observations until durable acknowledgment.
                let pending: Vec<AgentToControl> = engine
                    .pending_observations()
                    .into_iter()
                    .map(|observation| AgentToControl::PushObservationDelta { observation })
                    .collect();
                if !pending.is_empty() {
                    tracing::info!(count = pending.len(), "flushing spooled observations");
                }
                send_messages(&mut conn.writer, pending).await?;
                Ok::<_, Box<dyn std::error::Error>>(conn)
            }
            .await;
            match registered {
                Ok(conn) => {
                    tracing::info!("connected to control-d");
                    connection = Some(conn);
                    next_heartbeat = Instant::now() + heartbeat_dur;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "control connection failed; will retry");
                    reconnect.failed(engine.session_id());
                }
            }
        }

        let read_result = tokio::select! {
            _ = ticker.tick() => {
                let now = chrono::Utc::now();
                // Run scheduled watches — also while disconnected: pending
                // observations accumulate in the bounded spool.
                let outgoing = engine.run_due_watches(now).await;
                if let Some(conn) = connection.as_mut()
                    && let Err(e) = send_messages(&mut conn.writer, outgoing).await
                {
                    tracing::warn!(error = %e, "socket write failed; reconnecting");
                    connection = None;
                    reconnect.failed(engine.session_id());
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
                                reconnect.failed(engine.session_id());
                            }
                        }
                    }
                }
                continue;
            }
            frame = async {
                match connection.as_mut() {
                    Some(conn) => conn.incoming.recv().await.unwrap_or(Err(WireError::ChannelClosed)),
                    None => std::future::pending::<IncomingFrame>().await,
                }
            } => frame,
        };

        match read_result {
            Ok(Some(ControlToAgent::RegisterAck {
                accepted: false,
                reason,
                ..
            })) => {
                tracing::warn!(?reason, "control-d rejected registration");
                connection = None;
                reconnect.failed(engine.session_id());
            }
            Ok(Some(msg)) => {
                if matches!(msg, ControlToAgent::RegisterAck { accepted: true, .. }) {
                    reconnect = Reconnect::new();
                }
                let now = chrono::Utc::now();
                let replies = engine.handle_control(msg, now).await;
                if let Some(conn) = connection.as_mut()
                    && let Err(e) = send_messages(&mut conn.writer, replies).await
                {
                    tracing::warn!(error = %e, "reply write failed; reconnecting");
                    connection = None;
                    reconnect.failed(engine.session_id());
                }
            }
            Ok(None) => {
                tracing::warn!("control-d closed the connection");
                connection = None;
                reconnect.failed(engine.session_id());
            }
            Err(e) => {
                tracing::warn!(error = %e, "socket read failed; reconnecting");
                connection = None;
                reconnect.failed(engine.session_id());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_transport_flags_require_one_complete_configuration() {
        let parse = |extra: &[&str]| {
            Args::try_parse_from(
                [
                    "agent-d",
                    "--host-id",
                    "edge-01",
                    "--control-key-id",
                    "key",
                    "--control-pub-hex",
                    "hex",
                ]
                .into_iter()
                .chain(extra.iter().copied()),
            )
        };
        let args = parse(&[]).unwrap();
        assert!(matches!(
            ControlTransport::from_args(&args).unwrap(),
            ControlTransport::Unix(path) if path == std::path::Path::new("./control-data/agent.sock")
        ));
        let mut tls = vec![
            "--control-mtls-addr",
            "localhost:8443",
            "--tls-server-name",
            "localhost",
            "--tls-ca-cert",
            "ca.crt",
            "--tls-client-cert",
            "edge.crt",
        ];
        assert!(parse(&tls).is_err());
        tls.extend(["--tls-client-key", "edge.key"]);
        assert!(parse(&tls).is_ok());
        tls.extend(["--control-sock", "agent.sock"]);
        assert!(parse(&tls).is_err());
    }

    #[test]
    fn profile_flag_is_optional_and_parsed_as_a_path() {
        let base = [
            "agent-d",
            "--host-id",
            "edge-01",
            "--control-key-id",
            "key",
            "--control-pub-hex",
            "hex",
        ];
        let args = Args::try_parse_from(base.to_vec()).unwrap();
        assert_eq!(args.profile, None);

        let args = Args::try_parse_from(
            base.into_iter()
                .chain(["--profile", "/etc/defsecautmit/edge-01.profile.json"])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(
            args.profile.as_deref(),
            Some(std::path::Path::new("/etc/defsecautmit/edge-01.profile.json"))
        );
    }

    #[test]
    fn reconnect_jitter_is_bounded_and_deterministic() {
        let a = reconnect_jitter("sess-1", 1);
        assert_eq!(a, reconnect_jitter("sess-1", 1));
        assert!(a < Duration::from_millis(MAX_RECONNECT_JITTER));
        // Different attempts produce (deterministically) different spread.
        let values: Vec<Duration> = (0..16).map(|i| reconnect_jitter("sess-1", i)).collect();
        assert!(values.iter().any(|v| *v != values[0]));
    }
}
