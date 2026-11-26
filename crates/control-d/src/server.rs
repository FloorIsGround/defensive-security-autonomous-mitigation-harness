use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use defsec_mtls::MtlsAcceptor;
use defsec_protocol::{
    profile::HostProfileSummary,
    rpc::{AdminRequest, InvestigationCall},
    signing::SignedEnvelope,
    watch::WatchBundlePayload,
    wire::{AgentToControl, AgentToControlMessage, ControlToAgent, read_frame, write_frame},
};
use serde::{Deserialize, de::IgnoredAny};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UnixListener, UnixStream},
    sync::Semaphore,
    task::{JoinSet, spawn_blocking},
    time::timeout,
};

use crate::{ControlService, service::uuid};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_CONNECTION_LIMIT: usize = 128;
type ServerResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) type Registry = Arc<Mutex<HashMap<String, String>>>;

pub struct MtlsAgentServer {
    listener: TcpListener,
    acceptor: MtlsAcceptor,
}

impl MtlsAgentServer {
    pub async fn bind(addr: SocketAddr, acceptor: MtlsAcceptor) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            acceptor,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve_agent(self, service: ControlService) -> io::Result<()> {
        let registry = service.agent_registry();
        let mut tasks = JoinSet::new();
        let capacity = Arc::new(Semaphore::new(AGENT_CONNECTION_LIMIT));
        loop {
            tokio::select! {
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::warn!(%error, "mTLS agent task failed");
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, addr) = accepted?;
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { continue };
                    let acceptor = self.acceptor.clone();
                    let service = service.clone();
                    let registry = registry.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        match timeout(IO_TIMEOUT, acceptor.accept(stream)).await {
                            Ok(Ok((stream, peer))) => {
                                if let Err(error) = agent_connection(stream, service, registry, Some(peer.host_id)).await {
                                    tracing::debug!(%addr, %error, "mTLS agent connection ended");
                                }
                            }
                            Ok(Err(error)) => tracing::debug!(%addr, %error, "mTLS agent rejected"),
                            Err(error) => tracing::debug!(%addr, %error, "mTLS agent handshake timed out"),
                        }
                    });
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct SocketPolicy {
    pub mode: u32,
    pub allowed_uids: Vec<u32>,
}

impl Default for SocketPolicy {
    fn default() -> Self {
        Self {
            mode: 0o600,
            allowed_uids: vec![nix::unistd::geteuid().as_raw()],
        }
    }
}

pub struct UnixServer {
    listener: UnixListener,
    path: PathBuf,
    inode: (u64, u64),
    policy: SocketPolicy,
}

impl UnixServer {
    pub fn bind(path: impl AsRef<Path>, policy: SocketPolicy) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        if policy.mode & !0o777 != 0 || policy.allowed_uids.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid socket permissions or UID allowlist",
            ));
        }
        let listener = UnixListener::bind(&path)?;
        let meta = std::fs::symlink_metadata(&path)?;
        let server = Self {
            listener,
            path,
            inode: (meta.dev(), meta.ino()),
            policy,
        };
        std::fs::set_permissions(
            &server.path,
            std::fs::Permissions::from_mode(server.policy.mode),
        )?;
        Ok(server)
    }

    pub async fn serve_agent(self, service: ControlService) -> io::Result<()> {
        let registry = service.agent_registry();
        self.serve(move |stream| agent_connection(stream, service.clone(), registry.clone(), None))
            .await
    }

    pub async fn serve_admin(self, service: ControlService) -> io::Result<()> {
        self.serve(move |mut stream| {
            let service = service.clone();
            async move {
                let actor = format!("unix-uid:{}", stream.peer_cred()?.uid());
                while let Some(req) =
                    timeout(IO_TIMEOUT, read_frame::<_, AdminRequest>(&mut stream)).await??
                {
                    let response = spawn_blocking({
                        let service = service.clone();
                        let actor = actor.clone();
                        move || service.handle_admin_request_as(req, &actor)
                    })
                    .await?;
                    timeout(IO_TIMEOUT, write_frame(&mut stream, &response)).await??;
                }
                Ok(())
            }
        })
        .await
    }

    pub async fn serve_investigation(self, service: ControlService) -> io::Result<()> {
        self.serve(move |mut stream| {
            let service = service.clone();
            async move {
                while let Some(call) =
                    timeout(IO_TIMEOUT, read_frame::<_, InvestigationCall>(&mut stream))
                        .await?
                        // Decoder errors can include excerpts from the incoming frame.
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid investigation frame",
                            )
                        })?
                {
                    let response = spawn_blocking({
                        let service = service.clone();
                        move || service.handle_investigation_call(call)
                    })
                    .await?;
                    timeout(IO_TIMEOUT, write_frame(&mut stream, &response)).await??;
                }
                Ok(())
            }
        })
        .await
    }

    async fn serve<F, Fut>(self, connection: F) -> io::Result<()>
    where
        F: Fn(UnixStream) -> Fut,
        Fut: Future<Output = ServerResult<()>> + Send + 'static,
    {
        let mut tasks = JoinSet::new();
        let capacity = Arc::new(Semaphore::new(AGENT_CONNECTION_LIMIT));
        loop {
            tokio::select! {
                result = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Some(Ok(Err(error))) => tracing::debug!(%error,"local connection ended"),
                        Some(Err(error)) => tracing::warn!(%error,"local connection task failed"),
                        _ => {}
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(cred) = stream.peer_cred() else {continue};
                    if !self.policy.allowed_uids.contains(&cred.uid()) {
                        tracing::warn!(uid=cred.uid(),"local peer UID rejected");
                        continue;
                    }
                    let Ok(permit) = capacity.clone().try_acquire_owned() else {continue};
                    let task = connection(stream);
                    tasks.spawn(async move {
                        let _permit = permit;
                        task.await
                    });
                }
            }
        }
    }
}

impl Drop for UnixServer {
    fn drop(&mut self) {
        if let Ok(meta) = std::fs::symlink_metadata(&self.path)
            && (meta.dev(), meta.ino()) == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

struct RegisteredAgent {
    registry: Registry,
    host: String,
    connection: String,
}

impl RegisteredAgent {
    fn is_current(&self, registry: &HashMap<String, String>) -> bool {
        registry.get(&self.host) == Some(&self.connection)
    }
}

impl Drop for RegisteredAgent {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock()
            && self.is_current(&registry)
        {
            registry.remove(&self.host);
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReportedHostProfile {
    Summary(HostProfileSummary),
    Malformed(IgnoredAny),
}

async fn agent_connection<S>(
    mut stream: S,
    service: ControlService,
    registry: Registry,
    authenticated_host_id: Option<String>,
) -> ServerResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let register = timeout(
        IO_TIMEOUT,
        read_frame::<_, AgentToControlMessage<ReportedHostProfile>>(&mut stream),
    )
    .await??;
    let Some(msg @ AgentToControlMessage::Register { .. }) = register else {
        return Ok(());
    };
    let AgentToControlMessage::Register {
        host_id,
        session_id,
        active_bundle_version,
        ..
    } = &msg
    else {
        unreachable!()
    };
    if let Some(cert_host_id) = authenticated_host_id
        && cert_host_id != *host_id
    {
        tracing::warn!(%cert_host_id, registered_host_id = %host_id, "mTLS agent host ID mismatch");
        timeout(IO_TIMEOUT, stream.shutdown()).await??;
        return Ok(());
    }
    let mut bundle_version = *active_bundle_version;
    let session = session_id.clone();
    let agent = Arc::new(RegisteredAgent {
        registry: registry.clone(),
        host: host_id.clone(),
        connection: uuid(),
    });
    let mut updates = service.subscribe_bundles();
    let replies = spawn_blocking({
        let service = service.clone();
        let agent = agent.clone();
        move || -> io::Result<_> {
            let mut registry = registry
                .lock()
                .map_err(|_| io::Error::other("agent registry lock poisoned"))?;
            let replies = service.handle_agent_message_with_profile(msg, |profile| match profile {
                ReportedHostProfile::Summary(summary) => Ok(summary),
                ReportedHostProfile::Malformed(_) => Err("malformed host profile summary".into()),
            });
            if matches!(
                replies.first(),
                Some(ControlToAgent::RegisterAck { accepted: true, .. })
            ) {
                registry.insert(agent.host.clone(), agent.connection.clone());
                service.bundle_changed();
            }
            Ok(replies)
        }
    })
    .await??;
    let accepted = matches!(
        replies.first(),
        Some(ControlToAgent::RegisterAck { accepted: true, .. })
    );
    let (mut reader, mut writer) = tokio::io::split(stream);
    send_replies(&mut writer, replies, &mut bundle_version).await?;
    if !accepted {
        return Ok(());
    }
    loop {
        // Keep partially read frames across bundle notifications.
        let read = read_frame::<_, AgentToControl>(&mut reader);
        tokio::pin!(read);
        let msg = loop {
            tokio::select! {
                changed = updates.changed() => {
                    changed?;
                    let latest = spawn_blocking({
                        let service = service.clone();
                        let agent = agent.clone();
                        move || -> ServerResult<_> {
                            let registry = agent.registry.lock().map_err(|_|io::Error::other("agent registry lock poisoned"))?;
                            if !agent.is_current(&registry) {
                                return Ok(None);
                            }
                            Ok(Some(service.latest_bundle(&agent.host)?))
                        }
                    }).await??;
                    let Some(latest) = latest else {return Ok(())};
                    if let Some((version,envelope)) = latest
                        && version > bundle_version
                    {
                        timeout(IO_TIMEOUT,write_frame(&mut writer,&ControlToAgent::SyncWatchBundle{envelope})).await??;
                        bundle_version = version;
                    }
                }
                result = &mut read => break result?,
            }
        };
        let Some(msg) = msg else { return Ok(()) };
        let scoped = match &msg {
            AgentToControl::Heartbeat {
                host_id,
                session_id,
                ..
            } => host_id == &agent.host && session_id == &session,
            AgentToControl::PushObservationDelta { observation } => {
                // Allow flushing unacknowledged durable-spool records from prior
                // sessions of the same enrolled host after restart.
                observation.host_id == agent.host
            }
            AgentToControl::BundleAck { host_id, .. } => host_id == &agent.host,
            AgentToControl::Register { .. } => false,
        };
        if !scoped {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "message is outside registered session",
            )
            .into());
        }
        let replies = spawn_blocking({
            let service = service.clone();
            let agent = agent.clone();
            move || -> io::Result<_> {
                let registry = agent
                    .registry
                    .lock()
                    .map_err(|_| io::Error::other("agent registry lock poisoned"))?;
                Ok(agent
                    .is_current(&registry)
                    .then(|| service.handle_agent_message(msg)))
            }
        })
        .await??;
        let Some(replies) = replies else {
            return Ok(());
        };
        send_replies(&mut writer, replies, &mut bundle_version).await?;
    }
}

async fn send_replies(
    writer: &mut (impl AsyncWrite + Unpin),
    replies: Vec<ControlToAgent>,
    bundle_version: &mut u64,
) -> ServerResult<()> {
    for response in replies {
        if let ControlToAgent::SyncWatchBundle {
            envelope: SignedEnvelope { raw_payload, .. },
        } = &response
        {
            let payload: WatchBundlePayload = serde_json::from_str(raw_payload)?;
            *bundle_version = payload.bundle_version;
        }
        timeout(IO_TIMEOUT, write_frame(writer, &response)).await??;
    }
    Ok(())
}
