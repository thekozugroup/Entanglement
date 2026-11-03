//! The TCP-over-tailnet transport: listener, dialer, connections, serving.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::error::MeshTailscaleError;
use crate::framing::{read_frame, read_frame_opt, write_frame};
use crate::handshake::{client_handshake, server_handshake, Remote};
use crate::status::TailscaleStatus;
use crate::{AclMode, MeshTailscaleConfig, TailscalePeer};

/// Maximum simultaneous in-flight inbound handshakes. Excess connections are
/// dropped immediately so a flood cannot exhaust tasks or descriptors.
const MAX_PENDING_HANDSHAKES: usize = 64;

/// Authorization source for [`AclMode::EntangleOnTop`].
///
/// Implementations must fail closed.
pub trait PeerAllowlist: std::fmt::Debug + Send + Sync {
    /// `true` only if `peer` is explicitly trusted.
    fn is_allowed(&self, peer: &PeerId) -> bool;
}

/// A fixed set of allowed peers.
#[derive(Clone, Debug, Default)]
pub struct StaticAllowlist(HashSet<PeerId>);

impl StaticAllowlist {
    /// Build from an iterator of peer ids.
    pub fn new(peers: impl IntoIterator<Item = PeerId>) -> Self {
        Self(peers.into_iter().collect())
    }
}

impl PeerAllowlist for StaticAllowlist {
    fn is_allowed(&self, peer: &PeerId) -> bool {
        self.0.contains(peer)
    }
}

/// Handler for inbound requests, used by [`MeshTailscale::serve`].
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    /// Produce the response for `payload` sent by the authenticated `peer`.
    async fn handle(&self, peer: PeerId, payload: Vec<u8>) -> Vec<u8>;
}

struct Inner {
    config: MeshTailscaleConfig,
    identity: IdentityKeyPair,
    public_key: [u8; 32],
    peer_id: PeerId,
    local_addr: SocketAddr,
    incoming: tokio::sync::Mutex<mpsc::Receiver<MeshConn>>,
    accept_task: JoinHandle<()>,
    shutdown_tx: watch::Sender<bool>,
    candidates: Mutex<BTreeMap<PeerId, TailscalePeer>>,
}

/// A live `mesh.tailscale` transport. Cheap to clone.
#[derive(Clone)]
pub struct MeshTailscale {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for MeshTailscale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshTailscale")
            .field("peer_id", &self.inner.peer_id)
            .field("local_addr", &self.inner.local_addr)
            .field("acl_mode", &self.inner.config.acl_mode)
            .finish_non_exhaustive()
    }
}

impl MeshTailscale {
    /// Bind the listener and start accepting.
    ///
    /// The listener binds `config.bind_ip:config.port` (port `0` = ephemeral).
    /// It is *not* gated on the tailnet being up: liveness is reported
    /// separately (see [`crate::spawn_liveness`]) and the broker decides
    /// whether to route over this transport.
    pub async fn start(
        identity: &IdentityKeyPair,
        config: MeshTailscaleConfig,
    ) -> Result<Self, MeshTailscaleError> {
        let config = config.normalized();
        let bind = SocketAddr::new(config.bind_ip, config.port);
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|e| MeshTailscaleError::Bind {
                bind,
                reason: e.to_string(),
            })?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| MeshTailscaleError::Bind {
                bind,
                reason: e.to_string(),
            })?;
        let public_key = *identity.public().as_bytes();
        let peer_id = PeerId::from_public_key_bytes(&public_key);

        let (tx, rx) = mpsc::channel(32);
        let (shutdown_tx, _) = watch::channel(false);
        let accept_task = tokio::spawn(accept_loop(listener, identity.clone(), config.clone(), tx));
        debug!(peer_id = %peer_id, addr = %local_addr, acl = ?config.acl_mode, "mesh.tailscale listening");
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                identity: identity.clone(),
                public_key,
                peer_id,
                local_addr,
                incoming: tokio::sync::Mutex::new(rx),
                accept_task,
                shutdown_tx,
                candidates: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    /// Our own `PeerId`.
    pub fn local_peer_id(&self) -> PeerId {
        self.inner.peer_id
    }

    /// Our own Ed25519 public key.
    pub fn local_public_key(&self) -> [u8; 32] {
        self.inner.public_key
    }

    /// The bound listener address.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// The active (normalized) config.
    pub fn config(&self) -> &MeshTailscaleConfig {
        &self.inner.config
    }

    /// Dial `peer` and complete the handshake.
    ///
    /// Fails unless the server proves possession of `peer.public_key`, and
    /// fails with a handshake error if the server's ACL rejected us.
    pub async fn connect(&self, peer: &TailscalePeer) -> Result<MeshConn, MeshTailscaleError> {
        let cfg = &self.inner.config;
        let mut stream = dial(peer.addr, cfg.connect_timeout).await?;
        let (remote, admitted) = client_handshake(
            &mut stream,
            &self.inner.identity,
            Some(&peer.public_key),
            cfg.handshake_timeout,
        )
        .await?;
        if !admitted {
            return Err(MeshTailscaleError::Handshake(format!(
                "peer {} authenticated us but rejected us (we are not in its allowlist)",
                remote.peer_id
            )));
        }
        Ok(MeshConn::new(stream, remote, cfg))
    }

    /// Connect, send one request, return the response, close.
    pub async fn request(
        &self,
        peer: &TailscalePeer,
        payload: &[u8],
    ) -> Result<Vec<u8>, MeshTailscaleError> {
        let mut conn = self.connect(peer).await?;
        conn.request(payload).await
    }

    /// Wait for the next inbound connection that passed the handshake and the
    /// ACL. `None` once the transport has been shut down.
    pub async fn accept(&self) -> Option<MeshConn> {
        self.inner.incoming.lock().await.recv().await
    }

    /// Accept connections until shutdown, answering every request with
    /// `handler`. Each connection runs on its own task.
    pub async fn serve<H: RequestHandler>(&self, handler: Arc<H>) {
        let mut shutdown = self.inner.shutdown_tx.subscribe();
        loop {
            let conn = tokio::select! {
                c = self.accept() => c,
                _ = shutdown.changed() => None,
            };
            let Some(mut conn) = conn else { break };
            let handler = Arc::clone(&handler);
            let mut shutdown = self.inner.shutdown_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    let req = tokio::select! {
                        r = conn.accept_request() => r,
                        _ = shutdown.changed() => return,
                    };
                    match req {
                        Ok(Some(req)) => {
                            let peer = req.peer();
                            let resp = handler.handle(peer, req.payload().to_vec()).await;
                            if let Err(e) = req.respond(&resp).await {
                                debug!(%peer, error = %e, "mesh.tailscale response failed");
                                return;
                            }
                        }
                        Ok(None) => return,
                        Err(e) => {
                            debug!(error = %e, "mesh.tailscale inbound connection ended");
                            return;
                        }
                    }
                }
            });
        }
    }

    /// Stop accepting and signal serving tasks to finish.
    pub async fn shutdown(&self) {
        let _ = self.inner.shutdown_tx.send(true);
        self.inner.accept_task.abort();
        // Close the queue so `accept()` returns `None`.
        self.inner.incoming.lock().await.close();
    }

    /// Probe one address with the handshake, using a throw-away identity so
    /// that our real key is never disclosed to a peer that has not been
    /// trusted. Returns the authenticated identity of whatever answered.
    pub async fn probe(&self, addr: SocketAddr) -> Result<TailscalePeer, MeshTailscaleError> {
        let cfg = &self.inner.config;
        let ephemeral = IdentityKeyPair::generate();
        let mut stream = dial(addr, cfg.connect_timeout).await?;
        let (remote, _admitted) =
            client_handshake(&mut stream, &ephemeral, None, cfg.handshake_timeout).await?;
        Ok(TailscalePeer {
            peer_id: remote.peer_id,
            public_key: remote.public_key,
            addr,
            magic_dns: String::new(),
        })
    }

    /// Enumerate online tailnet peers from `status` and probe each on the
    /// configured port (spec §6.1.1 as amended: Tailscale cannot host our
    /// SRV/TXT records). Peers that answer the handshake become candidates;
    /// the candidate set is replaced by this round's result.
    pub async fn discover(&self, status: &TailscaleStatus) -> Vec<TailscalePeer> {
        let port = match self.inner.config.port {
            0 => self.inner.local_addr.port(),
            p => p,
        };
        self.discover_on_port(status, port).await
    }

    /// [`MeshTailscale::discover`] with an explicit remote port.
    pub async fn discover_on_port(
        &self,
        status: &TailscaleStatus,
        port: u16,
    ) -> Vec<TailscalePeer> {
        let mut set = JoinSet::new();
        for node in status.online_peers() {
            let me = self.clone();
            let ips = node.ips.clone();
            let dns = node.dns_name.clone();
            set.spawn(async move {
                for ip in ips {
                    if let Ok(mut p) = me.probe(SocketAddr::new(ip, port)).await {
                        p.magic_dns = dns;
                        return Some(p);
                    }
                }
                None
            });
        }
        let mut found = BTreeMap::new();
        while let Some(res) = set.join_next().await {
            if let Ok(Some(p)) = res {
                if p.peer_id != self.inner.peer_id {
                    found.insert(p.peer_id, p);
                }
            }
        }
        let out: Vec<_> = found.values().cloned().collect();
        if let Ok(mut c) = self.inner.candidates.lock() {
            *c = found;
        }
        out
    }

    /// Candidates found by the last [`MeshTailscale::discover`] round.
    pub fn candidates(&self) -> Vec<TailscalePeer> {
        self.inner
            .candidates
            .lock()
            .map(|c| c.values().cloned().collect())
            .unwrap_or_default()
    }
}

async fn dial(addr: SocketAddr, limit: Duration) -> Result<TcpStream, MeshTailscaleError> {
    match timeout(limit, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(MeshTailscaleError::Connect {
            addr,
            reason: e.to_string(),
        }),
        Err(_) => Err(MeshTailscaleError::Connect {
            addr,
            reason: format!("timed out after {}ms", limit.as_millis()),
        }),
    }
}

async fn accept_loop(
    listener: TcpListener,
    identity: IdentityKeyPair,
    config: MeshTailscaleConfig,
    tx: mpsc::Sender<MeshConn>,
) {
    let permits = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let (mut stream, from) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "mesh.tailscale accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            debug!(%from, "mesh.tailscale: too many pending handshakes, dropping");
            continue;
        };
        let _ = stream.set_nodelay(true);
        let identity = identity.clone();
        let config = config.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let acl = config.acl_mode;
            let allow = config.allowlist.clone();
            let admit = move |p: &PeerId| match acl {
                AclMode::TrustTailnet => true,
                AclMode::EntangleOnTop => allow.as_ref().is_some_and(|a| a.is_allowed(p)),
            };
            match server_handshake(&mut stream, &identity, config.handshake_timeout, admit).await {
                Ok(remote) => {
                    let conn = MeshConn::new(stream, remote, &config);
                    // A full queue means nobody is accepting; drop.
                    if tx.try_send(conn).is_err() {
                        debug!(%from, "mesh.tailscale: accept queue full, dropping connection");
                    }
                }
                Err(e @ MeshTailscaleError::PeerNotAllowed(_)) => {
                    debug!(%from, error = %e, "mesh.tailscale: rejecting peer");
                }
                Err(e) => debug!(%from, error = %e, "mesh.tailscale: inbound handshake failed"),
            }
        });
    }
}

/// An established, identity-verified connection.
#[derive(Debug)]
pub struct MeshConn {
    stream: TcpStream,
    remote: Remote,
    max_frame_bytes: usize,
    request_timeout: Duration,
    idle_timeout: Duration,
}

impl MeshConn {
    fn new(stream: TcpStream, remote: Remote, cfg: &MeshTailscaleConfig) -> Self {
        Self {
            stream,
            remote,
            max_frame_bytes: cfg.max_frame_bytes,
            request_timeout: cfg.request_timeout,
            idle_timeout: cfg.idle_timeout,
        }
    }

    /// The authenticated `PeerId` of the remote end.
    pub fn remote_peer_id(&self) -> PeerId {
        self.remote.peer_id
    }

    /// The authenticated Ed25519 public key of the remote end.
    pub fn remote_public_key(&self) -> [u8; 32] {
        self.remote.public_key
    }

    /// Send one request frame and wait for the response frame.
    pub async fn request(&mut self, payload: &[u8]) -> Result<Vec<u8>, MeshTailscaleError> {
        let max = self.max_frame_bytes;
        let limit = self.request_timeout;
        let stream = &mut self.stream;
        let fut = async {
            write_frame(stream, payload, max).await?;
            read_frame(stream, max).await
        };
        match timeout(limit, fut).await {
            Ok(r) => r,
            Err(_) => Err(MeshTailscaleError::request_timeout(limit)),
        }
    }

    /// Wait for the next inbound request. `Ok(None)` when the peer closed the
    /// connection or it sat idle past `idle_timeout`.
    pub async fn accept_request(&mut self) -> Result<Option<MeshRequest<'_>>, MeshTailscaleError> {
        let max = self.max_frame_bytes;
        let idle = self.idle_timeout;
        let read = timeout(idle, read_frame_opt(&mut self.stream, max)).await;
        match read {
            Err(_) => Ok(None),
            Ok(Err(e)) => Err(e),
            Ok(Ok(None)) => Ok(None),
            Ok(Ok(Some(payload))) => Ok(Some(MeshRequest {
                payload,
                conn: self,
            })),
        }
    }
}

/// An inbound request awaiting its response.
#[derive(Debug)]
pub struct MeshRequest<'a> {
    payload: Vec<u8>,
    conn: &'a mut MeshConn,
}

impl MeshRequest<'_> {
    /// The request body.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The authenticated sender.
    pub fn peer(&self) -> PeerId {
        self.conn.remote.peer_id
    }

    /// Send the response frame.
    pub async fn respond(self, payload: &[u8]) -> Result<(), MeshTailscaleError> {
        let max = self.conn.max_frame_bytes;
        let limit = self.conn.request_timeout;
        match timeout(limit, write_frame(&mut self.conn.stream, payload, max)).await {
            Ok(r) => r,
            Err(_) => Err(MeshTailscaleError::request_timeout(limit)),
        }
    }
}
