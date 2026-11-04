//! The TCP-over-tailnet transport: listener, dialer, connections, serving.

use std::collections::{btree_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
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
use crate::framing::{read_sealed, read_sealed_opt, write_sealed, Opener, Sealer};
use crate::handshake::{client_handshake, server_handshake, Admission, Refusal, Remote, Session};
use crate::protocol::{
    decode_answer, decode_select, encode_answer, encode_select, validate_name,
    PROTOCOL_LESS_ANSWER, SELECT_MAX, STATUS_NOT_SERVED, STATUS_SERVED,
};
use crate::status::TailscaleStatus;
use crate::stream::SealedStream;
use crate::{AclMode, MeshTailscaleConfig, TailscalePeer};

/// Maximum simultaneous in-flight inbound handshakes. Excess connections are
/// dropped immediately so a flood cannot exhaust tasks or descriptors.
const MAX_PENDING_HANDSHAKES: usize = 64;

/// Maximum probes one discovery round runs at once. Each holds a socket for
/// up to connect + handshake timeout, and a shared tailnet can list
/// thousands of online nodes.
const MAX_CONCURRENT_PROBES: usize = 16;

/// Maximum in-flight inbound handshakes from one source IP, so that one host
/// holding silent connections cannot take every slot of
/// [`MAX_PENDING_HANDSHAKES`] and lock all other peers out.
const MAX_PENDING_PER_SOURCE: usize = 8;

/// Per-source pending-handshake counts; [`SourceSlot`] releases on drop.
#[derive(Default)]
struct PendingBySource(Mutex<HashMap<IpAddr, usize>>);

struct SourceSlot {
    table: Arc<PendingBySource>,
    ip: IpAddr,
}

impl PendingBySource {
    fn try_take(self: &Arc<Self>, ip: IpAddr) -> Option<SourceSlot> {
        let mut t = self.0.lock().ok()?;
        let n = t.entry(ip).or_insert(0);
        if *n >= MAX_PENDING_PER_SOURCE {
            return None;
        }
        *n += 1;
        Some(SourceSlot {
            table: Arc::clone(self),
            ip,
        })
    }
}

/// Established inbound connections, in total and per peer; [`ConnSlot`]
/// releases on drop (i.e. when the server-side [`MeshConn`] goes away).
#[derive(Default)]
struct ConnTable(Mutex<ConnCounts>);

#[derive(Default)]
struct ConnCounts {
    total: usize,
    per_peer: HashMap<PeerId, usize>,
}

pub(crate) struct ConnSlot {
    table: Arc<ConnTable>,
    peer: PeerId,
}

impl std::fmt::Debug for ConnSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnSlot")
            .field("peer", &self.peer)
            .finish()
    }
}

impl ConnTable {
    fn try_take(
        self: &Arc<Self>,
        peer: PeerId,
        max_total: usize,
        max_per_peer: usize,
    ) -> Option<ConnSlot> {
        let mut c = self.0.lock().ok()?;
        let mine = c.per_peer.get(&peer).copied().unwrap_or(0);
        if c.total >= max_total || mine >= max_per_peer {
            return None;
        }
        c.total += 1;
        c.per_peer.insert(peer, mine + 1);
        Some(ConnSlot {
            table: Arc::clone(self),
            peer,
        })
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        if let Ok(mut c) = self.table.0.lock() {
            c.total = c.total.saturating_sub(1);
            if let Some(n) = c.per_peer.get_mut(&self.peer) {
                *n -= 1;
                if *n == 0 {
                    c.per_peer.remove(&self.peer);
                }
            }
        }
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        if let Ok(mut t) = self.table.0.lock() {
            if let Some(n) = t.get_mut(&self.ip) {
                *n -= 1;
                if *n == 0 {
                    t.remove(&self.ip);
                }
            }
        }
    }
}

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

/// Handler for inbound requests, used by [`MeshTailscale::serve`] and
/// [`RequestProtocol`].
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    /// Produce the response for `payload` sent by the authenticated `peer`.
    async fn handle(&self, peer: PeerId, payload: Vec<u8>) -> Vec<u8>;
}

/// Serves connections that selected one sub-protocol (see
/// [`MeshTailscale::serve_protocols`]).
#[async_trait::async_trait]
pub trait ProtocolHandler: Send + Sync + 'static {
    /// Serve `conn` until it ends. The protocol is already selected
    /// ([`MeshConn::protocol`]); the remote identity is authenticated and,
    /// in `entangle-on-top` mode, was allowed by the allowlist.
    async fn serve(&self, conn: MeshConn);
}

/// A [`ProtocolHandler`] for request/response protocols: every frame on the
/// connection is a request answered by the [`RequestHandler`], exactly as
/// [`MeshTailscale::serve`] answers them.
#[derive(Debug)]
pub struct RequestProtocol<H>(pub Arc<H>);

#[async_trait::async_trait]
impl<H: RequestHandler> ProtocolHandler for RequestProtocol<H> {
    async fn serve(&self, mut conn: MeshConn) {
        serve_requests(&mut conn, self.0.as_ref()).await;
    }
}

/// Answer requests on `conn` with `handler` until the peer closes, the
/// connection idles out or a request fails.
async fn serve_requests<H: RequestHandler + ?Sized>(conn: &mut MeshConn, handler: &H) {
    loop {
        match conn.accept_request().await {
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
    /// whether to route over this transport. Connections from sources that
    /// `config.address_policy` does not permit are closed unread.
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
    /// Under [`crate::AddressPolicy::TailnetOnly`] (the default) an address
    /// outside the tailnet ranges is refused without dialling.
    ///
    /// Fails unless the server proves possession of `peer.public_key`, and
    /// fails with a handshake error if the server's ACL rejected us or it is
    /// at its connection limit.
    pub async fn connect(&self, peer: &TailscalePeer) -> Result<MeshConn, MeshTailscaleError> {
        let cfg = &self.inner.config;
        let mut stream = dial(peer.addr, cfg).await?;
        let (remote, admission, session) = client_handshake(
            &mut stream,
            &self.inner.identity,
            Some(&peer.public_key),
            cfg.handshake_timeout,
        )
        .await?;
        match admission {
            Admission::Admitted => Ok(MeshConn::new(stream, remote, session, None, None, cfg)),
            Admission::Denied => Err(MeshTailscaleError::Handshake(format!(
                "peer {} authenticated us but rejected us (we are not in its allowlist)",
                remote.peer_id
            ))),
            Admission::Busy => Err(MeshTailscaleError::Handshake(format!(
                "peer {} is at its connection limit; try again later",
                remote.peer_id
            ))),
        }
    }

    /// Dial `peer`, complete the handshake, and select the sub-protocol
    /// `protocol` (e.g. `entangle/scheduler/1`; see the `protocol` module).
    ///
    /// Every failure here happens before any application data is sent: a
    /// peer that does not serve `protocol` (or predates protocol selection)
    /// fails with [`MeshTailscaleError::Handshake`], as do the handshake's
    /// own refusals.
    pub async fn connect_protocol(
        &self,
        peer: &TailscalePeer,
        protocol: &[u8],
    ) -> Result<MeshConn, MeshTailscaleError> {
        validate_name(protocol)?;
        let mut conn = self.connect(peer).await?;
        conn.select_protocol(protocol).await?;
        Ok(conn)
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
    ///
    /// Every frame is a request: this is the protocol-less mode. A node
    /// serving more than one sub-protocol uses
    /// [`MeshTailscale::serve_protocols`] instead.
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
                tokio::select! {
                    () = serve_requests(&mut conn, handler.as_ref()) => {}
                    _ = shutdown.changed() => {}
                }
            });
        }
    }

    /// Accept connections until shutdown and hand each to the handler of
    /// the sub-protocol it selects (see the `protocol` module: the tailnet
    /// equivalent of an ALPN). Each connection runs on its own task.
    ///
    /// A connection that selects a protocol not in `handlers`, sends
    /// something other than a selection, or selects nothing within the
    /// handshake timeout is closed; nothing it sent reaches a handler. In
    /// `entangle-on-top` mode the allowlist is consulted again before the
    /// selection is even parsed.
    pub async fn serve_protocols(&self, handlers: Vec<(Vec<u8>, Arc<dyn ProtocolHandler>)>) {
        let handlers = Arc::new(handlers);
        let mut shutdown = self.inner.shutdown_tx.subscribe();
        loop {
            let conn = tokio::select! {
                c = self.accept() => c,
                _ = shutdown.changed() => None,
            };
            let Some(mut conn) = conn else { break };
            let handlers = Arc::clone(&handlers);
            let mut shutdown = self.inner.shutdown_tx.subscribe();
            tokio::spawn(async move {
                let names: Vec<&[u8]> = handlers.iter().map(|(n, _)| n.as_slice()).collect();
                let selected = tokio::select! {
                    r = conn.accept_protocol(&names) => r,
                    _ = shutdown.changed() => return,
                };
                let name = match selected {
                    Ok(name) => name,
                    Err(e) => {
                        debug!(peer = %conn.remote_peer_id(), error = %e, "mesh.tailscale: no protocol selected");
                        return;
                    }
                };
                let Some((_, handler)) = handlers.iter().find(|(n, _)| *n == name) else {
                    return;
                };
                let handler = Arc::clone(handler);
                tokio::select! {
                    () = handler.serve(conn) => {}
                    _ = shutdown.changed() => {}
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
        let mut stream = dial(addr, cfg).await?;
        let (remote, _admitted, _session) =
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
    ///
    /// A `PeerId` that answers from more than one tailnet node in the same
    /// round is left out (and logged): either a node is relaying another's
    /// handshake or a key was copied, and neither address can be preferred
    /// on evidence. The session layer already stops a relay from reading or
    /// injecting; this keeps one from silently becoming the chosen route.
    pub async fn discover(&self, status: &TailscaleStatus) -> Vec<TailscalePeer> {
        let port = match self.inner.config.port {
            0 => self.inner.local_addr.port(),
            p => p,
        };
        self.discover_on_port(status, port).await
    }

    /// [`MeshTailscale::discover`] with an explicit remote port. At most 16
    /// probes run at once.
    pub async fn discover_on_port(
        &self,
        status: &TailscaleStatus,
        port: u16,
    ) -> Vec<TailscalePeer> {
        let mut set = JoinSet::new();
        let policy = self.inner.config.address_policy;
        let probes = Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES));
        for node in status.online_peers() {
            let me = self.clone();
            // Never dial outside the tailnet, whatever the status JSON says:
            // WireGuard is what keeps the probe off the LAN.
            let ips: Vec<_> = node
                .ips
                .iter()
                .copied()
                .filter(|ip| policy.permits(*ip))
                .collect();
            if ips.is_empty() {
                continue;
            }
            let dns = node.dns_name.clone();
            let probes = Arc::clone(&probes);
            set.spawn(async move {
                // Closed only if the semaphore is dropped, which it is not
                // while this round runs.
                let _permit = probes.acquire_owned().await.ok()?;
                for ip in ips {
                    if let Ok(mut p) = me.probe(SocketAddr::new(ip, port)).await {
                        p.magic_dns = dns;
                        return Some(p);
                    }
                }
                None
            });
        }
        let mut found: BTreeMap<PeerId, TailscalePeer> = BTreeMap::new();
        let mut ambiguous: BTreeSet<PeerId> = BTreeSet::new();
        while let Some(res) = set.join_next().await {
            let Ok(Some(p)) = res else { continue };
            if p.peer_id == self.inner.peer_id {
                continue;
            }
            if ambiguous.contains(&p.peer_id) {
                warn!(peer = %p.peer_id, addr = %p.addr, "mesh.tailscale discovery: PeerId answered from yet another tailnet node");
                continue;
            }
            match found.entry(p.peer_id) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(p);
                }
                btree_map::Entry::Occupied(e) => {
                    let first = e.remove();
                    warn!(
                        peer = %p.peer_id,
                        first = %first.addr,
                        second = %p.addr,
                        "mesh.tailscale discovery: one PeerId answered from two tailnet nodes \
                         (a relaying node or a copied key); not using it this round"
                    );
                    ambiguous.insert(p.peer_id);
                }
            }
        }
        let out: Vec<_> = found.values().cloned().collect();
        if let Ok(mut c) = self.inner.candidates.lock() {
            *c = found;
        }
        out
    }

    /// Forget every discovered candidate (spec §6.1.1: when the tailnet is
    /// not active, peers reachable only via `mesh.tailscale` are
    /// unreachable). Returns how many were dropped.
    pub fn clear_candidates(&self) -> usize {
        self.inner
            .candidates
            .lock()
            .map(|mut c| std::mem::take(&mut *c).len())
            .unwrap_or(0)
    }

    /// The candidate for `peer` from the last discovery round, if any.
    pub fn candidate(&self, peer: &PeerId) -> Option<TailscalePeer> {
        self.inner
            .candidates
            .lock()
            .ok()
            .and_then(|c| c.get(peer).cloned())
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

async fn dial(
    addr: SocketAddr,
    cfg: &MeshTailscaleConfig,
) -> Result<TcpStream, MeshTailscaleError> {
    if !cfg.address_policy.permits(addr.ip()) {
        return Err(MeshTailscaleError::Connect {
            addr,
            reason: "not a tailnet address (refused by the address policy)".into(),
        });
    }
    let limit = cfg.connect_timeout;
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
    let per_source = Arc::new(PendingBySource::default());
    let established = Arc::new(ConnTable::default());
    loop {
        let (mut stream, from) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "mesh.tailscale accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !config.address_policy.permits(from.ip()) {
            debug!(%from, "mesh.tailscale: source is not a tailnet address, closing");
            continue;
        }
        let Some(source_slot) = per_source.try_take(from.ip()) else {
            debug!(%from, "mesh.tailscale: too many pending handshakes from this source, dropping");
            continue;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            debug!(%from, "mesh.tailscale: too many pending handshakes, dropping");
            continue;
        };
        let _ = stream.set_nodelay(true);
        let identity = identity.clone();
        let config = config.clone();
        let tx = tx.clone();
        let established = Arc::clone(&established);
        tokio::spawn(async move {
            let _permit = (permit, source_slot);
            let acl = config.acl_mode;
            let allow = config.allowlist.clone();
            let (max_total, max_per_peer) =
                (config.max_connections, config.max_connections_per_peer);
            let admit = move |p: &PeerId| {
                let allowed = match acl {
                    AclMode::TrustTailnet => true,
                    AclMode::EntangleOnTop => allow.as_ref().is_some_and(|a| a.is_allowed(p)),
                };
                if !allowed {
                    return Err(Refusal::NotAllowed);
                }
                established
                    .try_take(*p, max_total, max_per_peer)
                    .ok_or(Refusal::Busy)
            };
            match server_handshake(&mut stream, &identity, config.handshake_timeout, admit).await {
                Ok((remote, session, slot)) => {
                    // entangle-on-top keeps consulting the allowlist for
                    // every request, so a revocation also ends service on
                    // connections the peer already has.
                    let recheck = match config.acl_mode {
                        AclMode::EntangleOnTop => config.allowlist.clone(),
                        AclMode::TrustTailnet => None,
                    };
                    let conn = MeshConn::new(stream, remote, session, Some(slot), recheck, &config);
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
///
/// Every frame on it is a sealed record under the session keys agreed in the
/// handshake, so only the authenticated remote can produce or read them.
///
/// Frames carry no request id, so a connection is only usable while both
/// ends agree on where they are in the request/response sequence. Any call
/// that fails, times out or is cancelled (its future dropped) part-way
/// leaves the connection *poisoned*: every later call fails with
/// `ENTANGLE-E0647` instead of pairing a late response with the wrong
/// request. On the serving side, dropping a [`MeshRequest`] without
/// responding poisons the connection the same way. Open a new connection
/// after a failure.
#[derive(Debug)]
pub struct MeshConn {
    stream: TcpStream,
    remote: Remote,
    sealer: Sealer,
    opener: Opener,
    /// Held by server-side connections: counts against the connection caps
    /// until this connection (or the stream it became) is dropped.
    slot: Option<ConnSlot>,
    /// The sub-protocol selected on this connection, if any.
    protocol: Option<Vec<u8>>,
    /// Deadline for the protocol-selection exchange.
    setup_timeout: Duration,
    /// Set while an operation is in flight and left set if it does not
    /// complete; see the type docs.
    poisoned: bool,
    /// Server side, entangle-on-top: re-checked before each request is
    /// handed out.
    allowlist: Option<Arc<dyn PeerAllowlist>>,
    max_frame_bytes: usize,
    request_timeout: Duration,
    idle_timeout: Duration,
}

impl MeshConn {
    fn new(
        stream: TcpStream,
        remote: Remote,
        session: Session,
        slot: Option<ConnSlot>,
        allowlist: Option<Arc<dyn PeerAllowlist>>,
        cfg: &MeshTailscaleConfig,
    ) -> Self {
        Self {
            stream,
            remote,
            sealer: session.sealer,
            opener: session.opener,
            slot,
            protocol: None,
            setup_timeout: cfg.handshake_timeout,
            poisoned: false,
            allowlist,
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

    /// The sub-protocol selected on this connection
    /// ([`MeshTailscale::connect_protocol`] / [`MeshConn::accept_protocol`]),
    /// or `None` for a protocol-less connection.
    pub fn protocol(&self) -> Option<&[u8]> {
        self.protocol.as_deref()
    }

    /// Client side: name `protocol` and wait for the server to accept it.
    pub(crate) async fn select_protocol(
        &mut self,
        protocol: &[u8],
    ) -> Result<(), MeshTailscaleError> {
        self.begin()?;
        let limit = self.setup_timeout;
        let peer = self.remote.peer_id;
        let (stream, sealer, opener) = (&mut self.stream, &mut self.sealer, &mut self.opener);
        let exchange = async {
            write_sealed(stream, sealer, &encode_select(protocol), SELECT_MAX).await?;
            read_sealed(stream, opener, SELECT_MAX).await
        };
        let name = String::from_utf8_lossy(protocol);
        let answer = match timeout(limit, exchange).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(MeshTailscaleError::FrameTooLarge { .. })) => {
                return Err(MeshTailscaleError::Handshake(format!(
                    "peer {peer} answered the {name} selection with a reply that is not a \
                     protocol answer (a build without protocol selection?)"
                )))
            }
            Ok(Err(e)) => {
                return Err(MeshTailscaleError::Handshake(format!(
                    "selecting {name} with peer {peer}: {e}"
                )))
            }
            Err(_) => {
                return Err(MeshTailscaleError::Handshake(format!(
                    "peer {peer} did not answer the {name} selection within {}ms",
                    limit.as_millis()
                )))
            }
        };
        match decode_answer(&answer) {
            Some(STATUS_SERVED) => {
                self.protocol = Some(protocol.to_vec());
                self.poisoned = false;
                Ok(())
            }
            Some(_) => Err(MeshTailscaleError::Handshake(format!(
                "peer {peer} does not serve {name} over mesh.tailscale"
            ))),
            None => Err(MeshTailscaleError::Handshake(format!(
                "peer {peer} answered the {name} selection with a reply that is not a protocol \
                 answer (a build without protocol selection?)"
            ))),
        }
    }

    /// Server side: read the client's protocol selection and accept it if it
    /// names one of `served`, returning the name.
    ///
    /// The selection is read under a small fixed cap (checked against the
    /// declared length before allocation) and the handshake timeout. In
    /// `entangle-on-top` mode the allowlist is consulted before the record
    /// is parsed. On any failure the connection stays unusable: the caller
    /// drops it. An unserved protocol is answered "not served" first, so
    /// the client can tell that apart from a network failure.
    pub async fn accept_protocol(
        &mut self,
        served: &[&[u8]],
    ) -> Result<Vec<u8>, MeshTailscaleError> {
        self.begin()?;
        let limit = self.setup_timeout;
        let read = timeout(
            limit,
            read_sealed_opt(&mut self.stream, &mut self.opener, SELECT_MAX),
        )
        .await;
        let record = match read {
            Err(_) => {
                return Err(MeshTailscaleError::Protocol(format!(
                    "no protocol selection within {}ms",
                    limit.as_millis()
                )))
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok(None)) => {
                return Err(MeshTailscaleError::Stream(
                    "peer closed the connection before selecting a protocol".into(),
                ))
            }
            Ok(Ok(Some(record))) => record,
        };
        if let Some(list) = &self.allowlist {
            if !list.is_allowed(&self.remote.peer_id) {
                return Err(MeshTailscaleError::PeerNotAllowed(self.remote.peer_id));
            }
        }
        let max = self.max_frame_bytes;
        let Some(name) = decode_select(&record) else {
            // A client from before protocol selection (its diag probe):
            // answer as that build's listener did, then close. The record
            // reaches no handler.
            let _ = timeout(
                limit,
                write_sealed(
                    &mut self.stream,
                    &mut self.sealer,
                    PROTOCOL_LESS_ANSWER,
                    max,
                ),
            )
            .await;
            return Err(MeshTailscaleError::Protocol(
                "the first record is not a protocol selection (answered as a protocol-less \
                 request)"
                    .into(),
            ));
        };
        if !served.contains(&name) {
            let what = String::from_utf8_lossy(name).into_owned();
            let _ = timeout(
                limit,
                write_sealed(
                    &mut self.stream,
                    &mut self.sealer,
                    &encode_answer(STATUS_NOT_SERVED),
                    max,
                ),
            )
            .await;
            return Err(MeshTailscaleError::Protocol(format!(
                "peer asked for {what:?}, which is not served here"
            )));
        }
        let name = name.to_vec();
        match timeout(
            limit,
            write_sealed(
                &mut self.stream,
                &mut self.sealer,
                &encode_answer(STATUS_SERVED),
                max,
            ),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => return Err(MeshTailscaleError::request_timeout(limit)),
        }
        self.protocol = Some(name.clone());
        self.poisoned = false;
        Ok(name)
    }

    /// Turn the connection into a long-lived bidirectional framed stream
    /// (see [`SealedStream`]). Fails on a connection an earlier exchange
    /// left unusable.
    ///
    /// The stream keeps the connection's frame cap, its allowlist re-check
    /// (server side, `entangle-on-top`) and its place in the server's
    /// connection limits until both halves are dropped.
    pub fn into_stream(self) -> Result<SealedStream, MeshTailscaleError> {
        if self.poisoned {
            return Err(MeshTailscaleError::Stream(
                "connection is unusable after an earlier failed, timed-out or cancelled \
                 exchange; open a new one"
                    .into(),
            ));
        }
        let (read, write) = self.stream.into_split();
        Ok(SealedStream::assemble(
            read,
            write,
            self.sealer,
            self.opener,
            self.remote.public_key,
            self.remote.peer_id,
            self.allowlist,
            self.slot,
            self.max_frame_bytes,
        ))
    }

    fn begin(&mut self) -> Result<(), MeshTailscaleError> {
        if self.poisoned {
            return Err(MeshTailscaleError::Stream(
                "connection is unusable after an earlier failed, timed-out or cancelled \
                 exchange; open a new one"
                    .into(),
            ));
        }
        self.poisoned = true;
        Ok(())
    }

    /// Send one request frame and wait for the response frame.
    ///
    /// On any error, timeout or cancellation the connection is poisoned (see
    /// the type docs).
    pub async fn request(&mut self, payload: &[u8]) -> Result<Vec<u8>, MeshTailscaleError> {
        self.begin()?;
        let max = self.max_frame_bytes;
        let limit = self.request_timeout;
        let (stream, sealer, opener) = (&mut self.stream, &mut self.sealer, &mut self.opener);
        let fut = async {
            write_sealed(stream, sealer, payload, max).await?;
            read_sealed(stream, opener, max).await
        };
        let resp = match timeout(limit, fut).await {
            Ok(r) => r?,
            Err(_) => return Err(MeshTailscaleError::request_timeout(limit)),
        };
        self.poisoned = false;
        Ok(resp)
    }

    /// Wait for the next inbound request. `Ok(None)` when the peer closed the
    /// connection or it sat idle past `idle_timeout`.
    ///
    /// The connection stays poisoned until the returned request is answered
    /// with [`MeshRequest::respond`].
    ///
    /// On a server-side connection in [`AclMode::EntangleOnTop`] the peer
    /// allowlist is consulted again for every request: once the peer is no
    /// longer allowed, its request is not returned and this fails with
    /// `ENTANGLE-E0648` (the connection stays poisoned, so it ends).
    pub async fn accept_request(&mut self) -> Result<Option<MeshRequest<'_>>, MeshTailscaleError> {
        self.begin()?;
        let max = self.max_frame_bytes;
        let idle = self.idle_timeout;
        let read = timeout(
            idle,
            read_sealed_opt(&mut self.stream, &mut self.opener, max),
        )
        .await;
        match read {
            Err(_) => Ok(None),
            Ok(Err(e)) => Err(e),
            Ok(Ok(None)) => Ok(None),
            Ok(Ok(Some(payload))) => {
                if let Some(list) = &self.allowlist {
                    if !list.is_allowed(&self.remote.peer_id) {
                        return Err(MeshTailscaleError::PeerNotAllowed(self.remote.peer_id));
                    }
                }
                Ok(Some(MeshRequest {
                    payload,
                    conn: self,
                }))
            }
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
        let conn = &mut *self.conn;
        match timeout(
            limit,
            write_sealed(&mut conn.stream, &mut conn.sealer, payload, max),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => return Err(MeshTailscaleError::request_timeout(limit)),
        }
        conn.poisoned = false;
        Ok(())
    }
}
