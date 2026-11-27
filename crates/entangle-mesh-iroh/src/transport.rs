//! The `mesh.iroh` transport itself: an iroh QUIC endpoint bound to the
//! daemon's Ed25519 identity, plus the framed request/response round-trip.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use tokio::{sync::Semaphore, task::JoinSet, time::timeout};
use tracing::{debug, warn};

use crate::error::MeshIrohError;
use crate::framing::{read_frame, write_frame};
use crate::peer::IrohPeer;
use crate::{MeshIrohConfig, MeshTransport};

#[cfg(test)]
mod admission_test;
#[cfg(test)]
mod relay_test;

/// A live `mesh.iroh` transport.
///
/// Cheap to clone-by-`Arc`; the underlying [`Endpoint`] is itself a handle.
#[derive(Debug, Clone)]
pub struct MeshIroh {
    config: MeshIrohConfig,
    endpoint: Endpoint,
    public_key: [u8; 32],
    peer_id: PeerId,
}

impl MeshIroh {
    /// Bind a transport whose network identity **is** the daemon identity.
    ///
    /// iroh derives its `EndpointId` from an Ed25519 secret key; we hand it
    /// ours, so `EndpointId == IdentityPublicKey` byte-for-byte and therefore
    /// [`PeerId::from_public_key_bytes`] of the observed remote id is the same
    /// `PeerId` the rest of the workspace already uses for trust decisions.
    /// Nothing else in the stack has to learn a second identifier.
    pub async fn start(
        config: MeshIrohConfig,
        identity: &IdentityKeyPair,
    ) -> Result<Self, MeshIrohError> {
        Self::start_with_seed(config, &secret_seed(identity)?).await
    }

    /// Bind a transport from a raw 32-byte Ed25519 secret seed.
    ///
    /// Same as [`MeshIroh::start`] for callers that hold the seed directly
    /// (tests, key-rotation paths) rather than an [`IdentityKeyPair`].
    pub async fn start_with_seed(
        config: MeshIrohConfig,
        seed: &[u8; 32],
    ) -> Result<Self, MeshIrohError> {
        let config = config.normalized();
        let secret = SecretKey::from_bytes(seed);
        let public_key = *secret.public().as_bytes();

        let relay_mode = if config.allow_derp_relay {
            RelayMode::Default
        } else {
            RelayMode::Disabled
        };

        let builder = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret)
            .alpns(vec![config.alpn.clone()])
            .relay_mode(relay_mode)
            // Replace iroh's default `0.0.0.0` + `[::]` sockets with exactly
            // the address the operator configured, so `bind` means bind.
            .clear_ip_transports()
            .bind_addr(config.bind)
            .map_err(|e| MeshIrohError::Bind {
                bind: config.bind,
                reason: e.to_string(),
            })?;

        let endpoint = builder.bind().await.map_err(|e| MeshIrohError::Bind {
            bind: config.bind,
            reason: e.to_string(),
        })?;

        let peer_id = PeerId::from_public_key_bytes(&public_key);
        debug!(
            peer_id = %peer_id,
            bind = %config.bind,
            relay = config.allow_derp_relay,
            alpn = %String::from_utf8_lossy(&config.alpn),
            "mesh.iroh endpoint bound"
        );
        Ok(Self {
            config,
            endpoint,
            public_key,
            peer_id,
        })
    }

    /// Borrow the active (normalized) config.
    pub const fn config(&self) -> &MeshIrohConfig {
        &self.config
    }

    /// The `<pubkey-hex>@<host>:<port>` strings this endpoint is reachable on.
    ///
    /// This is the operator-facing "long address" that `entangle mesh trust`
    /// and the pairing flow consume, and it round-trips through
    /// [`crate::parse_node_addr`].
    ///
    /// A socket bound to the wildcard address (`0.0.0.0` / `::`, the default)
    /// is **expanded** rather than reported verbatim: the wildcard is a *bind*
    /// address, not a reachable one, so printing `0.0.0.0:41641` hands the
    /// operator a string no other machine can dial. Each unspecified bind is
    /// replaced by this host's routable interface address plus loopback, on
    /// the same port. Concrete binds pass through untouched.
    pub fn node_addrs(&self) -> Vec<String> {
        let mut out = Vec::new();
        for addr in self.local_addrs() {
            for resolved in expand_unspecified(addr) {
                let s = crate::format_node_addr(&self.public_key, resolved);
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
        out
    }

    /// Escape hatch for callers that need iroh-specific behaviour (relay
    /// URLs, connection-type watchers, custom protocols).
    ///
    /// Everything the dispatcher and pairing code need is on [`MeshTransport`];
    /// this exists so that needing one extra iroh knob does not force a fork.
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    fn peer_addr(&self, peer: &IrohPeer) -> Result<EndpointAddr, MeshIrohError> {
        let id = iroh::EndpointId::from_bytes(&peer.public_key).map_err(|e| {
            MeshIrohError::Identity(format!("peer public key is not a valid Ed25519 point: {e}"))
        })?;
        let mut addr = EndpointAddr::new(id);
        for hint in peer.addrs() {
            addr = addr.with_ip_addr(hint);
        }
        Ok(addr)
    }
}

fn secret_seed(identity: &IdentityKeyPair) -> Result<[u8; 32], MeshIrohError> {
    // `IdentityKeyPair` deliberately does not expose its secret bytes; PKCS#8
    // PEM is the one serialization it does offer, so we round-trip through it
    // rather than widening that crate's API. The PEM never leaves this stack
    // frame.
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    let pem = identity.to_pem();
    let signing = ed25519_dalek::SigningKey::from_pkcs8_pem(&pem).map_err(|e| {
        MeshIrohError::Identity(format!("identity key is not decodable PKCS#8: {e}"))
    })?;
    Ok(signing.to_bytes())
}

#[async_trait::async_trait]
impl MeshTransport for MeshIroh {
    fn local_peer_id(&self) -> PeerId {
        self.peer_id
    }

    fn local_public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn local_addrs(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    async fn connect(&self, peer: &IrohPeer) -> Result<MeshConn, MeshIrohError> {
        let addr = self.peer_addr(peer)?;
        let dialing = self.endpoint.connect(addr, &self.config.alpn);
        let conn = match timeout(self.config.connect_timeout, dialing).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                return Err(MeshIrohError::Connect {
                    peer: peer.peer_id,
                    reason: e.to_string(),
                })
            }
            Err(_elapsed) => {
                return Err(MeshIrohError::ConnectTimeout {
                    peer: peer.peer_id,
                    after: self.config.connect_timeout,
                })
            }
        };
        Ok(MeshConn::wrap(conn, &self.config))
    }

    async fn request(&self, peer: &IrohPeer, payload: &[u8]) -> Result<Vec<u8>, MeshIrohError> {
        let conn = self.connect(peer).await?;
        let response = conn.request(payload).await;
        conn.close();
        response
    }

    async fn accept(&self) -> Result<Option<MeshConn>, MeshIrohError> {
        let Some(incoming) = self.endpoint.accept().await else {
            // `accept()` yields `None` only once the endpoint is closed.
            return Ok(None);
        };
        let conn = incoming
            .await
            .map_err(|e| MeshIrohError::Stream(format!("accepting connection: {e}")))?;
        Ok(Some(MeshConn::wrap(conn, &self.config)))
    }

    async fn shutdown(&self) {
        self.endpoint.close().await;
    }
}

/// One established, identity-verified connection to a peer.
///
/// Deliberately exposes no iroh types: the dispatcher works in terms of
/// [`PeerId`] and byte payloads.
#[derive(Debug, Clone)]
pub struct MeshConn {
    inner: Connection,
    remote_public_key: [u8; 32],
    remote_peer_id: PeerId,
    max_frame_bytes: usize,
    request_timeout: Duration,
}

impl MeshConn {
    fn wrap(inner: Connection, config: &MeshIrohConfig) -> Self {
        // QUIC has already proven possession of the remote secret key during
        // the handshake, so this id is authenticated, not merely claimed.
        let remote_public_key = *inner.remote_id().as_bytes();
        Self {
            remote_peer_id: PeerId::from_public_key_bytes(&remote_public_key),
            remote_public_key,
            inner,
            max_frame_bytes: config.max_frame_bytes,
            request_timeout: config.request_timeout,
        }
    }

    /// The authenticated [`PeerId`] of the remote end.
    pub const fn remote_peer_id(&self) -> PeerId {
        self.remote_peer_id
    }

    /// Direct remote socket on the currently selected QUIC path, when available.
    pub fn selected_socket(&self) -> Option<SocketAddr> {
        self.inner
            .paths()
            .iter()
            .find(|p| p.is_selected())
            .and_then(|p| match p.remote_addr() {
                iroh::TransportAddr::Ip(addr) => Some(*addr),
                _ => None,
            })
    }

    /// The authenticated raw Ed25519 public key of the remote end.
    ///
    /// `PeerId::from_public_key_bytes(&conn.remote_public_key())` equals
    /// [`MeshConn::remote_peer_id`] by construction.
    pub const fn remote_public_key(&self) -> [u8; 32] {
        self.remote_public_key
    }

    /// Open a persistent bidirectional stream and send the protocol opening frame.
    pub async fn open_stream(&self, opening: &[u8]) -> Result<MeshDuplex, MeshIrohError> {
        timeout(self.request_timeout, async {
            let (mut send, recv) = self
                .inner
                .open_bi()
                .await
                .map_err(|e| MeshIrohError::Stream(e.to_string()))?;
            write_frame(&mut send, opening, self.max_frame_bytes).await?;
            Ok(MeshDuplex {
                send,
                recv,
                max: self.max_frame_bytes,
            })
        })
        .await
        .map_err(|_| MeshIrohError::RequestTimeout(self.request_timeout))?
    }

    /// Send one framed request and wait for the framed response.
    ///
    /// Each call uses a fresh QUIC bidirectional stream, so concurrent
    /// requests on one connection do not head-of-line block each other.
    pub async fn request(&self, payload: &[u8]) -> Result<Vec<u8>, MeshIrohError> {
        match timeout(self.request_timeout, self.request_inner(payload)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(MeshIrohError::RequestTimeout(self.request_timeout)),
        }
    }

    async fn request_inner(&self, payload: &[u8]) -> Result<Vec<u8>, MeshIrohError> {
        let (mut send, mut recv) = self
            .inner
            .open_bi()
            .await
            .map_err(|e| MeshIrohError::Stream(format!("opening stream: {e}")))?;
        write_frame(&mut send, payload, self.max_frame_bytes).await?;
        send.finish()
            .map_err(|e| MeshIrohError::Stream(format!("finishing request stream: {e}")))?;
        read_frame(&mut recv, self.max_frame_bytes).await
    }

    /// Wait for the next inbound request on this connection.
    ///
    /// Returns `Ok(None)` when the peer closed the connection cleanly.
    pub async fn accept_request(&self) -> Result<Option<MeshRequest>, MeshIrohError> {
        self.read_request(None).await
    }

    async fn read_request(
        &self,
        readers: Option<&Semaphore>,
    ) -> Result<Option<MeshRequest>, MeshIrohError> {
        let (send, mut recv) = match self.inner.accept_bi().await {
            Ok(pair) => pair,
            Err(e) if is_clean_close(&e) => return Ok(None),
            Err(e) => return Err(MeshIrohError::Stream(format!("accepting stream: {e}"))),
        };
        // Idle connections do not consume a frame buffer. FIFO admission only starts
        // once the peer has actually opened its request stream.
        let _read = match readers {
            Some(available) => Some(
                available
                    .acquire()
                    .await
                    .map_err(|_| MeshIrohError::Stream("frame reader closed".into()))?,
            ),
            None => None,
        };
        let payload = read_frame(&mut recv, self.max_frame_bytes).await?;
        Ok(Some(MeshRequest {
            payload,
            recv,
            send,
            peer: self.remote_peer_id,
            remote_socket: self.selected_socket(),
            max_frame_bytes: self.max_frame_bytes,
        }))
    }

    /// Close the connection, telling the peer it was deliberate.
    pub fn close(&self) {
        self.inner.close(0u32.into(), b"entangle: done");
    }

    /// Wait until the connection is closed by either end.
    ///
    /// A server that has answered its last request must await this (or keep
    /// calling [`MeshConn::accept_request`], which is the same thing) before
    /// dropping the connection: dropping a QUIC connection with data still in
    /// flight discards it, and the requester sees a lost connection instead of
    /// its response.
    pub async fn closed(&self) {
        let _ = self.inner.closed().await;
    }
}

fn is_clean_close(err: &iroh::endpoint::ConnectionError) -> bool {
    use iroh::endpoint::ConnectionError;
    matches!(
        err,
        ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed
    )
}

/// An inbound framed request awaiting a response.
///
/// Dropping it without calling [`MeshRequest::respond`] resets the stream, and
/// the requester observes a stream error rather than hanging.
#[derive(Debug)]
pub struct MeshRequest {
    remote_socket: Option<SocketAddr>,
    payload: Vec<u8>,
    recv: RecvStream,
    send: SendStream,
    peer: PeerId,
    max_frame_bytes: usize,
}

impl MeshRequest {
    /// Direct remote socket selected when the opening frame was received.
    pub fn selected_socket(&self) -> Option<SocketAddr> {
        self.remote_socket
    }

    /// The authenticated [`PeerId`] that sent this request.
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }

    /// The request payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Take ownership of the payload, keeping the ability to respond.
    pub fn take_payload(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.payload)
    }

    /// Continue using both directions after decoding the initial request frame.
    pub fn into_stream(self) -> MeshDuplex {
        MeshDuplex {
            send: self.send,
            recv: self.recv,
            max: self.max_frame_bytes,
        }
    }

    /// Send the framed response and finish the stream.
    pub async fn respond(mut self, payload: &[u8]) -> Result<(), MeshIrohError> {
        write_frame(&mut self.send, payload, self.max_frame_bytes).await?;
        self.send
            .finish()
            .map_err(|e| MeshIrohError::Stream(format!("finishing response stream: {e}")))?;
        Ok(())
    }
}

/// Both directions of an authenticated QUIC stream. Split them so a complete
/// frame read can continue independently of heartbeats and outbound writes.
pub struct MeshDuplex {
    send: SendStream,
    recv: RecvStream,
    max: usize,
}

impl MeshDuplex {
    /// Separate independently driven frame reader and writer.
    pub fn split(self) -> (MeshFrameWriter, MeshFrameReader) {
        (
            MeshFrameWriter(self.send, self.max),
            MeshFrameReader(self.recv, self.max),
        )
    }
}

/// Length-bounded outgoing QUIC frames.
pub struct MeshFrameWriter(SendStream, usize);
impl MeshFrameWriter {
    /// Write one whole frame.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MeshIrohError> {
        write_frame(&mut self.0, payload, self.1).await
    }
    /// Shut down the outgoing half after the last frame.
    pub fn finish(&mut self) -> Result<(), MeshIrohError> {
        self.0
            .finish()
            .map_err(|e| MeshIrohError::Stream(e.to_string()))
    }
}
/// Length-bounded incoming QUIC frames.
pub struct MeshFrameReader(RecvStream, usize);
impl MeshFrameReader {
    /// Read one frame with an additional caller-supplied protocol ceiling.
    pub async fn receive(&mut self, max: usize) -> Result<Vec<u8>, MeshIrohError> {
        read_frame(&mut self.0, self.1.min(max)).await
    }
}

/// Serve inbound requests on `transport` until it is shut down.
///
/// A convenience over [`MeshTransport::accept`] +
/// [`MeshConn::accept_request`] for the common "one handler for every peer"
/// case: the cross-node dispatcher's server half is exactly this loop with a
/// handler that decodes an RPC envelope.
///
/// Each connection is served on its own task; a failing connection is logged
/// and dropped rather than taking the listener down.
pub async fn serve<H, F>(transport: std::sync::Arc<MeshIroh>, handler: H)
where
    H: Fn(PeerId, Vec<u8>) -> F + Clone + Send + Sync + 'static,
    F: std::future::Future<Output = Vec<u8>> + Send + 'static,
{
    serve_requests(transport, move |mut req| {
        let handler = handler.clone();
        async move {
            let response = handler(req.peer_id(), req.take_payload()).await;
            req.respond(&response).await
        }
    })
    .await;
}

/// Serve authenticated requests that can upgrade to a duplex subprotocol.
pub async fn serve_requests<H, F>(transport: std::sync::Arc<MeshIroh>, handler: H)
where
    H: Fn(MeshRequest) -> F + Clone + Send + Sync + 'static,
    F: std::future::Future<Output = Result<(), MeshIrohError>> + Send + 'static,
{
    serve_bounded(
        transport,
        handler,
        Arc::new(Semaphore::new(64)),
        Arc::new(Semaphore::new(8)),
    )
    .await;
}

// Connections cover handshakes, idle clients and admitted operations. A smaller,
// independent frame budget bounds concurrent opening payloads before a handler
// can evaluate its application allowlist. An upgraded stream manages its own flow control.
async fn serve_bounded<H, F>(
    transport: Arc<MeshIroh>,
    handler: H,
    connections: Arc<Semaphore>,
    readers: Arc<Semaphore>,
) where
    H: Fn(MeshRequest) -> F + Clone + Send + Sync + 'static,
    F: std::future::Future<Output = Result<(), MeshIrohError>> + Send + 'static,
{
    let mut sessions = JoinSet::new();
    loop {
        let incoming = tokio::select! {
            biased;
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!(%error, "mesh.iroh: connection handler terminated");
                }
                continue;
            }
            next = transport.endpoint.accept() => match next {
                Some(incoming) => incoming,
                None => return,
            }
        };
        let Ok(slot) = connections.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let handler = handler.clone();
        let config = transport.config.clone();
        let readers = readers.clone();
        sessions.spawn(async move {
            let _slot = slot;
            let conn = match timeout(config.connect_timeout, incoming).await {
                Ok(Ok(connection)) => MeshConn::wrap(connection, &config),
                Ok(Err(error)) => {
                    debug!(%error, "mesh.iroh: inbound handshake failed");
                    return;
                }
                Err(_) => return,
            };
            loop {
                // Bound the idle wait, reader queue and the entire opening frame together.
                // The admitted handler below can legitimately outlive this interval.
                match timeout(config.request_timeout, conn.read_request(Some(&readers))).await {
                    Ok(Ok(Some(req))) => {
                        if let Err(error) = handler(req).await {
                            warn!(peer = %conn.remote_peer_id(), %error, "mesh.iroh: response failed");
                            return;
                        }
                    }
                    Ok(Ok(None)) => return,
                    Ok(Err(error)) => {
                        debug!(peer = %conn.remote_peer_id(), %error, "mesh.iroh: inbound request failed");
                        return;
                    }
                    Err(_) => {
                        conn.close();
                        return;
                    }
                }
            }
        });
    }
}

/// Expand a wildcard bind address into addresses another host can actually dial.
///
/// `0.0.0.0` / `::` mean "listen on every interface" — they are never a
/// destination. Reporting one to an operator (or writing it into a peer record)
/// produces an address that silently fails to connect, which is why
/// [`MeshIroh::node_addrs`] routes through here.
///
/// Returns the routable interface address first (that is the one a peer on
/// another machine needs), then loopback so same-host pairing and local
/// integration tests still work. A concrete bind is returned unchanged.
fn expand_unspecified(addr: SocketAddr) -> Vec<SocketAddr> {
    if !addr.ip().is_unspecified() {
        return vec![addr];
    }
    let port = addr.port();
    let mut out = Vec::new();
    if let Some(ip) = routable_local_ip(addr.is_ipv6()) {
        out.push(SocketAddr::new(ip, port));
    }
    let loopback = if addr.is_ipv6() {
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    if !out.iter().any(|a| a.ip() == loopback) {
        out.push(SocketAddr::new(loopback, port));
    }
    out
}

/// This host's routable interface address, or `None` if it has no route out.
///
/// Uses the standard UDP-connect trick: `connect` on a UDP socket sends no
/// packets, it only asks the kernel to pick the source address it *would* use
/// to reach the target. So this needs no network access and cannot block —
/// it is a routing-table lookup, and the target is never contacted.
fn routable_local_ip(want_v6: bool) -> Option<std::net::IpAddr> {
    use std::net::UdpSocket;
    let (bind, probe) = if want_v6 {
        ("[::]:0", "[2001:4860:4860::8888]:80")
    } else {
        ("0.0.0.0:0", "8.8.8.8:80")
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(probe).ok()?;
    let ip = sock.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

#[cfg(test)]
mod addr_tests {
    use super::*;

    #[test]
    fn concrete_bind_passes_through_unchanged() {
        let a: SocketAddr = "192.168.1.5:41641".parse().unwrap();
        assert_eq!(expand_unspecified(a), vec![a]);
    }

    #[test]
    fn wildcard_v4_never_reports_the_wildcard() {
        let out = expand_unspecified("0.0.0.0:41641".parse().unwrap());
        assert!(
            !out.is_empty(),
            "wildcard must expand to something dialable"
        );
        for a in &out {
            assert!(!a.ip().is_unspecified(), "0.0.0.0 is not dialable: {a}");
            assert_eq!(a.port(), 41641, "port must be preserved");
        }
    }

    #[test]
    fn wildcard_v4_includes_loopback_so_same_host_pairing_works() {
        let out = expand_unspecified("0.0.0.0:41641".parse().unwrap());
        assert!(
            out.iter().any(|a| a.ip().is_loopback()),
            "expected a loopback fallback, got {out:?}"
        );
    }

    #[test]
    fn wildcard_v6_expands_to_v6_addresses() {
        let out = expand_unspecified("[::]:41641".parse().unwrap());
        assert!(!out.is_empty());
        for a in &out {
            assert!(a.is_ipv6(), "v6 wildcard must stay v6: {a}");
            assert!(!a.ip().is_unspecified());
        }
    }
}
