//! The `mesh.iroh` transport itself: an iroh QUIC endpoint bound to the
//! daemon's Ed25519 identity, plus the framed request/response round-trip.

use std::net::SocketAddr;
use std::time::Duration;

use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use iroh::endpoint::{Connection, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::error::MeshIrohError;
use crate::framing::{read_frame, write_frame};
use crate::peer::IrohPeer;
use crate::{MeshIrohConfig, MeshTransport};

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
    /// One per bound socket. This is the operator-facing "long address" that
    /// `entangle mesh trust` / the pairing flow consume, and it round-trips
    /// through [`crate::parse_node_addr`].
    pub fn node_addrs(&self) -> Vec<String> {
        self.local_addrs()
            .into_iter()
            .map(|addr| crate::format_node_addr(&self.public_key, addr))
            .collect()
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

    /// The authenticated raw Ed25519 public key of the remote end.
    ///
    /// `PeerId::from_public_key_bytes(&conn.remote_public_key())` equals
    /// [`MeshConn::remote_peer_id`] by construction.
    pub const fn remote_public_key(&self) -> [u8; 32] {
        self.remote_public_key
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
        let (send, mut recv) = match self.inner.accept_bi().await {
            Ok(pair) => pair,
            Err(e) if is_clean_close(&e) => return Ok(None),
            Err(e) => return Err(MeshIrohError::Stream(format!("accepting stream: {e}"))),
        };
        let payload = read_frame(&mut recv, self.max_frame_bytes).await?;
        Ok(Some(MeshRequest {
            payload,
            send,
            peer: self.remote_peer_id,
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
    payload: Vec<u8>,
    send: SendStream,
    peer: PeerId,
    max_frame_bytes: usize,
}

impl MeshRequest {
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

    /// Send the framed response and finish the stream.
    pub async fn respond(mut self, payload: &[u8]) -> Result<(), MeshIrohError> {
        write_frame(&mut self.send, payload, self.max_frame_bytes).await?;
        self.send
            .finish()
            .map_err(|e| MeshIrohError::Stream(format!("finishing response stream: {e}")))?;
        Ok(())
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
    loop {
        let conn = match transport.accept().await {
            Ok(Some(conn)) => conn,
            Ok(None) => return,
            Err(e) => {
                warn!(error = %e, "mesh.iroh: rejected inbound connection");
                continue;
            }
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            loop {
                match conn.accept_request().await {
                    Ok(Some(mut req)) => {
                        let peer = req.peer_id();
                        let response = handler(peer, req.take_payload()).await;
                        if let Err(e) = req.respond(&response).await {
                            warn!(%peer, error = %e, "mesh.iroh: response failed");
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(e) => {
                        warn!(error = %e, "mesh.iroh: inbound request failed");
                        return;
                    }
                }
            }
        });
    }
}
