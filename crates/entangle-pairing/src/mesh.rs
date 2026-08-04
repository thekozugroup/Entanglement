//! Pairing over the real mesh transport: mDNS to find the device, QUIC to talk
//! to it.
//!
//! This is the wiring layer. [`crate::net`] owns every security decision; this
//! module owns sockets, timeouts and the accept loop, and re-exports the few
//! `entangle-mesh-iroh` / `entangle-mesh-local` types a caller needs so the CLI
//! can drive the whole flow through `entangle-pairing` alone.
//!
//! ```text
//!   device A: entangle pair --responder      device B: entangle pair
//!   ├─ PairingListener::start                ├─ discover_pairing_hosts()  (mDNS)
//!   │   ├─ MeshIroh on ALPN_CONTROL          ├─ user picks a device
//!   │   └─ mDNS beacon (key + port)          ├─ user types the code
//!   └─ .wait()  ────────── QUIC ─────────────┴─ dial_and_pair()
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use entangle_mesh_iroh::{MeshConn, MeshIroh, MeshIrohConfig, MeshIrohError, MeshTransport};
use entangle_mesh_local::{
    Discovery, DiscoveryConfig, DiscoveryError, LocalPeer, PeerSeen, TransportAdvert,
    PAIRING_SERVICE_TYPE,
};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;
use tracing::{debug, warn};

use crate::net::{
    Dialer, HostConfig, HostSession, PairingNetError, PairingWire, MAX_PAIRING_FRAME_BYTES,
};
use crate::{PairedPeer, PairingCode, ShortFingerprint};

pub use entangle_mesh_iroh::{
    format_node_addr, parse_node_addr, IrohPeer, MeshTransport as PairingTransportExt, ALPN_CONTROL,
};

/// Default listen address for a pairing listener: every interface, kernel-chosen
/// port. The port is published in the mDNS beacon and in the printed long
/// address, so it never has to be well-known.
pub const DEFAULT_PAIRING_BIND: &str = "0.0.0.0:0";

/// How long to wait for a dial to complete before giving up.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one request/response round-trip may take.
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(20);
/// Grace period for the peer to close the connection after the final frame, so
/// the response is not discarded by an abrupt endpoint shutdown.
const LINGER: Duration = Duration::from_secs(3);
/// Frames one connection may send before it is dropped.
const MAX_FRAMES_PER_CONNECTION: usize = 8;

/// Errors from the networked pairing flow.
#[derive(Debug, thiserror::Error)]
pub enum PairingMeshError {
    /// Transport-level failure (bind, dial, stream).
    #[error(transparent)]
    Transport(#[from] MeshIrohError),
    /// Protocol or verification failure.
    #[error(transparent)]
    Net(#[from] PairingNetError),
    /// mDNS failure.
    #[error("discovery: {0}")]
    Discovery(#[from] DiscoveryError),
    /// Nobody paired before the session expired.
    #[error("timed out: no device completed pairing within {0:?}")]
    Timeout(Duration),
    /// The peer descriptor has no address to dial.
    #[error("no reachable address for {0}")]
    NoAddress(String),
}

/// Transport config used by both ends of the pairing flow.
///
/// Relay is left enabled so a cross-network `--peer <long-address>` pairing can
/// still hole-punch, but the frame cap is tightened to the pairing protocol's
/// own maximum: this endpoint never carries anything else.
pub fn pairing_transport_config(bind: SocketAddr) -> MeshIrohConfig {
    MeshIrohConfig {
        bind,
        alpn: ALPN_CONTROL.to_vec(),
        connect_timeout: DIAL_TIMEOUT,
        request_timeout: ROUND_TRIP_TIMEOUT,
        max_frame_bytes: MAX_PAIRING_FRAME_BYTES,
        ..MeshIrohConfig::default()
    }
}

/// The same config with relays disabled and bound to `127.0.0.1:0`.
///
/// For single-machine harnesses and the in-process tests: no DNS, no relay
/// fleet, no traffic that leaves the box.
pub fn loopback_pairing_config() -> MeshIrohConfig {
    MeshIrohConfig {
        alpn: ALPN_CONTROL.to_vec(),
        connect_timeout: DIAL_TIMEOUT,
        request_timeout: ROUND_TRIP_TIMEOUT,
        max_frame_bytes: MAX_PAIRING_FRAME_BYTES,
        ..MeshIrohConfig::loopback()
    }
}

/// Bind a short-lived QUIC endpoint for pairing, bound to this device's own
/// identity key (so its `EndpointId` *is* its `PeerId`).
pub async fn start_pairing_transport(
    identity: &IdentityKeyPair,
    bind: SocketAddr,
) -> Result<Arc<MeshIroh>, MeshIrohError> {
    start_pairing_transport_with(identity, pairing_transport_config(bind)).await
}

/// [`start_pairing_transport`] with an explicit transport config.
pub async fn start_pairing_transport_with(
    identity: &IdentityKeyPair,
    config: MeshIrohConfig,
) -> Result<Arc<MeshIroh>, MeshIrohError> {
    Ok(Arc::new(MeshIroh::start(config, identity).await?))
}

// ── Listener (the device that shows the code) ────────────────────────────────

/// A short-lived listener that waits for another device to pair with it.
///
/// Owns its own QUIC endpoint — it does **not** need the daemon to be running —
/// and, optionally, an mDNS beacon that makes it appear in the other device's
/// chooser. Both are torn down by [`PairingListener::shutdown`].
pub struct PairingListener {
    transport: Arc<MeshIroh>,
    session: Arc<HostSession>,
    beacon: Option<Discovery>,
    /// Woken after every handled frame so [`PairingListener::wait`] observes
    /// state changes immediately instead of polling.
    progress: Arc<Notify>,
    /// The accept loop. It keeps answering (with refusals) after the session
    /// ends, so a late dialer is told *why* rather than left hanging, and it
    /// stops when the endpoint is shut down.
    server: JoinHandle<()>,
}

impl PairingListener {
    /// Bind the endpoint and start the session clock.
    ///
    /// `announce` controls whether an mDNS beacon is published. A failure to
    /// announce is *not* fatal: the listener still works for a peer given the
    /// long address printed by [`PairingListener::node_addrs`], which is the
    /// cross-subnet path.
    pub async fn start(
        identity: IdentityKeyPair,
        config: HostConfig,
        bind: SocketAddr,
        announce: bool,
    ) -> Result<Self, PairingMeshError> {
        let transport = start_pairing_transport(&identity, bind).await?;
        Self::with_transport(transport, identity, config, announce)
    }

    /// Build a listener on an already-bound transport.
    ///
    /// # Errors
    /// [`PairingMeshError::Net`] if `transport` was not bound to `identity`.
    /// The two must be the same key or the QUIC-authenticated identity would
    /// not be the identity being paired, and every binding check in
    /// [`HostSession::handle`] would be checking the wrong subject.
    pub fn with_transport(
        transport: Arc<MeshIroh>,
        identity: IdentityKeyPair,
        config: HostConfig,
        announce: bool,
    ) -> Result<Self, PairingMeshError> {
        if transport.local_public_key() != *identity.public().as_bytes() {
            return Err(PairingNetError::Identity(
                "pairing transport is not bound to this device's identity key".into(),
            )
            .into());
        }
        let session = Arc::new(HostSession::new(identity, config));
        let beacon = if announce {
            match announce_beacon(&transport, &session) {
                Ok(d) => Some(d),
                Err(e) => {
                    warn!(error = %e, "mDNS beacon failed; pair with the long address instead");
                    None
                }
            }
        } else {
            None
        };
        let progress = Arc::new(Notify::new());
        let server = tokio::spawn(serve_loop(
            Arc::clone(&transport),
            Arc::clone(&session),
            Arc::clone(&progress),
        ));
        Ok(Self {
            transport,
            session,
            beacon,
            progress,
            server,
        })
    }

    /// The code to read out to the other device.
    pub fn code(&self) -> PairingCode {
        self.session.code()
    }

    /// This device's fingerprint.
    pub fn local_fingerprint(&self) -> ShortFingerprint {
        self.session.local_fingerprint()
    }

    /// `<pubkey-hex>@<host>:<port>` strings this listener can be dialed on.
    ///
    /// The escape hatch when mDNS cannot cross the network in between: the
    /// other device takes one of these with `entangle pair --peer …`.
    pub fn node_addrs(&self) -> Vec<String> {
        self.transport.node_addrs()
    }

    /// True if an mDNS beacon is live.
    pub fn is_announcing(&self) -> bool {
        self.beacon.is_some()
    }

    /// The underlying session (attempt counts, expiry, outcome).
    pub fn session(&self) -> &Arc<HostSession> {
        &self.session
    }

    /// Wait for a device to pair, or for the session to end.
    ///
    /// The accept loop runs in the background from construction; this only
    /// observes it. Returns the peer that proved knowledge of the code.
    pub async fn wait(&self) -> Result<PairedPeer, PairingMeshError> {
        let ttl = self.session.ttl();
        let deadline = TokioInstant::now() + self.session.time_remaining();
        loop {
            if let Some(peer) = self.session.outcome() {
                return Ok(peer);
            }
            if self.session.is_finished() {
                return Err(finished_error(&self.session, ttl));
            }
            // Register before re-checking so a wake-up between the check above
            // and the await here cannot be lost.
            let woken = self.progress.notified();
            tokio::select! {
                () = woken => {}
                () = tokio::time::sleep_until(deadline) => {
                    // Materialise the expiry, then report it.
                    let _ = self.session.is_finished();
                    return Err(finished_error(&self.session, ttl));
                }
            }
        }
    }

    /// Tear down the beacon, the accept loop, and the endpoint.
    pub async fn shutdown(self) {
        if let Some(beacon) = &self.beacon {
            let _ = beacon.shutdown();
        }
        // Closing the endpoint makes `accept()` yield `None`, which ends the
        // serve loop on its own; the abort is the backstop.
        self.transport.shutdown().await;
        self.server.abort();
    }
}

/// Answer pairing frames on every inbound connection until the endpoint closes.
///
/// Connections are served one at a time. The protocol is two round-trips long
/// and a pairing listener has exactly one job, so serialising them also bounds
/// how fast a hostile peer can spend the session's attempt budget.
async fn serve_loop(transport: Arc<MeshIroh>, session: Arc<HostSession>, progress: Arc<Notify>) {
    loop {
        match transport.accept().await {
            Ok(Some(conn)) => serve_connection(&session, &conn, &progress).await,
            // The endpoint was shut down.
            Ok(None) => return,
            Err(e) => {
                // A failed handshake is the dialer's problem, not ours.
                debug!(error = %e, "pairing listener: dropped an inbound connection");
            }
        }
    }
}

/// Answer frames on one connection until it closes.
async fn serve_connection(session: &HostSession, conn: &MeshConn, progress: &Notify) {
    let remote_key = conn.remote_public_key();
    // One honest exchange is two frames. The cap stops a single connection
    // from being an unbounded work source; the attempt cap in `HostSession`
    // is what bounds code guesses.
    for _ in 0..MAX_FRAMES_PER_CONNECTION {
        let request = match conn.accept_request().await {
            Ok(Some(req)) => req,
            Ok(None) => break,
            Err(e) => {
                debug!(error = %e, "pairing listener: inbound frame failed");
                break;
            }
        };
        let response = session.handle(remote_key, request.payload());
        let finished = session.is_finished();
        if let Err(e) = request.respond(&response).await {
            debug!(error = %e, "pairing listener: response failed");
            break;
        }
        progress.notify_waiters();
        if finished {
            // Let the peer read that last frame and close, rather than having
            // the response discarded by an abrupt teardown.
            let _ = tokio::time::timeout(LINGER, conn.closed()).await;
            break;
        }
    }
    conn.close();
}

fn finished_error(session: &HostSession, ttl: Duration) -> PairingMeshError {
    use crate::net::SessionEnd;
    match session.ended() {
        Some(SessionEnd::AttemptsExhausted) => {
            PairingNetError::Rejected(crate::net::RejectReason::TooManyAttempts).into()
        }
        Some(SessionEnd::Paired) => PairingNetError::NoPeer.into(),
        _ => PairingMeshError::Timeout(ttl),
    }
}

/// Publish the "waiting to pair" mDNS beacon for a listener.
///
/// The TXT record carries the raw public key and the QUIC port, which is what
/// makes the sighting dialable at all — a `peer_id` is a one-way hash and
/// cannot be turned back into the key QUIC needs.
fn announce_beacon(
    transport: &MeshIroh,
    session: &HostSession,
) -> Result<Discovery, PairingMeshError> {
    let port = transport
        .local_addrs()
        .first()
        .map(SocketAddr::port)
        .unwrap_or(0);

    let discovery = Discovery::new(DiscoveryConfig {
        local: LocalPeer {
            peer_id: session.local_peer_id(),
            display_name: session.display_name().to_string(),
            port,
            version: env!("CARGO_PKG_VERSION").to_string(),
            hardware: None,
        },
        announce_interval_secs: 30,
        channel_capacity: 16,
    })?
    .with_service_type(PAIRING_SERVICE_TYPE)?
    .with_transport_advert(TransportAdvert::new(transport.local_public_key(), port));

    discovery.start_announcing()?;
    Ok(discovery)
}

// ── Dialer (the device that types the code) ──────────────────────────────────

/// Run the full exchange against `peer` with the code the user typed.
///
/// On success both devices have signed over `nonce ‖ code` and this side holds
/// the other's key. Nothing is persisted here — the caller shows the
/// fingerprints and asks for confirmation first.
pub async fn dial_and_pair(
    transport: &MeshIroh,
    peer: &IrohPeer,
    identity: &IdentityKeyPair,
    display_name: &str,
    code: PairingCode,
) -> Result<PairedPeer, PairingMeshError> {
    let dialer = Dialer::new(identity, display_name, code);
    let conn = transport.connect(peer).await?;
    let remote_key = conn.remote_public_key();

    // QUIC authenticated whoever answered; make sure it is who we dialled.
    if remote_key != peer.public_key {
        conn.close();
        return Err(PairingNetError::Identity(
            "the device that answered is not the one we dialled".into(),
        )
        .into());
    }

    let result = run_exchange(&conn, &dialer, remote_key).await;
    conn.close();
    result
}

async fn run_exchange(
    conn: &MeshConn,
    dialer: &Dialer<'_>,
    remote_key: [u8; 32],
) -> Result<PairedPeer, PairingMeshError> {
    let reply = conn
        .request(&dialer.hello().encode().map_err(PairingMeshError::from)?)
        .await?;
    let offer = match PairingWire::decode(&reply).map_err(PairingMeshError::from)? {
        PairingWire::Offer(offer) => offer,
        PairingWire::Rejected { reason } => {
            return Err(PairingNetError::Rejected(reason).into());
        }
        other => {
            return Err(PairingNetError::Protocol(format!(
                "expected an offer, got {}",
                wire_name(&other)
            ))
            .into())
        }
    };
    dialer.check_offer(remote_key, &offer)?;

    let accept = PairingWire::Accept(dialer.accept_for(&offer))
        .encode()
        .map_err(PairingMeshError::from)?;
    let reply = conn.request(&accept).await?;
    let finalize = match PairingWire::decode(&reply).map_err(PairingMeshError::from)? {
        PairingWire::Finalize(f) => f,
        PairingWire::Rejected { reason } => {
            return Err(PairingNetError::Rejected(reason).into());
        }
        other => {
            return Err(PairingNetError::Protocol(format!(
                "expected a finalize, got {}",
                wire_name(&other)
            ))
            .into())
        }
    };

    Ok(dialer.finish(remote_key, &offer, &finalize)?)
}

fn wire_name(wire: &PairingWire) -> &'static str {
    match wire {
        PairingWire::Hello { .. } => "hello",
        PairingWire::Offer(_) => "offer",
        PairingWire::Accept(_) => "accept",
        PairingWire::Finalize(_) => "finalize",
        PairingWire::Rejected { .. } => "rejected",
    }
}

// ── Discovery (finding the device that shows the code) ───────────────────────

/// A device seen announcing itself as "waiting to pair".
///
/// Everything here is unauthenticated: it is what an mDNS packet claimed. It
/// becomes trustworthy only once the pairing exchange succeeds, and the
/// `public_key` was already checked to derive to `peer_id` before it got here.
#[derive(Clone, Debug)]
pub struct PairingCandidate {
    /// Announced peer id (verified to be this key's fingerprint).
    pub peer_id: PeerId,
    /// Announced display name — sanitized, still untrusted.
    pub display_name: String,
    /// Raw Ed25519 public key: what makes the candidate dialable.
    pub public_key: [u8; 32],
    /// Socket addresses to try.
    pub addrs: Vec<SocketAddr>,
    /// Advertised crate version.
    pub version: String,
}

impl PairingCandidate {
    /// The fingerprint to show in the chooser, so the user can compare it with
    /// the other device's screen *before* dialing.
    pub fn fingerprint(&self) -> ShortFingerprint {
        ShortFingerprint::from_public_key(&self.public_key)
    }

    /// Turn the sighting into a dialable descriptor.
    pub fn to_peer(&self) -> Result<IrohPeer, PairingMeshError> {
        let mut addrs = self.addrs.iter().copied();
        let first = addrs
            .next()
            .ok_or_else(|| PairingMeshError::NoAddress(self.peer_id.to_hex()))?;
        Ok(addrs.fold(IrohPeer::new(self.public_key, first), IrohPeer::with_addr))
    }

    fn from_sighting(seen: &PeerSeen) -> Option<Self> {
        Some(Self {
            peer_id: seen.peer_id,
            display_name: seen.display_name.clone(),
            public_key: seen.public_key?,
            addrs: seen.dial_targets(),
            version: seen.version.clone(),
        })
    }
}

/// Browse the LAN for devices currently in pairing mode.
///
/// Listens for `window`, then returns what it saw, sorted by display name so
/// the chooser's numbering is stable. Only sightings that carry a usable public
/// key and address are returned; anything else could not be dialled anyway.
pub async fn discover_pairing_hosts(
    local_peer_id: PeerId,
    window: Duration,
) -> Result<Vec<PairingCandidate>, PairingMeshError> {
    let discovery = Discovery::new(DiscoveryConfig {
        local: LocalPeer {
            peer_id: local_peer_id,
            display_name: String::new(),
            port: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
            hardware: None,
        },
        announce_interval_secs: 30,
        channel_capacity: 64,
    })?
    .with_service_type(PAIRING_SERVICE_TYPE)?;

    // Browse only — a device looking for a peer does not itself announce.
    discovery.spawn_browser()?;
    tokio::time::sleep(window).await;
    let seen = discovery.snapshot_peers().await;
    let _ = discovery.shutdown();

    let mut out: Vec<PairingCandidate> = seen
        .iter()
        .filter(|p| p.peer_id != local_peer_id)
        .filter_map(PairingCandidate::from_sighting)
        .filter(|c| !c.addrs.is_empty())
        .collect();
    out.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.peer_id.to_hex().cmp(&b.peer_id.to_hex()))
    });
    Ok(out)
}
