//! The two concrete links: the iroh endpoint (as `mesh.iroh` or
//! `mesh.local`) and the tailnet transport.

use std::collections::HashMap;
use std::sync::Arc;

use entangle_mesh_iroh::{DynMeshTransport, MeshIroh, MeshIrohError, ALPN_SCHEDULER, ALPN_STREAM};
use entangle_mesh_tailscale::{
    LivenessSnapshot, MeshConn, MeshTailscale, MeshTailscaleError, TailnetState,
};
use entangle_types::peer_id::PeerId;
use parking_lot::Mutex;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use super::{
    Availability, DialTarget, FrameError, FrameRecv, FrameSend, Link, LinkError, Outbound,
    StreamIo, TransportKind,
};
use crate::remote::PeerAddressBook;

/// Classify an iroh error: failures while dialling or authenticating
/// delivered nothing.
fn iroh_error(e: MeshIrohError) -> LinkError {
    match e {
        MeshIrohError::Connect { .. }
        | MeshIrohError::ConnectTimeout { .. }
        | MeshIrohError::Identity(_)
        | MeshIrohError::BadNodeAddr(_) => LinkError::Connect(e.to_string()),
        MeshIrohError::FrameTooLarge { declared, max } => {
            LinkError::FrameTooLarge { declared, max }
        }
        other => LinkError::Transport(other.to_string()),
    }
}

/// The iroh endpoint as a link.
///
/// As [`TransportKind::Iroh`] its targets come from the `[scheduler] peers`
/// address book; as [`TransportKind::Local`] ([`IrohLink::local`]) from mDNS
/// sightings — LAN addresses dialled directly over the same endpoint (spec
/// §6.1 `mesh.local`: "mDNS discovery + Iroh direct streams"). Either way
/// the QUIC handshake authenticates the key the target names.
pub struct IrohLink {
    kind: TransportKind,
    transport: DynMeshTransport,
    streams: Option<Arc<MeshIroh>>,
    book: Arc<dyn PeerAddressBook>,
}

impl std::fmt::Debug for IrohLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohLink")
            .field("kind", &self.kind)
            .field("local_peer_id", &self.transport.local_peer_id())
            .field("streams", &self.streams.is_some())
            .field("book", &self.book)
            .finish()
    }
}

impl IrohLink {
    /// `mesh.iroh` over `transport` (which must speak
    /// [`ALPN_SCHEDULER`]), dialling the addresses `book` knows.
    pub fn new(transport: DynMeshTransport, book: Arc<dyn PeerAddressBook>) -> Self {
        Self {
            kind: TransportKind::Iroh,
            transport,
            streams: None,
            book,
        }
    }

    /// `mesh.local`: the same endpoint, dialling the LAN addresses of mDNS
    /// sightings that `sightings` holds.
    pub fn local(transport: DynMeshTransport, sightings: Arc<dyn PeerAddressBook>) -> Self {
        Self {
            kind: TransportKind::Local,
            ..Self::new(transport, sightings)
        }
    }

    /// Open streams through `endpoint` (dialled with [`ALPN_STREAM`]);
    /// without it this link carries one-shot requests only.
    #[must_use]
    pub fn with_streams(mut self, endpoint: Arc<MeshIroh>) -> Self {
        self.streams = Some(endpoint);
        self
    }
}

#[async_trait::async_trait]
impl Link for IrohLink {
    fn kind(&self) -> TransportKind {
        self.kind
    }

    fn target(&self, peer: &PeerId) -> Option<DialTarget> {
        self.book.lookup(peer).map(DialTarget::Iroh)
    }

    async fn request(
        &self,
        target: &DialTarget,
        outbound: &Outbound<'_>,
    ) -> Result<Vec<u8>, LinkError> {
        let DialTarget::Iroh(peer) = target else {
            return Err(LinkError::Connect("not an iroh dial target".into()));
        };
        // The transport asks for the frame once its QUIC connection is up.
        self.transport
            .request_with(peer, &|| outbound.frame())
            .await
            .map_err(iroh_error)
    }

    async fn open_stream(&self, target: &DialTarget) -> Result<StreamIo, LinkError> {
        let DialTarget::Iroh(peer) = target else {
            return Err(LinkError::Connect("not an iroh dial target".into()));
        };
        let Some(endpoint) = &self.streams else {
            return Err(LinkError::Connect(
                "this iroh link carries no streams".into(),
            ));
        };
        let conn = endpoint
            .connect_alpn(peer, ALPN_STREAM)
            .await
            .map_err(iroh_error)?;
        match conn.open_stream().await {
            // Nothing has been sent yet: the peer learns of a QUIC stream
            // with its first frame.
            Ok(io) => Ok(StreamIo::from(io)
                .with_connection(conn)
                .with_transport(self.kind)),
            Err(e) => {
                conn.close();
                Err(LinkError::Connect(e.to_string()))
            }
        }
    }
}

/// The tailnet transport as a link.
///
/// Usable only while the liveness poller reports the tailnet `active` (spec
/// §6.1.1: a peer reachable only via `mesh.tailscale` is unreachable while
/// it is not); its targets are the candidates the last discovery round
/// found. Each request or stream is one connection: handshake (pinning the
/// candidate's key), then the sub-protocol selection, then the traffic.
///
/// The peer's listener caps what one node may hold there: 8 handshakes in
/// flight per source address (more are dropped unanswered) and
/// `max_connections_per_peer` established connections (more are refused
/// as `connection limit`). Since every request holds a connection until
/// its answer, and every stream for its life, a burst of concurrent work
/// to one peer would run into both. So the link keeps under them itself,
/// per peer: at most 4 connection setups at a time,
/// and at most this node's own `max_connections_per_peer` (the default is
/// the same on every node) connections open. Work beyond that waits for a
/// slot — up to the transport's request timeout, the longest a request
/// holds one — as connection setup, so the router's connect deadline
/// applies to the wait too.
#[derive(Debug, Clone)]
pub struct TailscaleLink {
    transport: MeshTailscale,
    liveness: watch::Receiver<LivenessSnapshot>,
    slots: Arc<Mutex<HashMap<PeerId, Arc<PeerSlots>>>>,
}

/// Connection setups (dial, handshake, protocol selection) one node runs at
/// once to one tailnet peer: half the listener's per-source cap of 8, which
/// leaves room for handshakes the listener has not finished counting down.
const MAX_SETUPS_PER_PEER: usize = 4;

/// One peer's slots; see [`TailscaleLink`].
#[derive(Debug)]
struct PeerSlots {
    setups: Semaphore,
    open: Arc<Semaphore>,
}

impl TailscaleLink {
    /// A link over `transport`, gated on `liveness`.
    pub fn new(transport: MeshTailscale, liveness: watch::Receiver<LivenessSnapshot>) -> Self {
        Self {
            transport,
            liveness,
            slots: Arc::default(),
        }
    }

    /// The transport.
    pub const fn transport(&self) -> &MeshTailscale {
        &self.transport
    }

    /// `peer`'s slots. One entry per peer ever dialled: discovery
    /// candidates, i.e. trusted peers, so the map stays small.
    fn slots(&self, peer: PeerId) -> Arc<PeerSlots> {
        let open = self.transport.config().max_connections_per_peer.max(1);
        Arc::clone(self.slots.lock().entry(peer).or_insert_with(|| {
            Arc::new(PeerSlots {
                setups: Semaphore::new(MAX_SETUPS_PER_PEER),
                open: Arc::new(Semaphore::new(open)),
            })
        }))
    }

    /// Take one of the peer's connection slots, then connect and select
    /// `protocol`. The connection holds the returned slot until both are
    /// dropped (connection first).
    async fn connect(
        &self,
        target: &DialTarget,
        protocol: &[u8],
    ) -> Result<(MeshConn, OwnedSemaphorePermit), LinkError> {
        let DialTarget::Tailscale(peer) = target else {
            return Err(LinkError::Connect("not a tailnet dial target".into()));
        };
        let slots = self.slots(peer.peer_id);
        let wait = self.transport.config().request_timeout;
        let busy = || {
            LinkError::Connect(format!(
                "every connection this node may hold to peer {} is in use, and none was \
                 freed within {}ms",
                peer.peer_id,
                wait.as_millis()
            ))
        };
        // The semaphores are never closed, so `acquire` fails only on
        // timeout.
        let open = tokio::time::timeout(wait, Arc::clone(&slots.open).acquire_owned())
            .await
            .map_err(|_| busy())?
            .map_err(|_| busy())?;
        let setup = tokio::time::timeout(wait, slots.setups.acquire())
            .await
            .map_err(|_| busy())?
            .map_err(|_| busy())?;
        // Every error before the selection is answered happens before any
        // application data is sent.
        let conn = self
            .transport
            .connect_protocol(peer, protocol)
            .await
            .map_err(|e| LinkError::Connect(e.to_string()))?;
        drop(setup);
        Ok((conn, open))
    }
}

/// A stream half that holds its connection's slot (see [`TailscaleLink`]):
/// the slot is freed once both halves, and so the connection, are gone.
struct Held<T> {
    // Dropped first: the connection closes before its slot is freed.
    inner: T,
    _slot: Arc<OwnedSemaphorePermit>,
}

#[async_trait::async_trait]
impl<T: FrameSend> FrameSend for Held<T> {
    async fn send(&mut self, payload: &[u8]) -> Result<(), FrameError> {
        self.inner.send(payload).await
    }
    async fn finish(&mut self) -> Result<(), FrameError> {
        self.inner.finish().await
    }
}

#[async_trait::async_trait]
impl<T: FrameRecv> FrameRecv for Held<T> {
    async fn recv_capped(&mut self, cap: usize) -> Result<Option<Vec<u8>>, FrameError> {
        self.inner.recv_capped(cap).await
    }
    async fn recv_capped_by(
        &mut self,
        cap: usize,
        peek: usize,
        cap_for: &mut (dyn for<'p> FnMut(&'p [u8]) -> usize + Send),
    ) -> Result<Option<Vec<u8>>, FrameError> {
        self.inner.recv_capped_by(cap, peek, cap_for).await
    }
}

fn tailscale_error(e: MeshTailscaleError) -> LinkError {
    match e {
        MeshTailscaleError::FrameTooLarge { declared, max } => {
            LinkError::FrameTooLarge { declared, max }
        }
        other => LinkError::Transport(other.to_string()),
    }
}

#[async_trait::async_trait]
impl Link for TailscaleLink {
    fn kind(&self) -> TransportKind {
        TransportKind::Tailscale
    }

    fn availability(&self) -> Availability {
        match &self.liveness.borrow().state {
            Some(TailnetState::Active) => Availability::Ready,
            Some(TailnetState::Stopped { reason }) => {
                Availability::Down(format!("tailnet stopped ({reason})"))
            }
            Some(TailnetState::Uninstalled) => {
                Availability::Down("tailscale is not installed".into())
            }
            None => Availability::Down("tailnet state not known yet".into()),
        }
    }

    fn target(&self, peer: &PeerId) -> Option<DialTarget> {
        self.transport.candidate(peer).map(DialTarget::Tailscale)
    }

    async fn request(
        &self,
        target: &DialTarget,
        outbound: &Outbound<'_>,
    ) -> Result<Vec<u8>, LinkError> {
        let (mut conn, slot) = self.connect(target, ALPN_SCHEDULER).await?;
        // Handshake done and protocol selected: build the frame now.
        let frame = outbound.frame();
        let answer = conn.request(&frame).await.map_err(tailscale_error);
        // The connection closes before its slot is freed.
        drop(conn);
        drop(slot);
        answer
    }

    async fn open_stream(&self, target: &DialTarget) -> Result<StreamIo, LinkError> {
        let (conn, slot) = self.connect(target, ALPN_STREAM).await?;
        let io = conn
            .into_stream()
            .map_err(|e| LinkError::Connect(e.to_string()))?;
        let key = io.remote_public_key();
        let (send, recv) = io.split();
        let slot = Arc::new(slot);
        Ok(StreamIo::new(
            Box::new(Held {
                inner: send,
                _slot: Arc::clone(&slot),
            }),
            Box::new(Held {
                inner: recv,
                _slot: slot,
            }),
            key,
            TransportKind::Tailscale,
        ))
    }
}
