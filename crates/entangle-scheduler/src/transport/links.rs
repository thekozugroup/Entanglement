//! The two concrete links: the iroh endpoint (as `mesh.iroh` or
//! `mesh.local`) and the tailnet transport.

use std::sync::Arc;

use entangle_mesh_iroh::{DynMeshTransport, MeshIroh, MeshIrohError, ALPN_SCHEDULER, ALPN_STREAM};
use entangle_mesh_tailscale::{LivenessSnapshot, MeshTailscale, MeshTailscaleError, TailnetState};
use entangle_types::peer_id::PeerId;
use tokio::sync::watch;

use super::{Availability, DialTarget, Link, LinkError, StreamIo, TransportKind};
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

    async fn request(&self, target: &DialTarget, payload: &[u8]) -> Result<Vec<u8>, LinkError> {
        let DialTarget::Iroh(peer) = target else {
            return Err(LinkError::Connect("not an iroh dial target".into()));
        };
        self.transport
            .request(peer, payload)
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
#[derive(Debug, Clone)]
pub struct TailscaleLink {
    transport: MeshTailscale,
    liveness: watch::Receiver<LivenessSnapshot>,
}

impl TailscaleLink {
    /// A link over `transport`, gated on `liveness`.
    pub fn new(transport: MeshTailscale, liveness: watch::Receiver<LivenessSnapshot>) -> Self {
        Self {
            transport,
            liveness,
        }
    }

    /// The transport.
    pub const fn transport(&self) -> &MeshTailscale {
        &self.transport
    }

    async fn connect(
        &self,
        target: &DialTarget,
        protocol: &[u8],
    ) -> Result<entangle_mesh_tailscale::MeshConn, LinkError> {
        let DialTarget::Tailscale(peer) = target else {
            return Err(LinkError::Connect("not a tailnet dial target".into()));
        };
        // Every error before the selection is answered happens before any
        // application data is sent.
        self.transport
            .connect_protocol(peer, protocol)
            .await
            .map_err(|e| LinkError::Connect(e.to_string()))
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

    async fn request(&self, target: &DialTarget, payload: &[u8]) -> Result<Vec<u8>, LinkError> {
        let mut conn = self.connect(target, ALPN_SCHEDULER).await?;
        conn.request(payload).await.map_err(tailscale_error)
    }

    async fn open_stream(&self, target: &DialTarget) -> Result<StreamIo, LinkError> {
        let conn = self.connect(target, ALPN_STREAM).await?;
        conn.into_stream()
            .map(StreamIo::from)
            .map_err(|e| LinkError::Connect(e.to_string()))
    }
}
