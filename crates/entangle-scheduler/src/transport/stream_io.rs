//! A transport-neutral framed bidirectional stream for `entangle/stream/1`.
//!
//! The stream drivers ([`crate::stream::driver`]) need four things from a
//! stream: send a frame, finish, receive a frame under a cap checked
//! **before** the frame is allocated (optionally a cap chosen from the
//! frame's first bytes), and the transport-authenticated identity of the
//! other end. [`StreamIo`] is exactly that, over either transport:
//!
//! * `mesh.iroh` / `mesh.local`: a QUIC bidirectional stream
//!   ([`FramedStream`], length-prefixed frames, wire format unchanged);
//! * `mesh.tailscale`: a [`SealedStream`] (sealed records, the frame length
//!   authenticated in the first record).
//!
//! Both enforce the receive caps from authenticated or header data before
//! reading a frame's body, so the drivers' per-frame caps (chunk budget,
//! control-frame bound) hold the same way on both.

use entangle_mesh_iroh::{FramedRecv, FramedSend, FramedStream, MeshConn, MeshIrohError};
use entangle_mesh_tailscale::{MeshTailscaleError, SealedRecv, SealedSend, SealedStream};
use entangle_types::peer_id::PeerId;

use super::TransportKind;

/// Why a frame could not be sent or received.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// A frame declared more bytes than the cap in force; refused before
    /// its body was read (or, when sending, before anything was written).
    #[error("frame declares {declared} bytes, cap is {max} bytes")]
    TooLarge {
        /// The declared length.
        declared: u64,
        /// The cap.
        max: usize,
    },
    /// Anything else: I/O, a reset or truncated stream, a malformed frame,
    /// a revoked peer. The transport's own error text.
    #[error("{0}")]
    Io(String),
}

impl From<MeshIrohError> for FrameError {
    fn from(e: MeshIrohError) -> Self {
        match e {
            MeshIrohError::FrameTooLarge { declared, max } => Self::TooLarge { declared, max },
            other => Self::Io(other.to_string()),
        }
    }
}

impl From<MeshTailscaleError> for FrameError {
    fn from(e: MeshTailscaleError) -> Self {
        match e {
            MeshTailscaleError::FrameTooLarge { declared, max } => Self::TooLarge { declared, max },
            other => Self::Io(other.to_string()),
        }
    }
}

/// The sending half of a [`StreamIo`].
#[async_trait::async_trait]
pub trait FrameSend: Send {
    /// Write one frame and flush it; a payload over the stream's cap is
    /// refused before anything is written.
    async fn send(&mut self, payload: &[u8]) -> Result<(), FrameError>;
    /// Finish the send side: the peer's next receive returns `Ok(None)`.
    async fn finish(&mut self) -> Result<(), FrameError>;
}

/// The receiving half of a [`StreamIo`].
#[async_trait::async_trait]
pub trait FrameRecv: Send {
    /// Read the next frame under `cap` (clamped to the stream's own cap).
    /// `Ok(None)`: the peer finished its send side.
    async fn recv_capped(&mut self, cap: usize) -> Result<Option<Vec<u8>>, FrameError>;

    /// Read the next frame under `cap`, then under `cap_for(first peek
    /// bytes)`, refusing an over-cap frame before the rest of its body is
    /// read.
    async fn recv_capped_by(
        &mut self,
        cap: usize,
        peek: usize,
        cap_for: &mut (dyn for<'p> FnMut(&'p [u8]) -> usize + Send),
    ) -> Result<Option<Vec<u8>>, FrameError>;
}

#[async_trait::async_trait]
impl FrameSend for FramedSend {
    async fn send(&mut self, payload: &[u8]) -> Result<(), FrameError> {
        FramedSend::send(self, payload).await.map_err(Into::into)
    }
    async fn finish(&mut self) -> Result<(), FrameError> {
        FramedSend::finish(self).await.map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl FrameRecv for FramedRecv {
    async fn recv_capped(&mut self, cap: usize) -> Result<Option<Vec<u8>>, FrameError> {
        FramedRecv::recv_capped(self, cap).await.map_err(Into::into)
    }
    async fn recv_capped_by(
        &mut self,
        cap: usize,
        peek: usize,
        cap_for: &mut (dyn for<'p> FnMut(&'p [u8]) -> usize + Send),
    ) -> Result<Option<Vec<u8>>, FrameError> {
        FramedRecv::recv_capped_by(self, cap, peek, |p| cap_for(p))
            .await
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl FrameSend for SealedSend {
    async fn send(&mut self, payload: &[u8]) -> Result<(), FrameError> {
        SealedSend::send(self, payload).await.map_err(Into::into)
    }
    async fn finish(&mut self) -> Result<(), FrameError> {
        SealedSend::finish(self).await.map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl FrameRecv for SealedRecv {
    async fn recv_capped(&mut self, cap: usize) -> Result<Option<Vec<u8>>, FrameError> {
        SealedRecv::recv_capped(self, cap).await.map_err(Into::into)
    }
    async fn recv_capped_by(
        &mut self,
        cap: usize,
        peek: usize,
        cap_for: &mut (dyn for<'p> FnMut(&'p [u8]) -> usize + Send),
    ) -> Result<Option<Vec<u8>>, FrameError> {
        SealedRecv::recv_capped_by(self, cap, peek, |p| cap_for(p))
            .await
            .map_err(Into::into)
    }
}

/// One framed bidirectional stream to a transport-authenticated peer.
///
/// Built from a [`FramedStream`] (iroh, or an in-memory duplex in tests) or
/// a [`SealedStream`] (tailscale) with `From`, so everything that takes
/// `impl Into<StreamIo>` accepts either.
pub struct StreamIo {
    send: Box<dyn FrameSend>,
    recv: Box<dyn FrameRecv>,
    remote_public_key: [u8; 32],
    remote_peer_id: PeerId,
    transport: TransportKind,
    conn: Option<MeshConn>,
}

impl std::fmt::Debug for StreamIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamIo")
            .field("remote_peer_id", &self.remote_peer_id)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl StreamIo {
    /// Assemble a stream from halves. `remote_public_key` is taken on trust:
    /// pass only a key the transport authenticated.
    pub fn new(
        send: Box<dyn FrameSend>,
        recv: Box<dyn FrameRecv>,
        remote_public_key: [u8; 32],
        transport: TransportKind,
    ) -> Self {
        Self {
            send,
            recv,
            remote_peer_id: PeerId::from_public_key_bytes(&remote_public_key),
            remote_public_key,
            transport,
            conn: None,
        }
    }

    /// Keep an iroh connection open for as long as the stream is used, and
    /// close it when the stream is done (see
    /// [`StreamHandle`](crate::StreamHandle)).
    #[must_use]
    pub fn with_connection(mut self, conn: MeshConn) -> Self {
        self.conn = Some(conn);
        self
    }

    /// Re-label the transport (a `mesh.local` route rides the iroh
    /// endpoint, so its streams are iroh streams labelled `local`).
    #[must_use]
    pub const fn with_transport(mut self, transport: TransportKind) -> Self {
        self.transport = transport;
        self
    }

    /// The transport-authenticated [`PeerId`] of the other end.
    pub const fn remote_peer_id(&self) -> PeerId {
        self.remote_peer_id
    }

    /// The transport-authenticated Ed25519 key of the other end.
    pub const fn remote_public_key(&self) -> [u8; 32] {
        self.remote_public_key
    }

    /// The transport carrying the stream.
    pub const fn transport(&self) -> TransportKind {
        self.transport
    }

    /// The halves and the attached connection, if any. The caller owns
    /// closing the connection.
    pub fn into_parts(self) -> (Box<dyn FrameSend>, Box<dyn FrameRecv>, Option<MeshConn>) {
        (self.send, self.recv, self.conn)
    }
}

impl From<FramedStream> for StreamIo {
    fn from(io: FramedStream) -> Self {
        let key = io.remote_public_key();
        let (send, recv) = io.split();
        Self::new(Box::new(send), Box::new(recv), key, TransportKind::Iroh)
    }
}

impl From<SealedStream> for StreamIo {
    fn from(io: SealedStream) -> Self {
        let key = io.remote_public_key();
        let (send, recv) = io.split();
        Self::new(
            Box::new(send),
            Box::new(recv),
            key,
            TransportKind::Tailscale,
        )
    }
}
