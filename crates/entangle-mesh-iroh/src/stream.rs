//! Long-lived, multi-frame bidirectional streams (`entangle/stream/1`).
//!
//! The request/response path ([`crate::MeshConn::request`]) moves exactly one
//! frame each way per QUIC stream. A streaming task (spec §7.1) needs a
//! stream that stays open and carries many frames in both directions — data
//! chunks one way, credit and heartbeat frames both ways. This module is that
//! stream, independent of what the frames mean:
//!
//! * [`FramedStream`] — one bidirectional stream with the authenticated
//!   identity of the other end, split into a [`FramedSend`] and a
//!   [`FramedRecv`] half so a protocol driver can read and write
//!   concurrently.
//! * [`crate::MeshConn::open_stream`] / [`crate::MeshConn::accept_stream`]
//!   — a QUIC bidirectional stream on a connection dialled with
//!   [`crate::ALPN_STREAM`].
//! * [`duplex_pair`] — the same framing over an in-memory pipe, for unit
//!   tests that want real byte-level framing (caps included) without a
//!   network.
//!
//! # Framing and caps
//!
//! Frames use the same `u32` big-endian length prefix as the request path.
//! Every receive checks the declared length against a cap **before** any
//! allocation — the stream's own cap, or a tighter per-frame cap a protocol
//! passes to [`FramedRecv::recv_capped`] (e.g. "the next frame may not carry
//! more than the bytes left in this stream's budget"). Bodies are read in
//! bounded steps, so a peer that declares a large in-cap frame and then
//! stalls costs one read buffer, not a frame-sized allocation.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use entangle_types::peer_id::PeerId;
use iroh::endpoint::{RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::MeshIrohError;
use crate::framing::{read_frame_or_eof, write_frame};

/// A boxed async writer: an in-memory pipe or any other non-QUIC sink.
type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;
/// A boxed async reader: a QUIC receive stream or an in-memory pipe.
type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;

/// QUIC application error code a [`FramedSend`] dropped before
/// [`FramedSend::finish`] resets its stream with.
pub const STREAM_ABANDONED: u32 = 1;

/// Where a [`FramedSend`] writes. A QUIC send stream is kept as itself so an
/// abandoned one can be reset rather than implicitly finished.
enum Writer {
    Quic(SendStream),
    Other(BoxedWrite),
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            // The trait method, not the inherent one (which has its own error type).
            Self::Quic(s) => AsyncWrite::poll_write(Pin::new(s), cx, buf),
            Self::Other(w) => Pin::new(w).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Quic(s) => AsyncWrite::poll_flush(Pin::new(s), cx),
            Self::Other(w) => Pin::new(w).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Quic(s) => AsyncWrite::poll_shutdown(Pin::new(s), cx),
            Self::Other(w) => Pin::new(w).poll_shutdown(cx),
        }
    }
}

/// The sending half of a [`FramedStream`].
///
/// Dropping it before [`FramedSend::finish`] has succeeded **resets** a QUIC
/// stream (code [`STREAM_ABANDONED`]): the peer sees a stream error rather
/// than a clean end, and the local QUIC stack discards whatever it has not
/// sent yet instead of keeping it — and the stream — alive until a peer that
/// may never read again has read it.
pub struct FramedSend {
    inner: Writer,
    max_frame_bytes: usize,
    finished: bool,
}

impl Drop for FramedSend {
    fn drop(&mut self) {
        if let (Writer::Quic(stream), false) = (&mut self.inner, self.finished) {
            // Already finished or reset by the peer: nothing to discard.
            let _ = stream.reset(VarInt::from_u32(STREAM_ABANDONED));
        }
    }
}

impl fmt::Debug for FramedSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramedSend")
            .field("max_frame_bytes", &self.max_frame_bytes)
            .finish_non_exhaustive()
    }
}

impl FramedSend {
    /// Write one frame and flush it.
    ///
    /// A payload over the stream's cap is refused with
    /// [`MeshIrohError::FrameTooLarge`] before any byte is written.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MeshIrohError> {
        write_frame(&mut self.inner, payload, self.max_frame_bytes).await?;
        self.inner
            .flush()
            .await
            .map_err(|e| MeshIrohError::Stream(format!("flushing frame: {e}")))
    }

    /// Finish the send side: the peer's next receive after the frames already
    /// sent returns `Ok(None)`.
    pub async fn finish(&mut self) -> Result<(), MeshIrohError> {
        self.inner
            .shutdown()
            .await
            .map_err(|e| MeshIrohError::Stream(format!("finishing stream: {e}")))?;
        self.finished = true;
        Ok(())
    }

    /// The largest payload [`FramedSend::send`] accepts.
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

/// The receiving half of a [`FramedStream`].
pub struct FramedRecv {
    inner: BoxedRead,
    max_frame_bytes: usize,
}

impl fmt::Debug for FramedRecv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramedRecv")
            .field("max_frame_bytes", &self.max_frame_bytes)
            .finish_non_exhaustive()
    }
}

impl FramedRecv {
    /// Read the next frame under the stream's own cap.
    ///
    /// `Ok(None)` means the peer finished its send side cleanly between
    /// frames. A frame whose declared length exceeds the cap is refused with
    /// [`MeshIrohError::FrameTooLarge`] before its body is read.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, MeshIrohError> {
        read_frame_or_eof(&mut self.inner, self.max_frame_bytes).await
    }

    /// Read the next frame under `cap`, clamped to the stream's own cap.
    ///
    /// Lets a protocol tighten the cap frame by frame from state only it
    /// knows (for example the bytes left in a stream's total budget), so an
    /// oversized frame is refused from its header alone.
    pub async fn recv_capped(&mut self, cap: usize) -> Result<Option<Vec<u8>>, MeshIrohError> {
        read_frame_or_eof(&mut self.inner, cap.min(self.max_frame_bytes)).await
    }

    /// The stream's own per-frame cap.
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

/// One long-lived bidirectional framed stream to an authenticated peer.
///
/// For a QUIC stream the remote identity is the one the handshake proved
/// (see [`crate::MeshConn::remote_peer_id`]); for a [`duplex_pair`] it is
/// whatever the test declared.
#[derive(Debug)]
pub struct FramedStream {
    send: FramedSend,
    recv: FramedRecv,
    remote_public_key: [u8; 32],
    remote_peer_id: PeerId,
}

impl FramedStream {
    /// Assemble a framed stream over arbitrary async halves.
    ///
    /// `max_frame_bytes` is clamped to [`crate::MAX_FRAME_BYTES`]; the
    /// remote identity is taken on trust from the caller, so only call this
    /// with an identity some lower layer authenticated.
    pub fn from_parts<W, R>(
        writer: W,
        reader: R,
        remote_public_key: [u8; 32],
        max_frame_bytes: usize,
    ) -> Self
    where
        W: AsyncWrite + Send + Unpin + 'static,
        R: AsyncRead + Send + Unpin + 'static,
    {
        Self::assemble(
            Writer::Other(Box::new(writer)),
            Box::new(reader),
            remote_public_key,
            max_frame_bytes,
        )
    }

    /// A framed stream over a QUIC bidirectional stream whose remote end the
    /// handshake authenticated as `remote_public_key`.
    pub(crate) fn from_quic(
        send: SendStream,
        recv: RecvStream,
        remote_public_key: [u8; 32],
        max_frame_bytes: usize,
    ) -> Self {
        Self::assemble(
            Writer::Quic(send),
            Box::new(recv),
            remote_public_key,
            max_frame_bytes,
        )
    }

    fn assemble(
        writer: Writer,
        reader: BoxedRead,
        remote_public_key: [u8; 32],
        max_frame_bytes: usize,
    ) -> Self {
        let max_frame_bytes = max_frame_bytes.clamp(1, crate::MAX_FRAME_BYTES);
        Self {
            send: FramedSend {
                inner: writer,
                max_frame_bytes,
                finished: false,
            },
            recv: FramedRecv {
                inner: reader,
                max_frame_bytes,
            },
            remote_peer_id: PeerId::from_public_key_bytes(&remote_public_key),
            remote_public_key,
        }
    }

    /// The [`PeerId`] of the other end.
    pub const fn remote_peer_id(&self) -> PeerId {
        self.remote_peer_id
    }

    /// The raw Ed25519 public key of the other end.
    pub const fn remote_public_key(&self) -> [u8; 32] {
        self.remote_public_key
    }

    /// Write one frame (see [`FramedSend::send`]).
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MeshIrohError> {
        self.send.send(payload).await
    }

    /// Read one frame (see [`FramedRecv::recv`]).
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, MeshIrohError> {
        self.recv.recv().await
    }

    /// Finish the send side (see [`FramedSend::finish`]).
    pub async fn finish(&mut self) -> Result<(), MeshIrohError> {
        self.send.finish().await
    }

    /// Split into independently usable halves.
    pub fn split(self) -> (FramedSend, FramedRecv) {
        (self.send, self.recv)
    }
}

/// Default buffer size of each direction of a [`duplex_pair`].
pub const DEFAULT_DUPLEX_BUFFER: usize = 64 * 1024;

/// Two connected in-memory [`FramedStream`]s, for tests.
///
/// The first end belongs to the holder of `a_public_key` and reports
/// `b_public_key` as its remote identity; the second is the mirror image.
/// Each direction buffers at most `buffer` bytes, so a writer whose reader
/// stops reading blocks — the same backpressure a QUIC stream applies.
pub fn duplex_pair(
    a_public_key: [u8; 32],
    b_public_key: [u8; 32],
    max_frame_bytes: usize,
    buffer: usize,
) -> (FramedStream, FramedStream) {
    let (a, b) = tokio::io::duplex(buffer.max(1));
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    (
        FramedStream::from_parts(a_write, a_read, b_public_key, max_frame_bytes),
        FramedStream::from_parts(b_write, b_read, a_public_key, max_frame_bytes),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn duplex_carries_frames_both_ways_and_reports_identities() {
        let (mut a, mut b) = duplex_pair([1; 32], [2; 32], 1024, DEFAULT_DUPLEX_BUFFER);
        assert_eq!(a.remote_public_key(), [2; 32]);
        assert_eq!(b.remote_peer_id(), PeerId::from_public_key_bytes(&[1; 32]));

        a.send(b"ping").await.unwrap();
        a.send(b"").await.unwrap();
        assert_eq!(b.recv().await.unwrap().as_deref(), Some(&b"ping"[..]));
        assert_eq!(b.recv().await.unwrap().as_deref(), Some(&b""[..]));
        b.send(b"pong").await.unwrap();
        assert_eq!(a.recv().await.unwrap().as_deref(), Some(&b"pong"[..]));

        a.finish().await.unwrap();
        assert!(b.recv().await.unwrap().is_none(), "finish is a clean end");
    }

    #[tokio::test]
    async fn per_frame_cap_is_checked_from_the_header() {
        let (mut a, b) = duplex_pair([1; 32], [2; 32], 1024, DEFAULT_DUPLEX_BUFFER);
        let (_b_send, mut b_recv) = b.split();
        a.send(&[7u8; 100]).await.unwrap();
        match b_recv.recv_capped(64).await {
            Err(MeshIrohError::FrameTooLarge { declared, max }) => {
                assert_eq!((declared, max), (100, 64));
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn per_frame_cap_cannot_exceed_the_stream_cap() {
        let (mut a, b) = duplex_pair([1; 32], [2; 32], 1024, 1 << 16);
        let (_s, mut r) = b.split();
        // The sender's own cap refuses an over-cap payload locally.
        assert!(matches!(
            a.send(&[0u8; 2048]).await,
            Err(MeshIrohError::FrameTooLarge { .. })
        ));
        a.send(&[0u8; 1000]).await.unwrap();
        assert_eq!(
            r.recv_capped(usize::MAX).await.unwrap().unwrap().len(),
            1000
        );
        assert_eq!(r.max_frame_bytes(), 1024);
    }

    #[tokio::test]
    async fn split_halves_work_concurrently() {
        let (a, b) = duplex_pair([1; 32], [2; 32], 1024, 64);
        let (mut a_send, mut a_recv) = a.split();
        let (mut b_send, mut b_recv) = b.split();
        let writer = tokio::spawn(async move {
            for i in 0..50u8 {
                a_send.send(&[i; 32]).await.unwrap();
            }
            a_send.finish().await.unwrap();
        });
        let echo = tokio::spawn(async move {
            let mut n = 0;
            while let Some(frame) = b_recv.recv().await.unwrap() {
                b_send.send(&frame[..1]).await.unwrap();
                n += 1;
            }
            b_send.finish().await.unwrap();
            n
        });
        let mut seen = Vec::new();
        while let Some(f) = a_recv.recv().await.unwrap() {
            seen.push(f[0]);
        }
        writer.await.unwrap();
        assert_eq!(echo.await.unwrap(), 50);
        assert_eq!(seen, (0..50u8).collect::<Vec<_>>());
    }
}
