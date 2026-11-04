//! Long-lived, multi-frame bidirectional streams over a sealed tailnet
//! connection (`entangle/stream/1` on `mesh.tailscale`).
//!
//! The request/response mode of [`MeshConn`](crate::MeshConn) moves one
//! frame each way at a time. A streaming task (spec §7.1) needs both
//! directions open at once with many frames on each, so
//! [`MeshConn::into_stream`](crate::MeshConn::into_stream) turns a connection
//! into a [`SealedStream`]: the TCP stream split into a [`SealedSend`] and a
//! [`SealedRecv`], each owning its direction's session key.
//!
//! # Wire format
//!
//! One logical frame is one or more sealed records (see `framing`), each at
//! most [`FRAGMENT_BYTES`] of payload:
//!
//! ```text
//! first record : kind(1) ‖ total_len (u32 BE) ‖ payload[.. min(total_len, FRAGMENT_BYTES)]
//! continuation : the next min(remaining, FRAGMENT_BYTES) payload bytes, exactly
//! kind         : 0x01 frame, 0x02 finish (total_len 0, nothing follows)
//! ```
//!
//! # Caps, checked before allocation
//!
//! A frame's length is in its first record, which is *authenticated*: it is
//! read under a fixed one-fragment cap (compared with the record header
//! before anything is allocated), opened, and only then is the declared
//! total compared with the receiver's cap, refusing an over-cap frame before
//! a byte of the rest is read. A per-frame cap chosen from the frame's first
//! bytes ([`SealedRecv::recv_capped_by`]) is applied the same way: the bytes
//! it looks at are authenticated. Bodies arrive one record at a time, so a
//! peer that declares a large in-cap frame and stalls costs one fragment of
//! memory, not a frame-sized buffer.
//!
//! # Ending a stream
//!
//! [`SealedSend::finish`] sends a sealed *finish* record and then closes the
//! TCP write side; the peer's next receive returns `Ok(None)`. A TCP close
//! **without** that record (a crashed or abandoned sender, or a relay
//! cutting the connection) is an error, not a clean end: truncation cannot
//! pass for completion. Dropping a [`SealedSend`] unfinished therefore looks
//! like a reset to the peer, as on a QUIC stream.
//!
//! In `entangle-on-top` mode the server side re-checks its allowlist for
//! every frame it receives, so a revoked peer's stream stops at its next
//! frame.

use std::sync::Arc;

use entangle_types::peer_id::PeerId;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::error::MeshTailscaleError;
use crate::framing::{read_sealed, read_sealed_opt, write_sealed, Opener, Sealer};
use crate::transport::{ConnSlot, PeerAllowlist};

/// Most payload bytes one record of a stream frame carries.
pub const FRAGMENT_BYTES: usize = 64 * 1024;

/// `kind ‖ total_len`.
const FIRST_HEADER: usize = 1 + 4;
/// Record kind: a data frame.
const KIND_FRAME: u8 = 0x01;
/// Record kind: the sender finished its side.
const KIND_FINISH: u8 = 0x02;

/// The connection-cap slot a server-side stream holds until both halves go.
type SharedSlot = Arc<Option<ConnSlot>>;

/// The sending half of a [`SealedStream`].
pub struct SealedSend {
    pub(crate) write: OwnedWriteHalf,
    pub(crate) sealer: Sealer,
    max_frame_bytes: usize,
    finished: bool,
    /// Set while a frame is being written and left set if that write does
    /// not complete: the stream is then torn and refuses further frames.
    torn: bool,
    _slot: SharedSlot,
}

impl std::fmt::Debug for SealedSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedSend")
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl SealedSend {
    /// Write one frame and flush it.
    ///
    /// A payload over the stream's cap is refused with
    /// [`MeshTailscaleError::FrameTooLarge`] before any byte is written.
    /// A write that fails or is cancelled part-way leaves the stream torn:
    /// later sends fail.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MeshTailscaleError> {
        if payload.len() > self.max_frame_bytes {
            return Err(MeshTailscaleError::FrameTooLarge {
                declared: payload.len() as u64,
                max: self.max_frame_bytes,
            });
        }
        self.usable()?;
        // In range: `max_frame_bytes` is clamped to `MAX_FRAME_BYTES` (64 MiB).
        let total =
            u32::try_from(payload.len()).map_err(|_| MeshTailscaleError::FrameTooLarge {
                declared: payload.len() as u64,
                max: self.max_frame_bytes,
            })?;
        self.torn = true;
        let head_len = payload.len().min(FRAGMENT_BYTES);
        let mut first = Vec::with_capacity(FIRST_HEADER + head_len);
        first.push(KIND_FRAME);
        first.extend_from_slice(&total.to_be_bytes());
        first.extend_from_slice(&payload[..head_len]);
        write_sealed(
            &mut self.write,
            &mut self.sealer,
            &first,
            FIRST_HEADER + FRAGMENT_BYTES,
        )
        .await?;
        for fragment in payload[head_len..].chunks(FRAGMENT_BYTES) {
            write_sealed(&mut self.write, &mut self.sealer, fragment, FRAGMENT_BYTES).await?;
        }
        self.torn = false;
        Ok(())
    }

    /// Finish the send side: the peer's next receive after the frames
    /// already sent returns `Ok(None)`.
    pub async fn finish(&mut self) -> Result<(), MeshTailscaleError> {
        self.usable()?;
        self.torn = true;
        let mut record = vec![KIND_FINISH];
        record.extend_from_slice(&0u32.to_be_bytes());
        write_sealed(&mut self.write, &mut self.sealer, &record, FIRST_HEADER).await?;
        self.write
            .shutdown()
            .await
            .map_err(|e| MeshTailscaleError::Stream(format!("finishing stream: {e}")))?;
        self.finished = true;
        self.torn = false;
        Ok(())
    }

    /// The largest payload [`SealedSend::send`] accepts.
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    fn usable(&self) -> Result<(), MeshTailscaleError> {
        if self.finished {
            return Err(MeshTailscaleError::Stream(
                "the stream's send side is already finished".into(),
            ));
        }
        if self.torn {
            return Err(MeshTailscaleError::Stream(
                "the stream is unusable after an earlier failed or cancelled send".into(),
            ));
        }
        Ok(())
    }
}

/// The receiving half of a [`SealedStream`].
pub struct SealedRecv {
    pub(crate) read: OwnedReadHalf,
    pub(crate) opener: Opener,
    max_frame_bytes: usize,
    peer: PeerId,
    /// Server side, `entangle-on-top`: consulted before each frame is
    /// handed out.
    allowlist: Option<Arc<dyn PeerAllowlist>>,
    /// The peer sent its finish record.
    ended: bool,
    /// An earlier receive failed part-way; the byte stream is out of step.
    failed: bool,
    _slot: SharedSlot,
}

impl std::fmt::Debug for SealedRecv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedRecv")
            .field("peer", &self.peer)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl SealedRecv {
    /// Read the next frame under the stream's own cap.
    ///
    /// `Ok(None)` means the peer finished its send side. A frame over the
    /// cap is refused with [`MeshTailscaleError::FrameTooLarge`] after its
    /// first record, before the rest is read.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, MeshTailscaleError> {
        self.recv_capped(self.max_frame_bytes).await
    }

    /// Read the next frame under `cap`, clamped to the stream's own cap.
    pub async fn recv_capped(&mut self, cap: usize) -> Result<Option<Vec<u8>>, MeshTailscaleError> {
        self.recv_capped_by(cap, 0, |_| cap).await
    }

    /// Read the next frame under a cap chosen by what the frame is: the
    /// declared length is checked against `cap` (clamped to the stream's
    /// own cap), then `cap_for` is given the frame's first `peek` bytes
    /// (fewer if the frame, or its first record, is shorter) and the frame
    /// is refused if it is longer than the cap it returns — before anything
    /// after the first record is read.
    pub async fn recv_capped_by<F>(
        &mut self,
        cap: usize,
        peek: usize,
        cap_for: F,
    ) -> Result<Option<Vec<u8>>, MeshTailscaleError>
    where
        F: FnOnce(&[u8]) -> usize,
    {
        if self.ended {
            return Ok(None);
        }
        if self.failed {
            return Err(MeshTailscaleError::Stream(
                "the stream is unusable after an earlier failed receive".into(),
            ));
        }
        self.failed = true;
        let out = self.read_frame(cap, peek, cap_for).await;
        if out.is_ok() {
            self.failed = false;
        }
        out
    }

    async fn read_frame<F>(
        &mut self,
        cap: usize,
        peek: usize,
        cap_for: F,
    ) -> Result<Option<Vec<u8>>, MeshTailscaleError>
    where
        F: FnOnce(&[u8]) -> usize,
    {
        let first = match read_sealed_opt(
            &mut self.read,
            &mut self.opener,
            FIRST_HEADER + FRAGMENT_BYTES,
        )
        .await
        {
            Ok(Some(record)) => record,
            Ok(None) => {
                return Err(MeshTailscaleError::Stream(
                    "the peer closed the stream without finishing it (abandoned or cut off)".into(),
                ))
            }
            Err(MeshTailscaleError::FrameTooLarge { declared, .. }) => {
                return Err(MeshTailscaleError::Protocol(format!(
                    "a stream record declares {declared} bytes, more than one fragment"
                )))
            }
            Err(e) => return Err(e),
        };
        if let Some(list) = &self.allowlist {
            if !list.is_allowed(&self.peer) {
                return Err(MeshTailscaleError::PeerNotAllowed(self.peer));
            }
        }
        let (kind, rest) = match first.split_first() {
            Some((&k, rest)) if rest.len() >= 4 => (k, rest),
            _ => {
                return Err(MeshTailscaleError::Protocol(
                    "stream record shorter than its header".into(),
                ))
            }
        };
        let (len_bytes, head) = rest.split_at(4);
        let mut len = [0u8; 4];
        len.copy_from_slice(len_bytes);
        let declared = u64::from(u32::from_be_bytes(len));
        match kind {
            KIND_FINISH if declared == 0 && head.is_empty() => {
                self.ended = true;
                return Ok(None);
            }
            KIND_FRAME => {}
            _ => {
                return Err(MeshTailscaleError::Protocol(format!(
                    "unknown or malformed stream record (kind {kind:#04x})"
                )))
            }
        }
        let max = cap.min(self.max_frame_bytes);
        if declared > max as u64 {
            return Err(MeshTailscaleError::FrameTooLarge { declared, max });
        }
        // In bounds of `max`, a usize.
        let total = declared as usize;
        if head.len() != total.min(FRAGMENT_BYTES) {
            return Err(MeshTailscaleError::Protocol(format!(
                "stream frame of {total} bytes starts with a {}-byte record",
                head.len()
            )));
        }
        let frame_cap = cap_for(&head[..peek.min(head.len())]).min(max);
        if total > frame_cap {
            return Err(MeshTailscaleError::FrameTooLarge {
                declared,
                max: frame_cap,
            });
        }
        let mut body = first;
        body.drain(..FIRST_HEADER);
        while body.len() < total {
            let want = (total - body.len()).min(FRAGMENT_BYTES);
            let fragment = match read_sealed(&mut self.read, &mut self.opener, FRAGMENT_BYTES).await
            {
                Ok(f) => f,
                Err(MeshTailscaleError::FrameTooLarge { declared, .. }) => {
                    return Err(MeshTailscaleError::Protocol(format!(
                        "a stream record declares {declared} bytes, more than one fragment"
                    )))
                }
                Err(e) => return Err(e),
            };
            if fragment.len() != want {
                return Err(MeshTailscaleError::Protocol(format!(
                    "stream fragment of {} bytes where {want} were due",
                    fragment.len()
                )));
            }
            body.extend_from_slice(&fragment);
        }
        Ok(Some(body))
    }

    /// The stream's own per-frame cap.
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

/// One long-lived bidirectional framed stream to an authenticated peer, over
/// a sealed tailnet connection. See the module docs.
#[derive(Debug)]
pub struct SealedStream {
    send: SealedSend,
    recv: SealedRecv,
    remote_public_key: [u8; 32],
    remote_peer_id: PeerId,
}

impl SealedStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assemble(
        read: OwnedReadHalf,
        write: OwnedWriteHalf,
        sealer: Sealer,
        opener: Opener,
        remote_public_key: [u8; 32],
        remote_peer_id: PeerId,
        allowlist: Option<Arc<dyn PeerAllowlist>>,
        slot: Option<ConnSlot>,
        max_frame_bytes: usize,
    ) -> Self {
        let slot: SharedSlot = Arc::new(slot);
        Self {
            send: SealedSend {
                write,
                sealer,
                max_frame_bytes,
                finished: false,
                torn: false,
                _slot: Arc::clone(&slot),
            },
            recv: SealedRecv {
                read,
                opener,
                max_frame_bytes,
                peer: remote_peer_id,
                allowlist,
                ended: false,
                failed: false,
                _slot: slot,
            },
            remote_public_key,
            remote_peer_id,
        }
    }

    /// The authenticated [`PeerId`] of the other end.
    pub const fn remote_peer_id(&self) -> PeerId {
        self.remote_peer_id
    }

    /// The authenticated Ed25519 public key of the other end.
    pub const fn remote_public_key(&self) -> [u8; 32] {
        self.remote_public_key
    }

    /// Write one frame (see [`SealedSend::send`]).
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MeshTailscaleError> {
        self.send.send(payload).await
    }

    /// Read one frame (see [`SealedRecv::recv`]).
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, MeshTailscaleError> {
        self.recv.recv().await
    }

    /// Finish the send side (see [`SealedSend::finish`]).
    pub async fn finish(&mut self) -> Result<(), MeshTailscaleError> {
        self.send.finish().await
    }

    /// Split into independently usable halves.
    pub fn split(self) -> (SealedSend, SealedRecv) {
        (self.send, self.recv)
    }
}
