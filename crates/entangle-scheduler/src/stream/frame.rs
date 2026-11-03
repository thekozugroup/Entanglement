//! The `entangle/stream/1` frames.
//!
//! Every frame on a stream is one [`StreamFrame`]: the wire version `v`
//! first, then a [`Frame`] body, postcard-encoded, one per transport frame
//! (the transport adds the `u32` length prefix and enforces the per-frame
//! cap before allocation).
//!
//! ```text
//! submitter                                   executor
//!   Open { task envelope, policy, hash } ──▶
//!                                       ◀── Accepted { observed hash, effective limits }
//!                                       ◀── Ping / Pong ──▶            (both ways, every heartbeat)
//!                                       ◀── Chunk { seq, bytes, signature }   (needs output credit)
//!   Credit { n } ──▶                                                   (output credit)
//!   Input { seq, bytes } ──▶                                           (needs input credit)
//!                                       ◀── Credit { n }                (input credit)
//!   InputEnd { chunks, bytes } ──▶
//!                                       ◀── End { chunks, bytes, transcript, signature }
//!   Cancel { reason } ──▶            or ◀── Error { reason, message } ──▶
//! ```
//!
//! Decoding follows the one-shot envelope's rules (`crate::wire`): version
//! first — so a future layout is *reported*, not misparsed — then structure,
//! then **no trailing bytes**.

use serde::{Deserialize, Serialize};

use super::error::{Reason, Side, StreamError};
use crate::work_unit::{PolicyHash, MAX_POLICY_BYTES};

/// Current stream wire version. Bump on any change to the layout of
/// [`StreamFrame`].
pub const STREAM_WIRE_VERSION: u16 = 1;

/// Longest `message` an `Error` frame may carry; longer text is truncated by
/// the sender and refused by the receiver.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 1024;

/// Upper bound on what a `Chunk` / `Input` frame carries besides the chunk
/// bytes: version, tag, sequence number, length prefix, signature.
pub const CHUNK_FRAME_OVERHEAD: usize = 128;

/// Upper bound on the encoded size of every frame other than `Open`,
/// `Chunk` and `Input`.
pub const CONTROL_FRAME_MAX: usize = 2 * 1024;

/// Upper bound on what an `Open` frame carries besides the task input.
pub const OPEN_FRAME_OVERHEAD: usize = MAX_POLICY_BYTES + 4 * 1024;

/// One frame on an `entangle/stream/1` stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamFrame {
    /// Wire version. Always the first field on the wire.
    pub v: u16,
    /// The frame itself.
    pub body: Frame,
}

/// An Ed25519 signature, `R || S`, as two fixed 32-byte halves (serde has no
/// impl for `[u8; 64]`; two halves keep the encoding fixed-size).
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature64 {
    /// `R`, the first 32 bytes.
    pub r: [u8; 32],
    /// `S`, the last 32 bytes.
    pub s: [u8; 32],
}

impl Signature64 {
    /// Split a raw 64-byte signature.
    pub fn from_bytes(raw: [u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&raw[..32]);
        s.copy_from_slice(&raw[32..]);
        Self { r, s }
    }

    /// The raw 64-byte signature.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&self.r);
        raw[32..].copy_from_slice(&self.s);
        raw
    }
}

impl std::fmt::Debug for Signature64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature64({}…)", hex::encode(&self.r[..8]))
    }
}

/// Channel limits as they travel on the wire (deliberately not
/// `entangle_types::task::ChannelSpec` itself, so a new field on the type
/// cannot silently change the wire layout).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireChannel {
    /// Largest chunk, in bytes.
    pub max_chunk_bytes: u64,
    /// Largest cumulative byte count per direction.
    pub max_total_bytes: u64,
    /// Output credit window, in chunks.
    pub credit_window: u32,
    /// Heartbeat interval, in milliseconds.
    pub heartbeat_ms: u32,
    /// Credit-exhaustion (stall) timeout, in milliseconds.
    pub credit_exhaustion_timeout_ms: u64,
}

impl From<&entangle_types::task::ChannelSpec> for WireChannel {
    fn from(c: &entangle_types::task::ChannelSpec) -> Self {
        Self {
            max_chunk_bytes: c.max_chunk_bytes,
            max_total_bytes: c.max_total_bytes,
            credit_window: c.credit_window,
            heartbeat_ms: c.heartbeat_ms,
            credit_exhaustion_timeout_ms: c.credit_exhaustion_timeout_ms,
        }
    }
}

/// The partial-result policy on the wire (see
/// `entangle_types::task::PartialResultPolicy`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WirePartial {
    /// Discard.
    Discard,
    /// Keep.
    Keep,
    /// Keep, signed.
    KeepSigned,
}

impl From<entangle_types::task::PartialResultPolicy> for WirePartial {
    fn from(p: entangle_types::task::PartialResultPolicy) -> Self {
        use entangle_types::task::PartialResultPolicy as P;
        match p {
            P::Discard => Self::Discard,
            P::Keep => Self::Keep,
            P::KeepSigned => Self::KeepSigned,
        }
    }
}

/// The task envelope: the first frame of every stream, submitter → executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenFrame {
    /// The task's UUID as raw bytes.
    pub task_id: [u8; 16],
    /// Fully-qualified plugin id.
    pub plugin: String,
    /// Initial input for `start-stream`.
    pub input: Vec<u8>,
    /// The submitter's ceiling on `input`.
    pub max_input_bytes: u64,
    /// Requested wall-clock timeout for the whole stream; the executor
    /// clamps it.
    pub timeout_ms: u64,
    /// Requested channel limits; the executor may lower them.
    pub channel: WireChannel,
    /// The submitter's partial-result policy (informational for the
    /// executor; applied by the submitter).
    pub partial_result: WirePartial,
    /// Canonical bytes of the task's integrity policy
    /// ([`crate::work_unit::canonical_policy_bytes`]).
    pub policy: Vec<u8>,
    /// `SHA-256(policy)` as sealed by the submitter (INV-INT-1).
    pub policy_hash: PolicyHash,
}

/// The executor's acceptance: what it will actually enforce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedFrame {
    /// The policy hash the executor verified and runs the task under.
    pub observed_policy_hash: PolicyHash,
    /// Effective channel limits — each at most what the submitter asked
    /// for, except the heartbeat interval, which the executor keeps within
    /// its own bounds.
    pub channel: WireChannel,
    /// Input credit window: how many `Input` chunks the submitter may have
    /// unacknowledged.
    pub input_window: u32,
    /// Effective wall-clock timeout, in milliseconds.
    pub timeout_ms: u64,
}

/// One signed output chunk, executor → submitter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkFrame {
    /// Sequence number: 0, 1, 2, … with no gaps.
    pub seq: u64,
    /// The chunk bytes.
    pub bytes: Vec<u8>,
    /// Executor signature over the chunk's signing message (see
    /// [`super::signing`]).
    pub signature: Signature64,
}

/// One input chunk, submitter → executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputFrame {
    /// Sequence number: 0, 1, 2, … with no gaps.
    pub seq: u64,
    /// The chunk bytes.
    pub bytes: Vec<u8>,
}

/// The executor's signed end of the output stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndFrame {
    /// Number of chunks sent.
    pub chunks: u64,
    /// Number of chunk bytes sent.
    pub bytes: u64,
    /// The running transcript hash over every chunk (see
    /// [`super::signing::transcript_next`]).
    pub transcript: [u8; 32],
    /// Executor signature over the end message.
    pub signature: Signature64,
}

/// The frame bodies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// Submitter → executor, first frame: the task.
    Open(OpenFrame),
    /// Executor → submitter: the task is accepted under these limits.
    Accepted(AcceptedFrame),
    /// Executor → submitter: one signed output chunk (consumes one output
    /// credit).
    Chunk(ChunkFrame),
    /// Submitter → executor: one input chunk (consumes one input credit).
    Input(InputFrame),
    /// Submitter → executor: no more input.
    InputEnd {
        /// Number of input chunks sent.
        chunks: u64,
        /// Number of input bytes sent.
        bytes: u64,
    },
    /// Either way: grant the other end `n` more data credits.
    Credit {
        /// Credits granted.
        n: u32,
    },
    /// Either way: heartbeat probe.
    Ping {
        /// Probe sequence number.
        seq: u64,
        /// Sender's clock, milliseconds since its stream start.
        ts_ms: u64,
    },
    /// Either way: heartbeat answer, echoing the ping.
    Pong {
        /// The ping's sequence number.
        seq: u64,
        /// The ping's timestamp, echoed.
        ts_ms: u64,
    },
    /// Executor → submitter: normal end of the output stream.
    End(EndFrame),
    /// Either way: the sender closed the stream.
    Error {
        /// Machine-readable reason.
        reason: Reason,
        /// Human-readable detail (untrusted on receipt).
        message: String,
    },
    /// Submitter → executor: stop.
    Cancel {
        /// Why.
        reason: Reason,
    },
}

impl Frame {
    /// A short name for logs and protocol-violation messages.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Open(_) => "Open",
            Self::Accepted(_) => "Accepted",
            Self::Chunk(_) => "Chunk",
            Self::Input(_) => "Input",
            Self::InputEnd { .. } => "InputEnd",
            Self::Credit { .. } => "Credit",
            Self::Ping { .. } => "Ping",
            Self::Pong { .. } => "Pong",
            Self::End(_) => "End",
            Self::Error { .. } => "Error",
            Self::Cancel { .. } => "Cancel",
        }
    }

    /// An `Error` frame, its message truncated to [`MAX_ERROR_MESSAGE_BYTES`].
    pub fn error(reason: Reason, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_ERROR_MESSAGE_BYTES {
            let mut cut = MAX_ERROR_MESSAGE_BYTES;
            while !message.is_char_boundary(cut) {
                cut -= 1;
            }
            message.truncate(cut);
        }
        Self::Error { reason, message }
    }
}

/// Encode `frame` at the current [`STREAM_WIRE_VERSION`].
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, StreamError> {
    postcard::to_allocvec(&StreamFrame {
        v: STREAM_WIRE_VERSION,
        body: frame.clone(),
    })
    .map_err(|e| StreamError::Transport(format!("encoding {} frame: {e}", frame.name())))
}

/// Encode `frame` without cloning it (for the large `Chunk` / `Open`).
pub fn encode_frame_owned(frame: Frame) -> Result<Vec<u8>, StreamError> {
    let name = frame.name();
    postcard::to_allocvec(&StreamFrame {
        v: STREAM_WIRE_VERSION,
        body: frame,
    })
    .map_err(|e| StreamError::Transport(format!("encoding {name} frame: {e}")))
}

/// Decode one frame from untrusted bytes sent by `from`.
///
/// Version first (an unknown version is
/// [`StreamError::UnsupportedVersion`]), then structure, then no trailing
/// bytes, then the `Error` message length.
pub fn decode_frame(bytes: &[u8], from: Side) -> Result<Frame, StreamError> {
    let malformed = |detail: String| StreamError::Protocol { by: from, detail };
    let (version, _) = postcard::take_from_bytes::<u16>(bytes)
        .map_err(|e| malformed(format!("reading frame version: {e}")))?;
    if version != STREAM_WIRE_VERSION {
        return Err(StreamError::UnsupportedVersion {
            got: version,
            expected: STREAM_WIRE_VERSION,
        });
    }
    let (frame, rest) = postcard::take_from_bytes::<StreamFrame>(bytes)
        .map_err(|e| malformed(format!("decoding frame: {e}")))?;
    if !rest.is_empty() {
        return Err(malformed(format!(
            "{} trailing bytes after the frame",
            rest.len()
        )));
    }
    if let Frame::Error { message, .. } = &frame.body {
        if message.len() > MAX_ERROR_MESSAGE_BYTES {
            return Err(malformed(format!(
                "Error message of {} bytes exceeds {MAX_ERROR_MESSAGE_BYTES}",
                message.len()
            )));
        }
    }
    Ok(frame.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> WireChannel {
        WireChannel::from(&entangle_types::task::ChannelSpec::default())
    }

    fn samples() -> Vec<Frame> {
        vec![
            Frame::Open(OpenFrame {
                task_id: [1; 16],
                plugin: "0123456789abcdef0123456789abcdef/s@0.1.0".into(),
                input: b"hi".to_vec(),
                max_input_bytes: 16,
                timeout_ms: 1000,
                channel: channel(),
                partial_result: WirePartial::KeepSigned,
                policy: vec![1, 2, 3],
                policy_hash: PolicyHash([9; 32]),
            }),
            Frame::Accepted(AcceptedFrame {
                observed_policy_hash: PolicyHash([9; 32]),
                channel: channel(),
                input_window: 4,
                timeout_ms: 5,
            }),
            Frame::Chunk(ChunkFrame {
                seq: u64::MAX,
                bytes: vec![0xab; 1000],
                signature: Signature64::from_bytes([0xff; 64]),
            }),
            Frame::Input(InputFrame {
                seq: 3,
                bytes: b"more".to_vec(),
            }),
            Frame::InputEnd {
                chunks: u64::MAX,
                bytes: u64::MAX,
            },
            Frame::Credit { n: u32::MAX },
            Frame::Ping {
                seq: u64::MAX,
                ts_ms: u64::MAX,
            },
            Frame::Pong { seq: 1, ts_ms: 2 },
            Frame::End(EndFrame {
                chunks: u64::MAX,
                bytes: u64::MAX,
                transcript: [7; 32],
                signature: Signature64::from_bytes([0xff; 64]),
            }),
            Frame::error(Reason::Busy, "x".repeat(MAX_ERROR_MESSAGE_BYTES)),
            Frame::Cancel {
                reason: Reason::Cancelled,
            },
        ]
    }

    #[test]
    fn every_frame_round_trips() {
        for f in samples() {
            let bytes = encode_frame(&f).unwrap();
            assert_eq!(decode_frame(&bytes, Side::Executor).unwrap(), f);
        }
    }

    /// The documented size bounds really bound the encodings, at the
    /// extreme values of every field.
    #[test]
    fn size_bounds_hold_at_the_extremes() {
        for f in samples() {
            let len = encode_frame(&f).unwrap().len();
            match &f {
                Frame::Chunk(c) => assert!(len <= c.bytes.len() + CHUNK_FRAME_OVERHEAD, "{len}"),
                Frame::Input(c) => assert!(len <= c.bytes.len() + CHUNK_FRAME_OVERHEAD, "{len}"),
                Frame::Open(o) => assert!(len <= o.input.len() + OPEN_FRAME_OVERHEAD),
                other => assert!(len <= CONTROL_FRAME_MAX, "{} is {len}", other.name()),
            }
        }
    }

    #[test]
    fn signature_halves_round_trip() {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(Signature64::from_bytes(raw).to_bytes(), raw);
    }

    #[test]
    fn future_version_is_reported_not_misparsed() {
        let bytes = postcard::to_allocvec(&StreamFrame {
            v: STREAM_WIRE_VERSION + 1,
            body: Frame::Credit { n: 1 },
        })
        .unwrap();
        assert_eq!(
            decode_frame(&bytes, Side::Submitter),
            Err(StreamError::UnsupportedVersion {
                got: STREAM_WIRE_VERSION + 1,
                expected: STREAM_WIRE_VERSION
            })
        );
    }

    #[test]
    fn trailing_bytes_and_garbage_are_protocol_errors() {
        let mut bytes = encode_frame(&Frame::Credit { n: 1 }).unwrap();
        bytes.push(0);
        assert!(matches!(
            decode_frame(&bytes, Side::Executor),
            Err(StreamError::Protocol { by: Side::Executor, detail }) if detail.contains("trailing")
        ));
        for seed in 0u8..=255 {
            let junk: Vec<u8> = (0..48u8).map(|i| i.wrapping_mul(seed) ^ 0x5a).collect();
            let _ = decode_frame(&junk, Side::Executor);
        }
        assert!(decode_frame(&[], Side::Executor).is_err());
    }

    #[test]
    fn oversized_error_message_is_truncated_on_send_and_refused_on_receipt() {
        let long = "é".repeat(MAX_ERROR_MESSAGE_BYTES);
        let Frame::Error { message, .. } = Frame::error(Reason::Internal, long.clone()) else {
            panic!("not an error frame");
        };
        assert!(message.len() <= MAX_ERROR_MESSAGE_BYTES);
        let raw = postcard::to_allocvec(&StreamFrame {
            v: STREAM_WIRE_VERSION,
            body: Frame::Error {
                reason: Reason::Internal,
                message: long,
            },
        })
        .unwrap();
        assert!(decode_frame(&raw, Side::Executor).is_err());
    }
}
