//! Streaming tasks (spec §7.1, §7.5, §16.5): a long-lived, credit-controlled,
//! signed chunk stream from one executor back to its submitter.
//!
//! # Layers
//!
//! * [`frame`] — the versioned `entangle/stream/1` frames: `Open` (the task
//!   envelope with its policy and `policy_hash`, as the one-shot path
//!   sends), `Accepted`, `Chunk { seq, bytes, signature }`, `Input`,
//!   `Credit { n }`, `Ping` / `Pong`, `End { totals, transcript, signature }`,
//!   `Error`, `Cancel`.
//! * [`executor`] / [`submitter`] — the two ends as **pure state machines**
//!   driven by explicit `now` values: credit flow control and the
//!   `Stalled` state (ATC-STR-1), heartbeats (ATC-STR-2), chunk signing and
//!   verification (ATC-STR-3), and the `max_chunk_bytes` /
//!   `max_total_bytes` caps on both ends (ATC-INT-6).
//! * [`heartbeat`] — the ping / missed-pong logic both ends share.
//! * [`signing`] — the chunk signing message and the transcript chain.
//! * [`validate`] — submit-time validation (ATC-INT-4) and the executor's
//!   ceilings.
//! * [`partial`] — the stream's result, with `PartialResultPolicy` applied.
//! * [`driver`] — async drivers that run the machines on real time over a
//!   [`FramedStream`](entangle_mesh_iroh::FramedStream) — a QUIC stream
//!   under [`ALPN_STREAM`](entangle_mesh_iroh::ALPN_STREAM), or an
//!   in-memory duplex in tests.
//! * [`server`] — the executor service ([`StreamServer`]) and the client
//!   entry point ([`open_stream`]).
//!
//! # Security boundary
//!
//! [`StreamServer`] turns an inbound stream into a plugin execution on this
//! node, exactly like the one-shot [`RemoteTaskServer`](crate::RemoteTaskServer),
//! and gates it the same way: the transport-authenticated caller must be in
//! the [`PeerAllowlist`](crate::PeerAllowlist) **before a byte of the
//! stream is decoded**, and every caller-requested limit is clamped by the
//! executor's [`StreamCeilings`] (timeouts, sizes, windows; one `Open` is
//! one plugin execution — no replication, no amplification).

pub mod driver;
pub mod error;
pub mod executor;
pub mod frame;
pub mod heartbeat;
pub mod partial;
pub mod server;
pub mod signing;
pub mod submitter;
pub mod validate;

use std::time::{Duration, Instant};

use entangle_types::peer_id::PeerId;
use entangle_types::task::TaskId;

pub use driver::{drive_executor, ExecutorReport, StreamHandle, StreamOptions, SubmitterReport};
pub use error::{Reason, Side, StreamError};
pub use executor::{ExecutorConfig, ExecutorMachine, ExecutorState, InputPoll, SendOutcome};
pub use frame::{Frame, Signature64, STREAM_WIRE_VERSION};
pub use heartbeat::{Heartbeat, MISSED_PONGS_LIMIT};
pub use partial::{finalize, RetainedChunk, StreamContext, StreamOutcome, StreamResult};
pub use server::{open_stream, serve_streams, StreamServer};
pub use signing::{verify_transcript, ChunkSigner, ChunkVerifier, SignedChunk};
pub use submitter::{
    ChunkPoll, EndSummary, InputSend, SubmitterMachine, SubmitterOptions, SubmitterState,
    VerifiedChunk,
};
pub use validate::{
    check_executor_allowed, check_stream_integrity, chunk_allowance, validate_submit,
    StreamCeilings, StreamLimits, MAX_STREAM_TIMEOUT_MS, MIN_CHUNK_ALLOWANCE,
    TRUSTED_EXECUTOR_HINT,
};

/// `tracing` target of stream lifecycle events (`StalledEvent` and friends).
///
/// Operators filter on it — `entangle logs scheduler --filter StalledEvent`
/// in spec §7.1 terms.
pub const STREAM_TRACE_TARGET: &str = "entangle::scheduler::stream";

/// Emitted by the executor when it has had zero credit for the
/// credit-exhaustion timeout (spec §7.1, ATC-STR-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StalledEvent {
    /// The stalled task.
    pub task_id: TaskId,
    /// The executor reporting the stall (this node).
    pub peer_id: PeerId,
    /// The last chunk sent, if any.
    pub last_seq: Option<u64>,
    /// Chunk bytes sent so far.
    pub bytes_emitted: u64,
    /// How long credit had been zero.
    pub waited: Duration,
    /// When the stall was declared.
    pub at: Instant,
}

/// Something a stream end reports while it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    /// The executor entered `Stalled`.
    Stalled(StalledEvent),
    /// Credit arrived for a stalled stream: back to `Active`.
    Resumed {
        /// The task.
        task_id: TaskId,
        /// How long it was stalled.
        after: Duration,
    },
    /// The stream ended or closed.
    Closed {
        /// The task.
        task_id: TaskId,
        /// Why (`EndOfStream` for a normal end).
        reason: Reason,
    },
}

/// How many consumed chunks a receiver accumulates before granting credit
/// back: half the window, so a busy stream sends one `Credit` per half
/// window instead of one per chunk, and a sender with zero credit is never
/// starved (the receiver has always consumed at least this many by the
/// time the sender's window is exhausted).
pub const fn grant_threshold(window: u32) -> u32 {
    let half = window / 2;
    if half == 0 {
        1
    } else {
        half
    }
}

#[cfg(test)]
mod tests;
