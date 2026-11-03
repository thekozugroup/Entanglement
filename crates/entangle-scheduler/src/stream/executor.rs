//! The executor's side of a stream, as a pure state machine.
//!
//! [`ExecutorMachine`] never touches a clock or a socket: every method takes
//! the current time as an argument, frames to send are pulled with
//! [`ExecutorMachine::poll_transmit`], and the next instant it needs to be
//! woken at is [`ExecutorMachine::poll_timeout`]. The async driver
//! ([`super::driver`]) feeds it real time; tests feed it whatever time they
//! like, which is how the 5 s / 15 s propositions of §16.5 are checked
//! without waiting.
//!
//! # States (spec §7.1)
//!
//! ```text
//! Active  -- credit_exhausted + credit_timeout --> Stalled   (StalledEvent)
//! Stalled -- Credit received -------------------> Active    (Resumed)
//! Stalled -- credit_timeout again (2x total) ---> Closed(SubmitterUnresponsive)
//! Active|Stalled -- 3 missed pongs -------------> Closed(PeerLost)
//! Active|Stalled -- plugin returned -------------> Finished  (signed End)
//! any -- Cancel / Error / violation / timeout --> Closed(reason)
//! ```
//!
//! # Credit
//!
//! The executor starts with `credit_window` output credits and spends one
//! per chunk; at zero it refuses to send ([`SendOutcome::Blocked`]) — the
//! driver then holds the plugin's `yield-chunk` call. A `Credit { n }` that
//! would lift the balance above the window is a violation (an honest
//! submitter only grants what it has consumed), as is an `Input` chunk the
//! executor never granted credit for.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use entangle_types::peer_id::PeerId;
use entangle_types::task::TaskId;

use super::error::{Reason, Side, StreamError};
use super::frame::{
    AcceptedFrame, ChunkFrame, EndFrame, Frame, InputFrame, CHUNK_FRAME_OVERHEAD, CONTROL_FRAME_MAX,
};
use super::heartbeat::{Beat, Heartbeat};
use super::signing::{transcript_next, transcript_start, ChunkSigner};
use super::validate::StreamLimits;
use super::{grant_threshold, StalledEvent, StreamEvent};
use crate::work_unit::PolicyHash;

/// Where an executor stream is.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExecutorState {
    /// Streaming.
    Active,
    /// Zero credit for longer than the credit-exhaustion timeout (a
    /// `StalledEvent` was emitted); recovers on credit.
    Stalled {
        /// When the stream entered `Stalled`.
        since: Instant,
    },
    /// The signed `End` frame is queued; nothing more will be sent.
    Finished,
    /// Closed for `reason` (see [`ExecutorMachine::error`]).
    Closed(Reason),
}

/// What [`ExecutorMachine::try_send_chunk`] did with a chunk.
#[derive(Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// Signed and queued as chunk `seq`.
    Sent {
        /// The chunk's sequence number.
        seq: u64,
    },
    /// No credit: the chunk is handed back, unchanged, to retry after the
    /// next `Credit` frame.
    Blocked(Vec<u8>),
}

/// The next item of the input stream for the plugin.
#[derive(Debug, PartialEq, Eq)]
pub enum InputPoll {
    /// An input chunk.
    Chunk(Vec<u8>),
    /// The submitter finished sending input.
    End,
    /// Nothing yet.
    Pending,
    /// The stream closed before the input ended.
    Closed,
}

/// Everything an [`ExecutorMachine`] needs besides its signing key.
#[derive(Clone, Debug)]
pub struct ExecutorConfig {
    /// The task being executed.
    pub task_id: TaskId,
    /// The policy hash it was verified under.
    pub policy_hash: PolicyHash,
    /// The effective limits (after the executor's clamp).
    pub limits: StreamLimits,
    /// This executor's peer id (for `StalledEvent`).
    pub local_peer: PeerId,
}

#[derive(Debug, Default)]
struct InputState {
    next_seq: u64,
    received_bytes: u64,
    /// Credits granted to the submitter beyond the initial window.
    granted: u64,
    /// Chunks consumed but not yet granted back.
    ungranted: u32,
    buffer: VecDeque<Vec<u8>>,
    ended: bool,
}

/// The executor's stream state machine. See the module docs.
#[derive(Debug)]
pub struct ExecutorMachine {
    task_id: TaskId,
    policy_hash: PolicyHash,
    local_peer: PeerId,
    limits: StreamLimits,
    signer: ChunkSigner,
    state: ExecutorState,
    deadline: Instant,
    out_credit: u32,
    credit_zero_since: Option<Instant>,
    next_seq: u64,
    bytes_sent: u64,
    transcript: [u8; 32],
    heartbeat: Heartbeat,
    input: InputState,
    outbox: VecDeque<Frame>,
    events: VecDeque<StreamEvent>,
    error: Option<StreamError>,
}

impl ExecutorMachine {
    /// Start a stream at `now`: queues the `Accepted` frame and the first
    /// heartbeat ping.
    pub fn new(config: ExecutorConfig, signer: ChunkSigner, now: Instant) -> Self {
        let limits = config.limits;
        let task_bytes = *config.task_id.as_bytes();
        let mut machine = Self {
            task_id: config.task_id,
            policy_hash: config.policy_hash,
            local_peer: config.local_peer,
            limits,
            signer,
            state: ExecutorState::Active,
            deadline: now + limits.timeout,
            out_credit: limits.credit_window,
            credit_zero_since: None,
            next_seq: 0,
            bytes_sent: 0,
            transcript: transcript_start(&task_bytes, &config.policy_hash),
            heartbeat: Heartbeat::new(limits.heartbeat, now),
            input: InputState::default(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            error: None,
        };
        machine.outbox.push_back(Frame::Accepted(AcceptedFrame {
            observed_policy_hash: config.policy_hash,
            channel: limits.wire_channel(),
            input_window: limits.input_window,
            timeout_ms: u64::try_from(limits.timeout.as_millis()).unwrap_or(u64::MAX),
        }));
        machine.on_timeout(now);
        machine
    }

    /// Current state.
    pub const fn state(&self) -> ExecutorState {
        self.state
    }

    /// `true` once nothing more will be sent (finished or closed).
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ExecutorState::Finished | ExecutorState::Closed(_)
        )
    }

    /// Why the stream closed, if it closed abnormally.
    pub const fn error(&self) -> Option<&StreamError> {
        self.error.as_ref()
    }

    /// Output credits left.
    pub const fn credit(&self) -> u32 {
        self.out_credit
    }

    /// Chunks sent so far.
    pub const fn chunks_sent(&self) -> u64 {
        self.next_seq
    }

    /// Chunk bytes sent so far.
    pub const fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// The effective limits.
    pub const fn limits(&self) -> &StreamLimits {
        &self.limits
    }

    /// The task id.
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// The policy hash the task runs under.
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    /// Sign and queue one output chunk, or hand it back if there is no
    /// credit.
    ///
    /// A chunk over `max_chunk_bytes`, or one that would carry the stream
    /// past `max_total_bytes`, is never sent: the stream closes with
    /// `ChunkSizeExceeded` / `TotalBytesExceeded` and the error is returned.
    pub fn try_send_chunk(
        &mut self,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<SendOutcome, StreamError> {
        if let Some(e) = self.closed_error() {
            return Err(e);
        }
        let len = bytes.len() as u64;
        if len > self.limits.max_chunk_bytes {
            return Err(self.fail(StreamError::ChunkSizeExceeded {
                limit: self.limits.max_chunk_bytes,
                actual: len,
            }));
        }
        let attempted = self.bytes_sent.saturating_add(len);
        if attempted > self.limits.max_total_bytes {
            return Err(self.fail(StreamError::StreamBytesExceeded {
                limit: self.limits.max_total_bytes,
                attempted,
            }));
        }
        if self.out_credit == 0 {
            self.credit_zero_since.get_or_insert(now);
            return Ok(SendOutcome::Blocked(bytes));
        }
        let seq = self.next_seq;
        let hash = *blake3::hash(&bytes).as_bytes();
        let signature = self.signer.sign_chunk(seq, &hash);
        self.transcript = transcript_next(&self.transcript, seq, &hash);
        self.outbox.push_back(Frame::Chunk(ChunkFrame {
            seq,
            bytes,
            signature,
        }));
        self.out_credit -= 1;
        self.next_seq += 1;
        self.bytes_sent = attempted;
        if self.out_credit == 0 {
            self.credit_zero_since = Some(now);
        }
        Ok(SendOutcome::Sent { seq })
    }

    /// The plugin returned successfully: queue the signed `End` frame.
    pub fn finish(&mut self, _now: Instant) -> Result<(), StreamError> {
        if let Some(e) = self.closed_error() {
            return Err(e);
        }
        let signature = self
            .signer
            .sign_end(self.next_seq, self.bytes_sent, &self.transcript);
        self.outbox.push_back(Frame::End(EndFrame {
            chunks: self.next_seq,
            bytes: self.bytes_sent,
            transcript: self.transcript,
            signature,
        }));
        self.state = ExecutorState::Finished;
        self.events.push_back(StreamEvent::Closed {
            task_id: self.task_id,
            reason: Reason::EndOfStream,
        });
        Ok(())
    }

    /// Close the stream because of `error`: queue an `Error` frame telling
    /// the submitter why. Returns `error` for convenience. No-op (returning
    /// the error) once terminal.
    pub fn fail(&mut self, error: StreamError) -> StreamError {
        if !self.is_terminal() {
            self.outbox
                .push_back(Frame::error(error.reason(), error.to_string()));
            self.close(error.clone());
        }
        error
    }

    /// Handle one frame from the submitter.
    ///
    /// `Err` means the frame was a violation and the stream is now closed
    /// (an `Error` frame is queued). Frames after the stream is terminal are
    /// ignored.
    pub fn on_frame(&mut self, frame: Frame, now: Instant) -> Result<(), StreamError> {
        if self.is_terminal() {
            return Ok(());
        }
        match frame {
            Frame::Credit { n } => self.on_credit(n, now),
            Frame::Input(input) => self.on_input(input),
            Frame::InputEnd { chunks, bytes } => {
                if self.input.ended {
                    return Err(self.violation("a second InputEnd"));
                }
                if chunks != self.input.next_seq || bytes != self.input.received_bytes {
                    return Err(self.violation(&format!(
                        "InputEnd claims {chunks} chunks / {bytes} bytes, {} / {} arrived",
                        self.input.next_seq, self.input.received_bytes
                    )));
                }
                self.input.ended = true;
                Ok(())
            }
            Frame::Ping { seq, ts_ms } => {
                self.outbox.push_back(Frame::Pong { seq, ts_ms });
                Ok(())
            }
            Frame::Pong { seq, .. } => {
                self.heartbeat.on_pong(seq, now);
                Ok(())
            }
            Frame::Cancel { .. } => {
                self.close(StreamError::Cancelled {
                    by: Side::Submitter,
                });
                Ok(())
            }
            Frame::Error { reason, message } => {
                self.close(StreamError::PeerAborted {
                    by: Side::Submitter,
                    reason,
                    message,
                });
                Ok(())
            }
            other @ (Frame::Open(_) | Frame::Accepted(_) | Frame::Chunk(_) | Frame::End(_)) => {
                Err(self.violation(&format!("unexpected {} frame", other.name())))
            }
        }
    }

    /// The transport refused a frame from the submitter whose header declared
    /// `declared` bytes, over the cap [`ExecutorMachine::frame_cap`] gave.
    pub fn on_oversized_frame(&mut self, declared: u64) -> StreamError {
        let chunk_cap = self.limits.max_chunk_bytes + CHUNK_FRAME_OVERHEAD as u64;
        let payload = declared.saturating_sub(CHUNK_FRAME_OVERHEAD as u64);
        let error = if declared > chunk_cap {
            StreamError::ChunkSizeExceeded {
                limit: self.limits.max_chunk_bytes,
                actual: payload,
            }
        } else {
            StreamError::StreamBytesExceeded {
                limit: self.limits.max_total_bytes,
                attempted: self.input.received_bytes.saturating_add(payload),
            }
        };
        self.fail(error)
    }

    /// The largest frame the submitter may send next, for the transport to
    /// enforce from the frame header: one chunk of at most the input budget
    /// left, or a control frame.
    pub fn frame_cap(&self) -> usize {
        let left = self
            .limits
            .max_total_bytes
            .saturating_sub(self.input.received_bytes);
        let chunk = self.limits.max_chunk_bytes.min(left);
        usize::try_from(chunk)
            .unwrap_or(usize::MAX)
            .saturating_add(CHUNK_FRAME_OVERHEAD)
            .max(CONTROL_FRAME_MAX)
    }

    /// The next input chunk for the plugin; consuming one grants the
    /// submitter credit back (batched, see [`grant_threshold`]).
    pub fn next_input(&mut self) -> InputPoll {
        if let Some(bytes) = self.input.buffer.pop_front() {
            if !self.is_terminal() {
                self.input.ungranted += 1;
                if self.input.ungranted >= grant_threshold(self.limits.input_window) {
                    let n = self.input.ungranted;
                    self.outbox.push_back(Frame::Credit { n });
                    self.input.granted += u64::from(n);
                    self.input.ungranted = 0;
                }
            }
            return InputPoll::Chunk(bytes);
        }
        if self.input.ended {
            InputPoll::End
        } else if self.is_terminal() {
            InputPoll::Closed
        } else {
            InputPoll::Pending
        }
    }

    /// When the machine next needs [`ExecutorMachine::on_timeout`].
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.is_terminal() {
            return None;
        }
        let mut next = self.heartbeat.deadline().min(self.deadline);
        if let Some(stall) = self.stall_deadline() {
            next = next.min(stall);
        }
        Some(next)
    }

    /// Run every timer due at `now`: the wall-clock deadline, the stall
    /// timers, and the heartbeat.
    pub fn on_timeout(&mut self, now: Instant) {
        if self.is_terminal() {
            return;
        }
        if now >= self.deadline {
            self.fail(StreamError::Timeout {
                after_ms: u64::try_from(self.limits.timeout.as_millis()).unwrap_or(u64::MAX),
            });
            return;
        }
        match (self.state, self.credit_zero_since) {
            (ExecutorState::Active, Some(zero)) if self.out_credit == 0 => {
                if now >= zero + self.limits.credit_timeout {
                    self.state = ExecutorState::Stalled { since: now };
                    let event = StalledEvent {
                        task_id: self.task_id,
                        peer_id: self.local_peer,
                        last_seq: self.next_seq.checked_sub(1),
                        bytes_emitted: self.bytes_sent,
                        waited: now.saturating_duration_since(zero),
                        at: now,
                    };
                    tracing::warn!(
                        target: super::STREAM_TRACE_TARGET,
                        event = "StalledEvent",
                        task = %event.task_id,
                        peer_id = %event.peer_id,
                        last_seq = ?event.last_seq,
                        bytes_emitted = event.bytes_emitted,
                        waited_ms = event.waited.as_millis() as u64,
                        "stream stalled: no credit from the submitter"
                    );
                    self.events.push_back(StreamEvent::Stalled(event));
                }
            }
            (ExecutorState::Stalled { since }, zero) => {
                if now >= since + self.limits.credit_timeout {
                    let waited = zero
                        .map(|z| now.saturating_duration_since(z))
                        .unwrap_or(Duration::ZERO);
                    self.fail(StreamError::SubmitterUnresponsive {
                        waited_ms: u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                    });
                    return;
                }
            }
            _ => {}
        }
        match self.heartbeat.on_tick(now) {
            Some(Beat::Ping { seq, ts_ms }) => self.outbox.push_back(Frame::Ping { seq, ts_ms }),
            Some(Beat::PeerLost { missed }) => {
                self.fail(StreamError::PeerLost { missed });
            }
            None => {}
        }
    }

    /// Next frame to send.
    pub fn poll_transmit(&mut self) -> Option<Frame> {
        self.outbox.pop_front()
    }

    /// Frames queued to send.
    pub fn queued(&self) -> usize {
        self.outbox.len()
    }

    /// Next event to report.
    pub fn poll_event(&mut self) -> Option<StreamEvent> {
        self.events.pop_front()
    }

    /// The transport under the stream failed or ended early.
    pub fn on_transport_lost(&mut self, detail: String) {
        if !self.is_terminal() {
            self.close(StreamError::Transport(detail));
        }
    }

    // ── internals ────────────────────────────────────────────────────────

    fn stall_deadline(&self) -> Option<Instant> {
        match self.state {
            ExecutorState::Active if self.out_credit == 0 => self
                .credit_zero_since
                .map(|z| z + self.limits.credit_timeout),
            ExecutorState::Stalled { since } => Some(since + self.limits.credit_timeout),
            _ => None,
        }
    }

    fn closed_error(&self) -> Option<StreamError> {
        match self.state {
            ExecutorState::Active | ExecutorState::Stalled { .. } => None,
            ExecutorState::Finished => Some(StreamError::Closed(Reason::EndOfStream)),
            ExecutorState::Closed(r) => Some(StreamError::Closed(r)),
        }
    }

    fn close(&mut self, error: StreamError) {
        let reason = error.reason();
        self.state = ExecutorState::Closed(reason);
        self.error = Some(error);
        self.events.push_back(StreamEvent::Closed {
            task_id: self.task_id,
            reason,
        });
    }

    fn violation(&mut self, detail: &str) -> StreamError {
        self.fail(StreamError::Protocol {
            by: Side::Submitter,
            detail: detail.to_owned(),
        })
    }

    fn on_credit(&mut self, n: u32, now: Instant) -> Result<(), StreamError> {
        let balance = u64::from(self.out_credit) + u64::from(n);
        if balance > u64::from(self.limits.credit_window) {
            return Err(self.fail(StreamError::CreditViolation {
                by: Side::Submitter,
                detail: format!(
                    "granted {n} credits with {} outstanding: the window is {}",
                    self.out_credit, self.limits.credit_window
                ),
            }));
        }
        if n == 0 {
            return Ok(());
        }
        // Cast is lossless: `balance <= credit_window: u32`.
        self.out_credit = balance as u32;
        self.credit_zero_since = None;
        if let ExecutorState::Stalled { since } = self.state {
            self.state = ExecutorState::Active;
            self.events.push_back(StreamEvent::Resumed {
                task_id: self.task_id,
                after: now.saturating_duration_since(since),
            });
        }
        Ok(())
    }

    fn on_input(&mut self, input: InputFrame) -> Result<(), StreamError> {
        if self.input.ended {
            return Err(self.violation("an Input chunk after InputEnd"));
        }
        let len = input.bytes.len() as u64;
        if len > self.limits.max_chunk_bytes {
            return Err(self.fail(StreamError::ChunkSizeExceeded {
                limit: self.limits.max_chunk_bytes,
                actual: len,
            }));
        }
        let attempted = self.input.received_bytes.saturating_add(len);
        if attempted > self.limits.max_total_bytes {
            return Err(self.fail(StreamError::StreamBytesExceeded {
                limit: self.limits.max_total_bytes,
                attempted,
            }));
        }
        let allowed = u64::from(self.limits.input_window) + self.input.granted;
        if self.input.next_seq >= allowed {
            return Err(self.fail(StreamError::CreditViolation {
                by: Side::Submitter,
                detail: format!(
                    "input chunk {} sent without credit (window {}, granted {})",
                    input.seq, self.limits.input_window, self.input.granted
                ),
            }));
        }
        if input.seq != self.input.next_seq {
            return Err(self.violation(&format!(
                "input chunk {} out of sequence: expected {}",
                input.seq, self.input.next_seq
            )));
        }
        self.input.next_seq += 1;
        self.input.received_bytes = attempted;
        self.input.buffer.push_back(input.bytes);
        Ok(())
    }
}
