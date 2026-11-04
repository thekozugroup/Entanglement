//! The submitter's side of a stream, as a pure state machine.
//!
//! Like [`super::executor::ExecutorMachine`], [`SubmitterMachine`] takes the
//! current time as an argument everywhere and does no I/O.
//!
//! # What the submitter checks, per chunk, in this order
//!
//! 1. **size** — the chunk is at most `max_chunk_bytes`, the stream's
//!    cumulative bytes stay within `max_total_bytes` (ATC-INT-6), and its
//!    chunk count within the allowance those bytes buy
//!    ([`chunk_allowance`]: a chunk costs bookkeeping however small). The
//!    submitter tracks the total itself (defense in depth): an executor that
//!    does not self-close at the cap is torn down with
//!    [`StreamError::StreamBytesExceeded`]. The transport has already
//!    refused, from the frame header alone, any frame larger than
//!    [`SubmitterMachine::frame_cap`], so no oversized chunk is ever
//!    allocated;
//! 2. **credit** — the executor had credit for it;
//! 3. **sequence** — `seq` is exactly the next number (a replayed or
//!    reordered chunk is refused);
//! 4. **signature** — it verifies against the executor's
//!    transport-authenticated key (ATC-STR-3).
//!
//! Any failure closes the stream: an `Error` frame is queued for the
//! executor and every later chunk is ignored.
//!
//! Output credit is granted back as the **application** consumes chunks
//! ([`SubmitterMachine::next_chunk`]), not as they arrive, so a slow
//! consumer slows the executor down end to end.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use entangle_types::peer_id::PeerId;
use entangle_types::task::{PartialResultPolicy, StreamingTask, TaskId};

use super::error::{Reason, Side, StreamError};
use super::frame::{
    AcceptedFrame, ChunkFrame, EndFrame, Frame, InputFrame, OpenFrame, Signature64, WireChannel,
    CHUNK_FRAME_OVERHEAD, CONTROL_FRAME_MAX,
};
use super::heartbeat::{Beat, Heartbeat};
use super::signing::{transcript_next, transcript_start, ChunkVerifier, SignedChunk};
use super::validate::{check_executor_allowed, chunk_allowance, validate_submit};
use super::{grant_threshold, StreamEvent};
use crate::work_unit::PolicyHash;

/// Default time an executor has to answer `Open` with `Accepted`.
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Slack added to the task's own timeout before the submitter gives up on a
/// stream that never ends: connection setup, framing and the return leg.
pub const DEFAULT_DEADLINE_SLACK: Duration = Duration::from_secs(10);

/// Largest input window the submitter accepts from an executor.
const MAX_INPUT_WINDOW: u32 = 4096;

/// Where a submitter stream is.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SubmitterState {
    /// `Open` sent; waiting for `Accepted`.
    Opening,
    /// Streaming.
    Active,
    /// A valid, signed `End` arrived: the output is complete.
    Ended,
    /// Closed for `reason` (see [`SubmitterMachine::error`]).
    Closed(Reason),
}

/// One verified output chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedChunk {
    /// Sequence number.
    pub seq: u64,
    /// The chunk bytes.
    pub bytes: Vec<u8>,
    /// The executor's signature, already verified.
    pub signature: Signature64,
}

impl From<VerifiedChunk> for SignedChunk {
    fn from(c: VerifiedChunk) -> Self {
        SignedChunk {
            seq: c.seq,
            bytes: c.bytes,
            signature: c.signature,
        }
    }
}

/// The verified end of a complete stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndSummary {
    /// Chunks in the stream.
    pub chunks: u64,
    /// Bytes in the stream.
    pub bytes: u64,
    /// Final transcript hash.
    pub transcript: [u8; 32],
    /// The executor's signature over the end message.
    pub signature: Signature64,
}

/// What [`SubmitterMachine::next_chunk`] has for the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkPoll {
    /// The next verified chunk.
    Chunk(VerifiedChunk),
    /// The stream ended normally and every chunk has been delivered.
    Ended(EndSummary),
    /// Nothing yet.
    Pending,
    /// The stream closed abnormally and every chunk received before that has
    /// been delivered.
    Closed(StreamError),
}

/// What [`SubmitterMachine::send_input`] did with an input chunk.
#[derive(Debug, PartialEq, Eq)]
pub enum InputSend {
    /// Queued as input chunk `seq`.
    Sent {
        /// Its sequence number.
        seq: u64,
    },
    /// No input credit yet (or the executor has not accepted the stream):
    /// the bytes are handed back to retry later.
    Blocked(Vec<u8>),
}

/// Knobs for a submitter stream.
#[derive(Copy, Clone, Debug)]
pub struct SubmitterOptions {
    /// Time the executor has to accept.
    pub open_timeout: Duration,
    /// Slack beyond the task timeout before the submitter gives up.
    pub deadline_slack: Duration,
}

impl Default for SubmitterOptions {
    fn default() -> Self {
        Self {
            open_timeout: DEFAULT_OPEN_TIMEOUT,
            deadline_slack: DEFAULT_DEADLINE_SLACK,
        }
    }
}

#[derive(Debug)]
struct Effective {
    max_chunk_bytes: u64,
    max_total_bytes: u64,
    credit_window: u32,
    input_window: u32,
}

/// The submitter's stream state machine. See the module docs.
#[derive(Debug)]
pub struct SubmitterMachine {
    task_id: TaskId,
    policy_hash: PolicyHash,
    policy_kind: entangle_types::task::PolicyKind,
    partial: PartialResultPolicy,
    declared: WireChannel,
    eff: Effective,
    verifier: ChunkVerifier,
    executor_key: [u8; 32],
    state: SubmitterState,
    opened: Instant,
    open_deadline: Instant,
    deadline: Instant,
    timeout_ms: u64,
    heartbeat: Option<Heartbeat>,
    // output (executor -> submitter)
    received: u64,
    received_bytes: u64,
    granted: u64,
    ungranted: u32,
    transcript: [u8; 32],
    buffer: VecDeque<VerifiedChunk>,
    end: Option<EndSummary>,
    // input (submitter -> executor)
    in_credit: u32,
    in_seq: u64,
    in_bytes: u64,
    in_finished: bool,
    outbox: VecDeque<Frame>,
    events: VecDeque<StreamEvent>,
    error: Option<StreamError>,
}

impl SubmitterMachine {
    /// Validate `task` (ATC-INT-4), check that `executor_key` — the
    /// transport-authenticated key of the executor — is allowed by its
    /// policy, and queue the `Open` frame.
    ///
    /// Nothing has been sent when this fails.
    pub fn new(
        task: &StreamingTask,
        executor_key: [u8; 32],
        options: SubmitterOptions,
        now: Instant,
    ) -> Result<Self, StreamError> {
        let envelope = validate_submit(task)?;
        check_executor_allowed(
            &task.integrity,
            &PeerId::from_public_key_bytes(&executor_key),
        )?;
        let task_bytes = *task.id.as_bytes();
        let declared = WireChannel::from(&task.channel);
        let mut machine = Self {
            task_id: task.id,
            policy_hash: envelope.hash(),
            policy_kind: task.integrity.kind(),
            partial: task.partial_result,
            declared,
            eff: Effective {
                max_chunk_bytes: declared.max_chunk_bytes,
                max_total_bytes: declared.max_total_bytes,
                credit_window: declared.credit_window,
                input_window: 0,
            },
            verifier: ChunkVerifier::new(executor_key, task_bytes, envelope.hash()),
            executor_key,
            state: SubmitterState::Opening,
            opened: now,
            open_deadline: now + options.open_timeout,
            deadline: now + Duration::from_millis(task.timeout_ms) + options.deadline_slack,
            timeout_ms: task.timeout_ms,
            heartbeat: None,
            received: 0,
            received_bytes: 0,
            granted: 0,
            ungranted: 0,
            transcript: transcript_start(&task_bytes, &envelope.hash()),
            buffer: VecDeque::new(),
            end: None,
            in_credit: 0,
            in_seq: 0,
            in_bytes: 0,
            in_finished: false,
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            error: None,
        };
        machine.outbox.push_back(Frame::Open(OpenFrame {
            task_id: task_bytes,
            plugin: task.plugin.to_string(),
            input: task.input.clone(),
            max_input_bytes: task.max_input_bytes,
            timeout_ms: task.timeout_ms,
            channel: declared,
            partial_result: task.partial_result.into(),
            policy: envelope.canonical().to_vec(),
            policy_hash: envelope.hash(),
        }));
        Ok(machine)
    }

    /// Current state.
    pub const fn state(&self) -> SubmitterState {
        self.state
    }

    /// `true` once the stream ended or closed.
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            SubmitterState::Ended | SubmitterState::Closed(_)
        )
    }

    /// Why the stream closed, if it closed abnormally.
    pub const fn error(&self) -> Option<&StreamError> {
        self.error.as_ref()
    }

    /// The task id.
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// The sealed policy hash.
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    /// The task's integrity policy variant (for reputation bookkeeping).
    pub const fn policy_kind(&self) -> entangle_types::task::PolicyKind {
        self.policy_kind
    }

    /// The task's partial-result policy.
    pub const fn partial_result(&self) -> PartialResultPolicy {
        self.partial
    }

    /// The executor's transport-authenticated public key.
    pub const fn executor_key(&self) -> [u8; 32] {
        self.executor_key
    }

    /// Chunks received (and verified) so far.
    pub const fn chunks_received(&self) -> u64 {
        self.received
    }

    /// Bytes received (and verified) so far.
    pub const fn bytes_received(&self) -> u64 {
        self.received_bytes
    }

    /// The transcript hash over the chunks received so far.
    pub const fn transcript(&self) -> [u8; 32] {
        self.transcript
    }

    /// Input credits left.
    pub const fn input_credit(&self) -> u32 {
        self.in_credit
    }

    /// Handle one frame from the executor.
    ///
    /// `Err` means the frame was a violation (or a forged / oversized chunk)
    /// and the stream is now closed, with an `Error` frame queued. Frames
    /// after the stream is terminal are ignored.
    pub fn on_frame(&mut self, frame: Frame, now: Instant) -> Result<(), StreamError> {
        if self.is_terminal() {
            return Ok(());
        }
        match (self.state, frame) {
            (_, Frame::Error { reason, message }) => {
                self.close(StreamError::PeerAborted {
                    by: Side::Executor,
                    reason,
                    message,
                });
                Ok(())
            }
            (SubmitterState::Opening, Frame::Accepted(a)) => self.on_accepted(a, now),
            (SubmitterState::Active, Frame::Chunk(c)) => self.on_chunk(c),
            (SubmitterState::Active, Frame::End(e)) => self.on_end(e),
            (SubmitterState::Active, Frame::Credit { n }) => {
                let balance = u64::from(self.in_credit) + u64::from(n);
                if balance > u64::from(self.eff.input_window) {
                    return Err(self.fail(StreamError::CreditViolation {
                        by: Side::Executor,
                        detail: format!(
                            "granted {n} input credits with {} outstanding: the window is {}",
                            self.in_credit, self.eff.input_window
                        ),
                    }));
                }
                // Lossless: `balance <= input_window: u32`.
                self.in_credit = balance as u32;
                Ok(())
            }
            (SubmitterState::Active, Frame::Ping { seq, ts_ms }) => {
                self.outbox.push_back(Frame::Pong { seq, ts_ms });
                Ok(())
            }
            (SubmitterState::Active, Frame::Pong { seq, .. }) => {
                if let Some(hb) = self.heartbeat.as_mut() {
                    hb.on_pong(seq, now);
                }
                Ok(())
            }
            (state, other) => {
                let detail = format!("unexpected {} frame while {state:?}", other.name());
                Err(self.fail(StreamError::Protocol {
                    by: Side::Executor,
                    detail,
                }))
            }
        }
    }

    /// The transport refused a frame whose header declared `declared` bytes,
    /// over [`SubmitterMachine::frame_cap`]: the executor tried to send a
    /// chunk over a cap. Closes the stream; nothing was allocated for it.
    pub fn on_oversized_frame(&mut self, declared: u64) -> StreamError {
        let chunk_cap = self.eff.max_chunk_bytes + CHUNK_FRAME_OVERHEAD as u64;
        let payload = declared.saturating_sub(CHUNK_FRAME_OVERHEAD as u64);
        let error = if declared > chunk_cap {
            StreamError::ChunkSizeExceeded {
                limit: self.eff.max_chunk_bytes,
                actual: payload,
            }
        } else {
            StreamError::StreamBytesExceeded {
                limit: self.eff.max_total_bytes,
                attempted: self.received_bytes.saturating_add(payload),
            }
        };
        self.fail(error)
    }

    /// The largest frame the executor may send next, enforced by the
    /// transport from the frame header: one chunk of at most the budget left
    /// in `max_total_bytes`, or a control frame.
    pub fn frame_cap(&self) -> usize {
        let left = self.eff.max_total_bytes.saturating_sub(self.received_bytes);
        let chunk = self.eff.max_chunk_bytes.min(left);
        usize::try_from(chunk)
            .unwrap_or(usize::MAX)
            .saturating_add(CHUNK_FRAME_OVERHEAD)
            .max(CONTROL_FRAME_MAX)
    }

    /// The next verified chunk for the application. Consuming one grants the
    /// executor credit back (batched, see [`grant_threshold`]).
    ///
    /// Chunks received before the stream closed are always delivered first;
    /// the terminal status follows them.
    pub fn next_chunk(&mut self) -> ChunkPoll {
        if let Some(chunk) = self.buffer.pop_front() {
            if self.state == SubmitterState::Active {
                self.ungranted += 1;
                if self.ungranted >= grant_threshold(self.eff.credit_window) {
                    let n = self.ungranted;
                    self.outbox.push_back(Frame::Credit { n });
                    self.granted += u64::from(n);
                    self.ungranted = 0;
                }
            }
            return ChunkPoll::Chunk(chunk);
        }
        match self.state {
            SubmitterState::Ended => match &self.end {
                Some(end) => ChunkPoll::Ended(end.clone()),
                None => ChunkPoll::Closed(StreamError::Closed(Reason::EndOfStream)),
            },
            SubmitterState::Closed(r) => {
                ChunkPoll::Closed(self.error.clone().unwrap_or(StreamError::Closed(r)))
            }
            SubmitterState::Opening | SubmitterState::Active => ChunkPoll::Pending,
        }
    }

    /// Queue one input chunk for the executor, or hand it back if there is no
    /// input credit yet.
    ///
    /// Input over the stream's own limits is refused locally (the stream
    /// stays open): this end never sends what the other end would have to
    /// abort on.
    pub fn send_input(&mut self, bytes: Vec<u8>) -> Result<InputSend, StreamError> {
        match self.state {
            SubmitterState::Ended => return Err(StreamError::Closed(Reason::EndOfStream)),
            SubmitterState::Closed(r) => return Err(StreamError::Closed(r)),
            SubmitterState::Opening => return Ok(InputSend::Blocked(bytes)),
            SubmitterState::Active => {}
        }
        if self.in_finished {
            return Err(StreamError::Protocol {
                by: Side::Submitter,
                detail: "input sent after finish_input".into(),
            });
        }
        let len = bytes.len() as u64;
        if len > self.eff.max_chunk_bytes {
            return Err(StreamError::ChunkSizeExceeded {
                limit: self.eff.max_chunk_bytes,
                actual: len,
            });
        }
        let attempted = self.in_bytes.saturating_add(len);
        if attempted > self.eff.max_total_bytes {
            return Err(StreamError::StreamBytesExceeded {
                limit: self.eff.max_total_bytes,
                attempted,
            });
        }
        if self.in_credit == 0 {
            return Ok(InputSend::Blocked(bytes));
        }
        let seq = self.in_seq;
        self.outbox
            .push_back(Frame::Input(InputFrame { seq, bytes }));
        self.in_credit -= 1;
        self.in_seq += 1;
        self.in_bytes = attempted;
        Ok(InputSend::Sent { seq })
    }

    /// Tell the executor no more input follows. `Ok(false)` while the stream
    /// is still opening (retry after `Accepted`); idempotent once sent.
    pub fn finish_input(&mut self) -> Result<bool, StreamError> {
        match self.state {
            SubmitterState::Opening => Ok(false),
            SubmitterState::Active => {
                if !self.in_finished {
                    self.in_finished = true;
                    self.outbox.push_back(Frame::InputEnd {
                        chunks: self.in_seq,
                        bytes: self.in_bytes,
                    });
                }
                Ok(true)
            }
            // The output already ended: nothing will read more input.
            SubmitterState::Ended => Ok(true),
            SubmitterState::Closed(r) => Err(StreamError::Closed(r)),
        }
    }

    /// Cancel the stream: queue `Cancel` and close.
    pub fn cancel(&mut self) {
        if !self.is_terminal() {
            self.outbox.push_back(Frame::Cancel {
                reason: Reason::Cancelled,
            });
            self.close(StreamError::Cancelled {
                by: Side::Submitter,
            });
        }
    }

    /// Close the stream because of `error`, telling the executor why.
    pub fn fail(&mut self, error: StreamError) -> StreamError {
        if !self.is_terminal() {
            self.outbox
                .push_back(Frame::error(error.reason(), error.to_string()));
            self.close(error.clone());
        }
        error
    }

    /// The transport under the stream failed or ended early.
    pub fn on_transport_lost(&mut self, detail: String) {
        if !self.is_terminal() {
            self.close(StreamError::Transport(detail));
        }
    }

    /// When the machine next needs [`SubmitterMachine::on_timeout`].
    pub fn poll_timeout(&self) -> Option<Instant> {
        match self.state {
            SubmitterState::Opening => Some(self.open_deadline.min(self.deadline)),
            SubmitterState::Active => Some(
                self.heartbeat
                    .as_ref()
                    .map_or(self.deadline, |hb| hb.deadline().min(self.deadline)),
            ),
            SubmitterState::Ended | SubmitterState::Closed(_) => None,
        }
    }

    /// Run every timer due at `now`.
    pub fn on_timeout(&mut self, now: Instant) {
        if self.is_terminal() {
            return;
        }
        if self.state == SubmitterState::Opening && now >= self.open_deadline {
            let waited = now.saturating_duration_since(self.opened);
            self.fail(StreamError::Timeout {
                after_ms: u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
            });
            return;
        }
        if now >= self.deadline {
            self.fail(StreamError::Timeout {
                after_ms: self.timeout_ms,
            });
            return;
        }
        let beat = self.heartbeat.as_mut().and_then(|hb| hb.on_tick(now));
        match beat {
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

    /// Next event to report.
    pub fn poll_event(&mut self) -> Option<StreamEvent> {
        self.events.pop_front()
    }

    // ── internals ────────────────────────────────────────────────────────

    fn close(&mut self, error: StreamError) {
        let reason = error.reason();
        self.state = SubmitterState::Closed(reason);
        self.error = Some(error);
        self.events.push_back(StreamEvent::Closed {
            task_id: self.task_id,
            reason,
        });
    }

    fn violation(&mut self, detail: String) -> StreamError {
        self.fail(StreamError::Protocol {
            by: Side::Executor,
            detail,
        })
    }

    fn on_accepted(&mut self, a: AcceptedFrame, now: Instant) -> Result<(), StreamError> {
        if a.observed_policy_hash != self.policy_hash {
            return Err(self.fail(StreamError::PolicyHashMismatch {
                expected: self.policy_hash.to_hex(),
                observed: a.observed_policy_hash.to_hex(),
            }));
        }
        if a.input_window == 0 || a.input_window > MAX_INPUT_WINDOW {
            return Err(self.violation(format!(
                "Accepted with an input window of {} (must be 1..={MAX_INPUT_WINDOW})",
                a.input_window
            )));
        }
        if a.channel.credit_window == 0
            || a.channel.max_chunk_bytes == 0
            || a.channel.max_total_bytes == 0
        {
            return Err(self.violation("Accepted with a zero channel limit".into()));
        }
        // An executor may only lower limits. Whatever it claims, this end
        // enforces the smaller of the two, so an executor that "raises" a
        // limit gains nothing.
        self.eff = Effective {
            max_chunk_bytes: self.declared.max_chunk_bytes.min(a.channel.max_chunk_bytes),
            max_total_bytes: self.declared.max_total_bytes.min(a.channel.max_total_bytes),
            credit_window: self.declared.credit_window.min(a.channel.credit_window),
            input_window: a.input_window,
        };
        self.in_credit = a.input_window;
        self.state = SubmitterState::Active;
        let mut hb = Heartbeat::new(
            Duration::from_millis(u64::from(self.declared.heartbeat_ms)),
            now,
        );
        if let Some(Beat::Ping { seq, ts_ms }) = hb.on_tick(now) {
            self.outbox.push_back(Frame::Ping { seq, ts_ms });
        }
        self.heartbeat = Some(hb);
        Ok(())
    }

    fn on_chunk(&mut self, c: ChunkFrame) -> Result<(), StreamError> {
        // 1. size — the DoS guards, before anything costs CPU.
        let len = c.bytes.len() as u64;
        if len > self.eff.max_chunk_bytes {
            return Err(self.fail(StreamError::ChunkSizeExceeded {
                limit: self.eff.max_chunk_bytes,
                actual: len,
            }));
        }
        let attempted = self.received_bytes.saturating_add(len);
        if attempted > self.eff.max_total_bytes {
            return Err(self.fail(StreamError::StreamBytesExceeded {
                limit: self.eff.max_total_bytes,
                attempted,
            }));
        }
        let allowance = chunk_allowance(self.eff.max_total_bytes);
        if self.received >= allowance {
            return Err(self.fail(StreamError::TooManyChunks { limit: allowance }));
        }
        // 2. credit.
        let allowed = u64::from(self.eff.credit_window) + self.granted;
        if self.received >= allowed {
            return Err(self.fail(StreamError::CreditViolation {
                by: Side::Executor,
                detail: format!(
                    "chunk {} sent without credit (window {}, granted {})",
                    c.seq, self.eff.credit_window, self.granted
                ),
            }));
        }
        // 3. sequence.
        if c.seq != self.received {
            let detail = if c.seq < self.received {
                format!(
                    "replayed chunk: sequence {} was already received (expected {})",
                    c.seq, self.received
                )
            } else {
                format!(
                    "out-of-order chunk: expected sequence {}, got {}",
                    self.received, c.seq
                )
            };
            return Err(self.fail(StreamError::BadChunkSignature {
                seq: c.seq,
                executor: self.verifier.executor().to_hex(),
                detail,
            }));
        }
        // 4. signature, against the transport-authenticated key.
        let hash = *blake3::hash(&c.bytes).as_bytes();
        if let Err(e) = self.verifier.verify_chunk(c.seq, &hash, &c.signature) {
            return Err(self.fail(e));
        }
        self.transcript = transcript_next(&self.transcript, c.seq, &hash);
        self.received += 1;
        self.received_bytes = attempted;
        self.buffer.push_back(VerifiedChunk {
            seq: c.seq,
            bytes: c.bytes,
            signature: c.signature,
        });
        Ok(())
    }

    fn on_end(&mut self, e: EndFrame) -> Result<(), StreamError> {
        if e.chunks != self.received || e.bytes != self.received_bytes {
            return Err(self.fail(StreamError::BadEnd(format!(
                "End claims {} chunks / {} bytes, {} / {} were received",
                e.chunks, e.bytes, self.received, self.received_bytes
            ))));
        }
        if e.transcript != self.transcript {
            return Err(self.fail(StreamError::BadEnd(
                "End transcript hash does not match the chunks received".into(),
            )));
        }
        if let Err(err) = self
            .verifier
            .verify_end(e.chunks, e.bytes, &e.transcript, &e.signature)
        {
            return Err(self.fail(err));
        }
        self.end = Some(EndSummary {
            chunks: e.chunks,
            bytes: e.bytes,
            transcript: e.transcript,
            signature: e.signature,
        });
        self.state = SubmitterState::Ended;
        self.events.push_back(StreamEvent::Closed {
            task_id: self.task_id,
            reason: Reason::EndOfStream,
        });
        Ok(())
    }
}
