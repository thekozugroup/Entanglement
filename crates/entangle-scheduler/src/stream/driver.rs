//! Async drivers: the pure state machines on real time, over a real
//! [`FramedStream`].
//!
//! Each driver owns one stream and runs three things:
//!
//! * a **reader** task, reading one frame at a time under the per-frame cap
//!   the machine computes ([`ExecutorMachine::frame_cap`] /
//!   [`SubmitterMachine::frame_cap`]) — so an oversized chunk is refused from
//!   its header, before allocation;
//! * a **writer** task behind two small bounded queues, so a peer that stops
//!   reading blocks the writer, never the timers: heartbeats, stall
//!   detection and the wall-clock deadline keep running. Heartbeat and
//!   credit frames ([`Frame::is_urgent`]) have their own queue, which the
//!   writer always drains first: a `Pong` waits for at most the frame being
//!   written, never for every chunk queued for a slow link;
//! * the **loop** itself, which feeds frames, timer expiries and
//!   application requests into the machine and moves the frames it emits to
//!   the writer.
//!
//! On the executor, a plugin chunk is acknowledged — and the guest's
//! `yield-chunk` returns — only once the machine has signed it under credit
//! **and** the writer queue had room for it, so backpressure reaches the
//! plugin from the submitter's consumption and from the network alike.
//!
//! When a stream ends, each side flushes, finishes its send half, and waits
//! briefly ([`LINGER`]) for the other side to finish too, so a final `End`,
//! `Error` or `Cancel` is delivered rather than cut off.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use entangle_host::{PluginChunk, StreamInput, StreamPortDriver};
use entangle_mesh_iroh::{FramedRecv, FramedSend, FramedStream, MeshConn, MeshIrohError};
use entangle_types::peer_id::PeerId;
use entangle_types::task::{PartialResultPolicy, StreamingTask, TaskId};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::error::{Reason, Side, StreamError};
use super::executor::{ExecutorMachine, InputPoll, SendOutcome};
use super::frame::{decode_frame, encode_frame_owned, Frame, CONTROL_FRAME_MAX};
use super::partial::{finalize, StreamContext, StreamOutcome, StreamResult};
use super::submitter::{ChunkPoll, InputSend, SubmitterMachine, SubmitterOptions, VerifiedChunk};
use super::StreamEvent;
use crate::reputation::{ReputationReason, ReputationStore};

/// Data frames the writer queue holds before the loop stops taking new
/// plugin chunks.
const WRITE_QUEUE: usize = 8;

/// Urgent frames (heartbeat, credit) the writer's priority queue holds.
const URGENT_QUEUE: usize = 32;

/// Frames waiting for the writer queue beyond which the peer is treated as
/// gone (it has stopped reading while still sending, e.g. a ping flood).
const MAX_PENDING_FRAMES: usize = 1024;

/// How long a finished side waits for the other to finish before closing.
pub const LINGER: Duration = Duration::from_secs(2);

/// A wake-up far enough away to mean "no timer".
const IDLE: Duration = Duration::from_secs(3600);

// ── reader / writer ─────────────────────────────────────────────────────────

enum ReadItem {
    Frame(Vec<u8>),
    Eof,
    TooLarge(u64),
    Failed(String),
}

/// Read frames in lockstep with the loop: each read waits for the cap the
/// loop computed **after** processing the previous frame, so the cap always
/// reflects the bytes already received (a reader running one frame ahead
/// would check the next header against a stale, larger budget).
fn spawn_reader(
    mut recv: FramedRecv,
    first_cap: usize,
) -> (
    mpsc::Receiver<ReadItem>,
    mpsc::Sender<usize>,
    JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel(1);
    let (cap_tx, mut cap_rx) = mpsc::channel::<usize>(1);
    let _ = cap_tx.try_send(first_cap);
    let task = tokio::spawn(async move {
        while let Some(cap) = cap_rx.recv().await {
            let item = match recv.recv_capped(cap).await {
                Ok(Some(bytes)) => ReadItem::Frame(bytes),
                Ok(None) => ReadItem::Eof,
                Err(MeshIrohError::FrameTooLarge { declared, .. }) => ReadItem::TooLarge(declared),
                Err(e) => ReadItem::Failed(e.to_string()),
            };
            let last = !matches!(item, ReadItem::Frame(_));
            if tx.send(item).await.is_err() || last {
                return;
            }
        }
    });
    (rx, cap_tx, task)
}

/// The writer's two queues: urgent frames go out before any queued data
/// frame; within each queue, order is kept.
struct WriteQueues {
    urgent: mpsc::Sender<Vec<u8>>,
    data: mpsc::Sender<Vec<u8>>,
}

fn spawn_writer(mut send: FramedSend) -> (WriteQueues, JoinHandle<()>) {
    let (urgent, mut urgent_rx) = mpsc::channel::<Vec<u8>>(URGENT_QUEUE);
    let (data, mut data_rx) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE);
    let task = tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                biased;
                Some(frame) = urgent_rx.recv() => frame,
                Some(frame) = data_rx.recv() => frame,
                else => break,
            };
            if let Err(e) = send.send(&frame).await {
                tracing::debug!(target: super::STREAM_TRACE_TARGET, error = %e, "stream writer stopped");
                return;
            }
        }
        let _ = send.finish().await;
    });
    (WriteQueues { urgent, data }, task)
}

/// The reader task and its two channels.
struct Reading {
    rx: mpsc::Receiver<ReadItem>,
    caps: mpsc::Sender<usize>,
    task: JoinHandle<()>,
}

/// Encoded frames waiting for room in the writer's queues.
#[derive(Default)]
struct Outbound {
    urgent: VecDeque<Vec<u8>>,
    data: VecDeque<Vec<u8>>,
}

impl Outbound {
    /// Encode `frame` onto the queue its kind belongs to.
    fn push(&mut self, frame: Frame) -> Result<(), StreamError> {
        let urgent = frame.is_urgent();
        let bytes = encode_frame_owned(frame)?;
        if urgent {
            self.urgent.push_back(bytes);
        } else {
            self.data.push_back(bytes);
        }
        Ok(())
    }

    fn len(&self) -> usize {
        self.urgent.len() + self.data.len()
    }
}

/// Wait until `deadline` (or effectively forever without one).
async fn sleep_until(deadline: Option<Instant>) {
    let at = deadline.unwrap_or_else(|| Instant::now() + IDLE);
    tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
}

/// Flush `out` into the writer, close the writer, and wait for the peer to
/// finish its side (bounded by [`LINGER`]).
///
/// A peer that has not taken the final frames within [`LINGER`] has stopped
/// reading: the writer is then aborted rather than left parked on a write
/// that may never complete, which would keep its queued frames and the
/// stream alive after this function returns. Dropping the stream's send
/// half unfinished resets a QUIC stream, so the transport lets go of it too.
async fn linger(mut out: Outbound, wq: WriteQueues, writer: JoinHandle<()>, reading: Reading) {
    let Reading {
        mut rx,
        caps,
        task: reader,
    } = reading;
    let abort_writer = writer.abort_handle();
    let flush = async {
        let WriteQueues { urgent, data } = wq;
        for (queue, tx) in [(&mut out.urgent, urgent), (&mut out.data, data)] {
            while let Some(frame) = queue.pop_front() {
                if tx.send(frame).await.is_err() {
                    break;
                }
            }
        }
        let _ = writer.await;
    };
    if tokio::time::timeout(LINGER, flush).await.is_err() {
        abort_writer.abort();
    }
    let drain = async {
        // Whatever still arrives is discarded; only control-sized frames are
        // read, so a closing peer cannot make this end allocate.
        let _ = caps.try_send(CONTROL_FRAME_MAX);
        while let Some(item) = rx.recv().await {
            if !matches!(item, ReadItem::Frame(_)) {
                break;
            }
            let _ = caps.try_send(CONTROL_FRAME_MAX);
        }
    };
    let _ = tokio::time::timeout(LINGER, drain).await;
    reader.abort();
}

// ── executor ────────────────────────────────────────────────────────────────

/// What an executor stream did.
#[derive(Clone, Debug)]
pub struct ExecutorReport {
    /// The task.
    pub task_id: TaskId,
    /// `Ok` when the plugin finished and the signed `End` was sent.
    pub outcome: Result<(), StreamError>,
    /// Chunks sent.
    pub chunks_sent: u64,
    /// Chunk bytes sent.
    pub bytes_sent: u64,
    /// Every event the stream reported, in order.
    pub events: Vec<StreamEvent>,
}

/// Run an executor stream to its end.
///
/// `port` is the driver end of the plugin's [`entangle_host::StreamPort`];
/// `plugin` is the plugin's execution (e.g. `Kernel::invoke_stream`),
/// resolving to `Err(text)` if it failed.
///
/// The plugin runs on **its own task**, not inside this loop, so a guest
/// that computes for a long time between two `yield-chunk` calls (an LLM's
/// prompt processing, say) never blocks this loop: heartbeats are still
/// answered, and credit, stall and deadline timers still run, while it
/// computes. A wasm guest also yields its worker thread at every epoch tick
/// (`LoadedStreamPlugin::run_stream`), so even as many computing guests as
/// the runtime has workers cannot starve these loops. The task is aborted when the stream
/// closes early (the guest's next host call fails first: its port is
/// dropped). `events` (optional) receives every [`StreamEvent`] as it
/// happens.
pub async fn drive_executor<P>(
    machine: ExecutorMachine,
    io: FramedStream,
    port: StreamPortDriver,
    plugin: P,
    events: Option<mpsc::UnboundedSender<StreamEvent>>,
) -> ExecutorReport
where
    P: Future<Output = Result<(), String>> + Send + 'static,
{
    let (send, recv) = io.split();
    drive_executor_halves(machine, send, recv, port, plugin, events).await
}

/// [`drive_executor`] over an already-split stream.
pub async fn drive_executor_halves<P>(
    mut m: ExecutorMachine,
    send: FramedSend,
    recv: FramedRecv,
    mut port: StreamPortDriver,
    plugin: P,
    events: Option<mpsc::UnboundedSender<StreamEvent>>,
) -> ExecutorReport
where
    P: Future<Output = Result<(), String>> + Send + 'static,
{
    let plugin = spawn_plugin(plugin);
    let (rx, caps, reader) = spawn_reader(recv, m.frame_cap());
    let mut reading = Reading {
        rx,
        caps,
        task: reader,
    };
    let (wq, writer) = spawn_writer(send);
    let mut out = Outbound::default();
    let mut seen = Vec::new();
    let mut plugin = std::pin::pin!(plugin);
    let mut plugin_done = false;
    let mut plugin_result: Option<Result<(), String>> = None;
    let mut chunks_open = true;
    let mut pending: Option<PluginChunk> = None;
    let mut input_end_sent = false;

    loop {
        let now = Instant::now();
        // Timers first. The select below is biased towards inbound frames,
        // so a submitter that keeps the reader busy must not be able to
        // postpone the wall-clock deadline, the stall timers or the
        // heartbeat by flooding (say) zero-credit frames.
        if m.poll_timeout().is_some_and(|at| at <= now) {
            m.on_timeout(now);
        }
        // A chunk the plugin is blocked on: send it if there is credit now.
        if let Some(chunk) = pending.take() {
            let PluginChunk { bytes, ack } = chunk;
            match m.try_send_chunk(bytes, now) {
                Ok(SendOutcome::Sent { .. }) => ack.sent(),
                Ok(SendOutcome::Blocked(bytes)) => pending = Some(PluginChunk { bytes, ack }),
                Err(e) => ack.refuse(e.to_string()),
            }
        }
        // Input for the plugin, while its channel has room.
        while !input_end_sent && port.input.capacity() > 0 {
            match m.next_input() {
                InputPoll::Chunk(bytes) => {
                    let _ = port.input.try_send(StreamInput::Chunk(bytes));
                }
                InputPoll::End => {
                    let _ = port.input.try_send(StreamInput::End);
                    input_end_sent = true;
                }
                InputPoll::Pending | InputPoll::Closed => break,
            }
        }
        // The plugin returned: end the stream.
        if pending.is_none() && !m.is_terminal() {
            match plugin_result.take() {
                Some(Ok(())) => {
                    let _ = m.finish(now);
                }
                Some(Err(e)) => {
                    m.fail(StreamError::Plugin(e));
                }
                None => {}
            }
        }
        move_frames_executor(&mut m, &mut out);
        while let Some(event) = m.poll_event() {
            if let Some(tx) = &events {
                let _ = tx.send(event.clone());
            }
            seen.push(event);
        }
        if m.is_terminal() {
            if let Some(chunk) = pending.take() {
                chunk.ack.refuse(close_text(m.error()));
            }
            break;
        }
        if out.len() > MAX_PENDING_FRAMES {
            m.on_transport_lost("the submitter stopped reading the stream".into());
            continue;
        }
        let deadline = m.poll_timeout();
        let take_chunk = chunks_open && pending.is_none() && out.data.is_empty();
        // The plugin's input channel holds one item: when the guest takes
        // it, the next buffered chunk (or the input's end) must follow at
        // once, not at the loop's next unrelated wake-up.
        let feed_input = !input_end_sent && m.has_input();

        tokio::select! {
            biased;
            item = reading.rx.recv() => match item {
                Some(ReadItem::Frame(bytes)) => {
                    match decode_frame(&bytes, Side::Submitter) {
                        Ok(frame) => { let _ = m.on_frame(frame, Instant::now()); }
                        Err(e) => { m.fail(e); }
                    }
                    let _ = reading.caps.try_send(m.frame_cap());
                }
                Some(ReadItem::TooLarge(declared)) => { m.on_oversized_frame(declared); }
                Some(ReadItem::Eof) => m.on_transport_lost("the submitter closed its side of the stream".into()),
                Some(ReadItem::Failed(e)) => m.on_transport_lost(e),
                None => m.on_transport_lost("stream reader stopped".into()),
            },
            permit = wq.urgent.reserve(), if !out.urgent.is_empty() => match permit {
                Ok(permit) => {
                    if let Some(frame) = out.urgent.pop_front() {
                        permit.send(frame);
                    }
                }
                Err(_) => m.on_transport_lost("stream writer stopped".into()),
            },
            permit = wq.data.reserve(), if !out.data.is_empty() => match permit {
                Ok(permit) => {
                    if let Some(frame) = out.data.pop_front() {
                        permit.send(frame);
                    }
                }
                Err(_) => m.on_transport_lost("stream writer stopped".into()),
            },
            () = sleep_until(deadline) => m.on_timeout(Instant::now()),
            permit = port.input.reserve(), if feed_input => match permit {
                Ok(permit) => match m.next_input() {
                    InputPoll::Chunk(bytes) => permit.send(StreamInput::Chunk(bytes)),
                    InputPoll::End => {
                        permit.send(StreamInput::End);
                        input_end_sent = true;
                    }
                    InputPoll::Pending | InputPoll::Closed => {}
                },
                // The guest dropped its port: it is gone or going.
                Err(_) => input_end_sent = true,
            },
            chunk = port.chunks.recv(), if take_chunk => match chunk {
                Some(chunk) => pending = Some(chunk),
                None => chunks_open = false,
            },
            result = &mut plugin, if !plugin_done => {
                plugin_done = true;
                plugin_result = Some(result);
                // The guest is gone; its port is closed.
                chunks_open = false;
            },
        }
    }

    // Close the plugin's input so a guest still reading sees the end.
    drop(port);
    linger(out, wq, writer, reading).await;
    let outcome = match m.error() {
        None => Ok(()),
        Some(e) => Err(e.clone()),
    };
    if let Err(e) = &outcome {
        tracing::info!(
            target: super::STREAM_TRACE_TARGET,
            task = %m.task_id(),
            reason = %e.reason(),
            error = %e,
            chunks = m.chunks_sent(),
            "executor stream closed"
        );
    }
    ExecutorReport {
        task_id: m.task_id(),
        outcome,
        chunks_sent: m.chunks_sent(),
        bytes_sent: m.bytes_sent(),
        events: seen,
    }
}

fn move_frames_executor(m: &mut ExecutorMachine, out: &mut Outbound) {
    while let Some(frame) = m.poll_transmit() {
        if let Err(e) = out.push(frame) {
            m.fail(StreamError::Transport(e.to_string()));
        }
    }
}

/// Aborts the plugin task when the driver lets go of it.
struct AbortOnDrop(JoinHandle<Result<(), String>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Run `plugin` on its own task; the returned future resolves with its
/// result and aborts the task if dropped first.
fn spawn_plugin<P>(plugin: P) -> impl Future<Output = Result<(), String>> + Send
where
    P: Future<Output = Result<(), String>> + Send + 'static,
{
    let mut task = AbortOnDrop(tokio::spawn(plugin));
    async move {
        match (&mut task.0).await {
            Ok(result) => result,
            Err(e) if e.is_cancelled() => Err("the plugin task was cancelled".to_owned()),
            Err(e) => Err(format!("the plugin task panicked: {e}")),
        }
    }
}

fn close_text(error: Option<&StreamError>) -> String {
    match error {
        Some(e) => format!("stream {}: {e}", e.reason()),
        None => "stream closed".to_owned(),
    }
}

// ── submitter ───────────────────────────────────────────────────────────────

/// Options for a submitter stream beyond the machine's own.
#[derive(Clone, Debug, Default)]
pub struct StreamOptions {
    /// Open / deadline timing.
    pub submitter: SubmitterOptions,
    /// Where to record the executor's behaviour: violations (bad
    /// signatures, size or credit violations, a bad `End`) penalize it,
    /// a complete stream records a correct result.
    pub reputation: Option<Arc<ReputationStore>>,
    /// Receives every [`StreamEvent`] as it happens.
    pub events: Option<mpsc::UnboundedSender<StreamEvent>>,
}

/// What a submitter stream did, for the partial-result policy and audit.
#[derive(Clone, Debug)]
pub struct SubmitterReport {
    /// How it ended.
    pub outcome: StreamOutcome,
    /// Facts for [`finalize`].
    pub context: StreamContext,
    /// The task's partial-result policy.
    pub policy: PartialResultPolicy,
    /// The executor's peer id.
    pub executor: PeerId,
}

/// Where the driver answers a command that can fail.
type Reply = oneshot::Sender<Result<(), StreamError>>;

enum Cmd {
    Next(oneshot::Sender<ChunkPoll>),
    Input(Vec<u8>, Reply),
    FinishInput(Reply),
    Cancel,
}

struct Finished {
    report: SubmitterReport,
    remaining: VecDeque<VerifiedChunk>,
    terminal: ChunkPoll,
}

enum HandleState {
    Running {
        cmds: mpsc::Sender<Cmd>,
        join: JoinHandle<Finished>,
    },
    Done(Box<Finished>),
}

/// The application's handle on a submitter stream.
///
/// Chunks come out of [`StreamHandle::next`] verified and in order; taking
/// one grants the executor credit back, so a consumer that stops calling
/// `next` stalls the executor (and, after the credit-exhaustion timeout,
/// gets the stream cancelled as unresponsive). Dropping the handle cancels
/// the stream.
pub struct StreamHandle {
    state: HandleState,
    task_id: TaskId,
    executor: PeerId,
    conn: Option<MeshConn>,
}

impl std::fmt::Debug for StreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamHandle")
            .field("task_id", &self.task_id)
            .field("executor", &self.executor)
            .field(
                "running",
                &matches!(self.state, HandleState::Running { .. }),
            )
            .finish()
    }
}

impl StreamHandle {
    /// Validate `task` (ATC-INT-4) and start streaming it over `io`, whose
    /// remote end is the executor. Its transport-authenticated key is what
    /// every chunk must verify against.
    ///
    /// Must be called inside a tokio runtime. Nothing is sent when it fails.
    pub fn start(
        io: FramedStream,
        task: &StreamingTask,
        options: StreamOptions,
    ) -> Result<Self, StreamError> {
        let executor = io.remote_peer_id();
        let machine = SubmitterMachine::new(
            task,
            io.remote_public_key(),
            options.submitter,
            Instant::now(),
        )?;
        let (cmds, cmd_rx) = mpsc::channel(8);
        let join = tokio::spawn(drive_submitter(machine, io, cmd_rx, options, executor));
        Ok(Self {
            state: HandleState::Running { cmds, join },
            task_id: task.id,
            executor,
            conn: None,
        })
    }

    /// Keep `conn` open for the stream's lifetime and close it when the
    /// handle is finished or dropped.
    #[must_use]
    pub fn with_connection(mut self, conn: MeshConn) -> Self {
        self.conn = Some(conn);
        self
    }

    /// The task.
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// The executor's (transport-authenticated) peer id.
    pub const fn executor(&self) -> PeerId {
        self.executor
    }

    /// The next verified chunk, or the stream's end: never
    /// [`ChunkPoll::Pending`]. After the end, keeps returning it.
    pub async fn next(&mut self) -> ChunkPoll {
        loop {
            match &mut self.state {
                HandleState::Done(done) => {
                    return match done.remaining.pop_front() {
                        Some(chunk) => ChunkPoll::Chunk(chunk),
                        None => done.terminal.clone(),
                    };
                }
                HandleState::Running { cmds, .. } => {
                    let (tx, rx) = oneshot::channel();
                    if cmds.send(Cmd::Next(tx)).await.is_ok() {
                        if let Ok(poll) = rx.await {
                            return poll;
                        }
                    }
                }
            }
            self.join_driver().await;
        }
    }

    /// Send one input chunk, waiting for input credit.
    pub async fn send_input(&mut self, bytes: Vec<u8>) -> Result<(), StreamError> {
        let (tx, rx) = oneshot::channel();
        self.command(Cmd::Input(bytes, tx), rx).await
    }

    /// Tell the executor no more input follows.
    pub async fn finish_input(&mut self) -> Result<(), StreamError> {
        let (tx, rx) = oneshot::channel();
        self.command(Cmd::FinishInput(tx), rx).await
    }

    /// Cancel the stream.
    pub async fn cancel(&mut self) {
        if let HandleState::Running { cmds, .. } = &self.state {
            let _ = cmds.send(Cmd::Cancel).await;
        }
    }

    /// Consume every chunk and return the stream's result with its
    /// partial-result policy applied.
    pub async fn collect(mut self) -> StreamResult {
        let mut chunks = Vec::new();
        while let ChunkPoll::Chunk(chunk) = self.next().await {
            chunks.push(chunk);
        }
        let report = self.finish().await;
        finalize(report.policy, report.outcome, chunks, report.context)
    }

    /// End the stream and return its report: once it has ended this just
    /// collects the report; a stream still running is cancelled first.
    /// Chunks not yet taken with [`StreamHandle::next`] are discarded.
    pub async fn finish(mut self) -> SubmitterReport {
        self.join_driver().await;
        if let Some(conn) = self.conn.take() {
            conn.close();
        }
        match std::mem::replace(
            &mut self.state,
            HandleState::Done(Box::new(placeholder_finished(self.task_id, self.executor))),
        ) {
            HandleState::Done(done) => done.report,
            // `join_driver` always leaves `Done`.
            HandleState::Running { .. } => placeholder_finished(self.task_id, self.executor).report,
        }
    }

    async fn command<T>(
        &mut self,
        cmd: Cmd,
        rx: oneshot::Receiver<Result<T, StreamError>>,
    ) -> Result<T, StreamError> {
        if let HandleState::Running { cmds, .. } = &self.state {
            if cmds.send(cmd).await.is_ok() {
                if let Ok(result) = rx.await {
                    return result;
                }
            }
        }
        self.join_driver().await;
        match &self.state {
            HandleState::Done(done) => Err(match &done.report.outcome {
                StreamOutcome::Complete(_) => StreamError::Closed(Reason::EndOfStream),
                StreamOutcome::Interrupted(e) => StreamError::Closed(e.reason()),
            }),
            HandleState::Running { .. } => Err(StreamError::Closed(Reason::Internal)),
        }
    }

    async fn join_driver(&mut self) {
        if let HandleState::Running { cmds, join } = &mut self.state {
            // Closing the command channel lets an idle driver finish: with no
            // handle left to consume, the stream is cancelled.
            let (closed_tx, _) = mpsc::channel(1);
            drop(std::mem::replace(cmds, closed_tx));
            let finished = match join.await {
                Ok(f) => f,
                Err(e) => {
                    let mut f = placeholder_finished(self.task_id, self.executor);
                    let err = StreamError::Transport(format!("stream driver failed: {e}"));
                    f.terminal = ChunkPoll::Closed(err.clone());
                    f.report.outcome = StreamOutcome::Interrupted(err);
                    f
                }
            };
            self.state = HandleState::Done(Box::new(finished));
        }
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            conn.close();
        }
    }
}

fn placeholder_finished(task_id: TaskId, executor: PeerId) -> Finished {
    let err = StreamError::Closed(Reason::Internal);
    Finished {
        report: SubmitterReport {
            outcome: StreamOutcome::Interrupted(err.clone()),
            context: StreamContext {
                task_id,
                policy_hash: crate::work_unit::PolicyHash([0; 32]),
                executor_key: [0; 32],
                received_chunks: 0,
                received_bytes: 0,
            },
            policy: PartialResultPolicy::Discard,
            executor,
        },
        remaining: VecDeque::new(),
        terminal: ChunkPoll::Closed(err),
    }
}

/// Which `ReputationReason` an executor-attributable error earns.
fn penalty(error: &StreamError) -> Option<ReputationReason> {
    match error {
        StreamError::BadChunkSignature { .. } | StreamError::BadEnd(_) => {
            Some(ReputationReason::BadChunkSignature)
        }
        StreamError::StreamBytesExceeded { .. } | StreamError::ChunkSizeExceeded { .. } => {
            Some(ReputationReason::OversizedOutput)
        }
        StreamError::CreditViolation {
            by: Side::Executor, ..
        }
        | StreamError::Protocol {
            by: Side::Executor, ..
        } => Some(ReputationReason::StreamProtocolViolation),
        StreamError::PolicyHashMismatch { .. } => Some(ReputationReason::PolicyHashMismatch),
        _ => None,
    }
}

async fn drive_submitter(
    mut m: SubmitterMachine,
    io: FramedStream,
    mut cmds: mpsc::Receiver<Cmd>,
    options: StreamOptions,
    executor: PeerId,
) -> Finished {
    let (send, recv) = io.split();
    let (rx, caps, reader) = spawn_reader(recv, m.frame_cap());
    let mut reading = Reading {
        rx,
        caps,
        task: reader,
    };
    let (wq, writer) = spawn_writer(send);
    let mut out = Outbound::default();
    let mut pending_next: Option<oneshot::Sender<ChunkPoll>> = None;
    let mut pending_input: Option<(Vec<u8>, Reply)> = None;
    let mut pending_finish: Option<Reply> = None;
    let mut cmds_open = true;

    loop {
        // Timers first (see the executor loop): a flooding executor cannot
        // postpone the deadline or the heartbeat.
        let now = Instant::now();
        if m.poll_timeout().is_some_and(|at| at <= now) {
            m.on_timeout(now);
        }
        if let Some(tx) = pending_next.take() {
            match m.next_chunk() {
                ChunkPoll::Pending => pending_next = Some(tx),
                poll => {
                    let _ = tx.send(poll);
                }
            }
        }
        if let Some((bytes, tx)) = pending_input.take() {
            match m.send_input(bytes) {
                Ok(InputSend::Sent { .. }) => {
                    let _ = tx.send(Ok(()));
                }
                Ok(InputSend::Blocked(bytes)) => pending_input = Some((bytes, tx)),
                Err(e) => {
                    let _ = tx.send(Err(e));
                }
            }
        }
        if pending_input.is_none() {
            if let Some(tx) = pending_finish.take() {
                match m.finish_input() {
                    Ok(true) => {
                        let _ = tx.send(Ok(()));
                    }
                    Ok(false) => pending_finish = Some(tx),
                    Err(e) => {
                        let _ = tx.send(Err(e));
                    }
                }
            }
        }
        while let Some(frame) = m.poll_transmit() {
            if let Err(e) = out.push(frame) {
                m.fail(StreamError::Transport(e.to_string()));
            }
        }
        while let Some(event) = m.poll_event() {
            if let Some(tx) = &options.events {
                let _ = tx.send(event);
            }
        }
        if m.is_terminal() {
            break;
        }
        if out.len() > MAX_PENDING_FRAMES {
            m.on_transport_lost("the executor stopped reading the stream".into());
            continue;
        }
        let deadline = m.poll_timeout();

        tokio::select! {
            biased;
            item = reading.rx.recv() => match item {
                Some(ReadItem::Frame(bytes)) => {
                    match decode_frame(&bytes, Side::Executor) {
                        Ok(frame) => { let _ = m.on_frame(frame, Instant::now()); }
                        Err(e) => { m.fail(e); }
                    }
                    let _ = reading.caps.try_send(m.frame_cap());
                }
                Some(ReadItem::TooLarge(declared)) => { m.on_oversized_frame(declared); }
                Some(ReadItem::Eof) => m.on_transport_lost("the executor closed its side of the stream".into()),
                Some(ReadItem::Failed(e)) => m.on_transport_lost(e),
                None => m.on_transport_lost("stream reader stopped".into()),
            },
            permit = wq.urgent.reserve(), if !out.urgent.is_empty() => match permit {
                Ok(permit) => {
                    if let Some(frame) = out.urgent.pop_front() {
                        permit.send(frame);
                    }
                }
                Err(_) => m.on_transport_lost("stream writer stopped".into()),
            },
            permit = wq.data.reserve(), if !out.data.is_empty() => match permit {
                Ok(permit) => {
                    if let Some(frame) = out.data.pop_front() {
                        permit.send(frame);
                    }
                }
                Err(_) => m.on_transport_lost("stream writer stopped".into()),
            },
            () = sleep_until(deadline) => m.on_timeout(Instant::now()),
            cmd = cmds.recv(), if cmds_open => match cmd {
                Some(Cmd::Next(tx)) => pending_next = Some(tx),
                Some(Cmd::Input(bytes, tx)) => {
                    if pending_input.is_some() {
                        let _ = tx.send(Err(StreamError::Protocol {
                            by: Side::Submitter,
                            detail: "send_input called while a previous call was pending".into(),
                        }));
                    } else {
                        pending_input = Some((bytes, tx));
                    }
                }
                Some(Cmd::FinishInput(tx)) => pending_finish = Some(tx),
                Some(Cmd::Cancel) => m.cancel(),
                None => {
                    // The handle is gone: nobody will consume the output.
                    cmds_open = false;
                    m.cancel();
                }
            },
        }
    }

    // Terminal: move the final frames out, then answer whatever is pending.
    while let Some(frame) = m.poll_transmit() {
        let _ = out.push(frame);
    }
    while let Some(event) = m.poll_event() {
        if let Some(tx) = &options.events {
            let _ = tx.send(event);
        }
    }
    let closed = m
        .error()
        .cloned()
        .unwrap_or(StreamError::Closed(Reason::EndOfStream));
    if let Some((_, tx)) = pending_input.take() {
        let _ = tx.send(Err(StreamError::Closed(closed.reason())));
    }
    if let Some(tx) = pending_finish.take() {
        let _ = tx.send(m.finish_input().map(|_| ()));
    }
    if let Some(tx) = pending_next.take() {
        let _ = tx.send(m.next_chunk());
    }
    let mut remaining = VecDeque::new();
    let terminal = loop {
        match m.next_chunk() {
            ChunkPoll::Chunk(chunk) => remaining.push_back(chunk),
            other => break other,
        }
    };
    linger(out, wq, writer, reading).await;

    let outcome = match &terminal {
        ChunkPoll::Ended(end) => StreamOutcome::Complete(end.clone()),
        ChunkPoll::Closed(e) => StreamOutcome::Interrupted(e.clone()),
        ChunkPoll::Chunk(_) | ChunkPoll::Pending => {
            StreamOutcome::Interrupted(StreamError::Closed(Reason::Internal))
        }
    };
    if let Some(store) = &options.reputation {
        match &outcome {
            StreamOutcome::Complete(_) => {
                store.record_correct(&executor, m.policy_kind());
            }
            StreamOutcome::Interrupted(e) => {
                if let Some(reason) = penalty(e) {
                    let score = store.penalize(&executor, m.policy_kind(), reason);
                    tracing::warn!(
                        target: super::STREAM_TRACE_TARGET,
                        peer = %executor,
                        reason = reason.as_str(),
                        score,
                        "stream executor penalized"
                    );
                }
            }
        }
    }
    Finished {
        report: SubmitterReport {
            outcome,
            context: StreamContext {
                task_id: m.task_id(),
                policy_hash: m.policy_hash(),
                executor_key: m.executor_key(),
                received_chunks: m.chunks_received(),
                received_bytes: m.bytes_received(),
            },
            policy: m.partial_result(),
            executor,
        },
        remaining,
        terminal,
    }
}
