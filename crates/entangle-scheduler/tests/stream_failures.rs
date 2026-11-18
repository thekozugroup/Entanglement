//! Streaming failure handling (spec §7.1): restarts from the initial input
//! on another executor, epochs for restarts after a delivery, the
//! scheduler's stall reactions (preempt, extend through a control frame,
//! preempt-and-reassign), the stall counter and stall blame.
//!
//! Healthy executors are real `StreamServer`s running the real
//! `stream-lines` component behind a capability gate (so an attempt they
//! serve carried a valid per-attempt token); broken ones are scripted at
//! the frame level: they crash after a number of chunks, or stop producing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use entangle_mesh_iroh::{duplex_pair, FramedStream, MAX_FRAME_BYTES};
use entangle_observability::catalog::names;
use entangle_observability::Registry;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::capability::{CapabilityTokens, StaticTokens};
use entangle_scheduler::stream::frame::{
    decode_frame, encode_frame, AcceptedFrame, ChunkFrame, Frame,
};
use entangle_scheduler::stream::{
    request_digest, ChunkPoll, ChunkSigner, Reason, Side, StallKind, StallPolicy, StallReaction,
    StreamCeilings, StreamError, StreamHandle, StreamOpener, StreamOptions, StreamServer,
    SubmitterOptions, SupervisedPoll, SupervisedStream,
};
use entangle_scheduler::{ReputationStore, RetryCause, StaticAllowlist};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{PolicyKind, RetryPolicy, StreamingTask};
use parking_lot::Mutex;

const TEST_DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(TEST_DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {TEST_DEADLINE:?}"),
    }
}

const STREAM_LINES_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/stream-lines.wasm"
);

fn keyring_for(publisher: &IdentityKeyPair) -> Keyring {
    let public = publisher.public();
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: public.fingerprint(),
        public_key: *public.as_bytes(),
        publisher_name: "test-publisher".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

/// A kernel with `stream-lines` loaded.
async fn stream_lines() -> (Arc<Kernel>, PluginId, tempfile::TempDir) {
    let publisher = IdentityKeyPair::generate();
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring_for(&publisher)).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let id = format!("{}/stream-lines@0.1.0", publisher.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n\
         description = \"streaming failure test plugin\"\n"
    );
    let wasm = std::fs::read(STREAM_LINES_WASM).expect("stream-lines fixture");
    std::fs::write(dir.path().join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.path().join("plugin.wasm"), &wasm).unwrap();
    let bundle = sign_artifact(&wasm, manifest.as_bytes(), &publisher);
    std::fs::write(
        dir.path().join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    kernel.load_plugin_from_dir(dir.path()).await.unwrap();
    (kernel, id.parse().unwrap(), dir)
}

fn lines(n: usize) -> String {
    (0..n).map(|i| format!("line {i:03}\n")).collect()
}

fn peer_of(key: &IdentityKeyPair) -> PeerId {
    PeerId::from_public_key_bytes(key.public().as_bytes())
}

/// How one executor behaves.
#[derive(Clone, Copy, Debug)]
enum Behaviour {
    /// A real `StreamServer` running the plugin.
    Healthy,
    /// Cannot be reached.
    Unreachable,
    /// Accepts, sends this many signed chunks, then the connection dies.
    CrashAfter(u64),
    /// Accepts, sends this many signed chunks, then sends nothing more
    /// (answering pings, holding credit).
    StallAfter(u64),
}

struct Executor {
    key: IdentityKeyPair,
    behaviour: Behaviour,
}

/// Opens streams over in-memory duplexes to scripted or real executors.
struct Opener {
    submitter: IdentityKeyPair,
    executors: HashMap<PeerId, Executor>,
    kernel: Arc<Kernel>,
    /// `(executor, task id, carried a capability token)` per attempt.
    opens: Mutex<Vec<(PeerId, [u8; 16], bool)>>,
}

impl Opener {
    fn opened(&self) -> Vec<(PeerId, [u8; 16], bool)> {
        self.opens.lock().clone()
    }
}

#[async_trait::async_trait]
impl StreamOpener for Opener {
    async fn open(
        &self,
        executor: PeerId,
        task: &StreamingTask,
        options: StreamOptions,
    ) -> Result<StreamHandle, StreamError> {
        let ex = self.executors.get(&executor).expect("known executor");
        if let Behaviour::Unreachable = ex.behaviour {
            self.opens
                .lock()
                .push((executor, *task.id.as_bytes(), false));
            return Err(StreamError::Transport("connection refused".into()));
        }
        let (sub_io, exec_io) = duplex_pair(
            *self.submitter.public().as_bytes(),
            *ex.key.public().as_bytes(),
            MAX_FRAME_BYTES,
            64 * 1024,
        );
        let had_token = options.capability.is_some();
        self.opens
            .lock()
            .push((executor, *task.id.as_bytes(), had_token));
        match ex.behaviour {
            Behaviour::Healthy => {
                let server = StreamServer::new(
                    Arc::clone(&self.kernel),
                    Arc::new(StaticAllowlist::new().allow(peer_of(&self.submitter))),
                    ex.key.clone(),
                )
                .with_ceilings(StreamCeilings {
                    min_heartbeat_ms: 10,
                    min_credit_exhaustion_timeout_ms: 10,
                    ..StreamCeilings::default()
                });
                tokio::spawn(async move { server.handle(exec_io).await });
            }
            Behaviour::CrashAfter(n) => {
                let key = ex.key.clone();
                tokio::spawn(scripted(exec_io, key, n, false));
            }
            Behaviour::StallAfter(n) => {
                let key = ex.key.clone();
                tokio::spawn(scripted(exec_io, key, n, true));
            }
            Behaviour::Unreachable => unreachable!(),
        }
        StreamHandle::start(sub_io, task, options)
    }
}

/// A scripted executor: accept, send `n` signed chunks (`chunk-<i>`), then
/// drop the stream (`stall = false`) or keep it open answering pings and
/// sending nothing (`stall = true`).
async fn scripted(mut io: FramedStream, key: IdentityKeyPair, n: u64, stall: bool) {
    let Ok(Some(bytes)) = io.recv().await else {
        return;
    };
    let Ok(Frame::Open(open)) = decode_frame(&bytes, Side::Submitter) else {
        return;
    };
    let accepted = Frame::Accepted(AcceptedFrame {
        observed_policy_hash: open.policy_hash,
        channel: open.channel,
        input_window: 4,
        timeout_ms: open.timeout_ms,
    });
    let _ = io.send(&encode_frame(&accepted).unwrap()).await;
    let signer = ChunkSigner::new(key, open.task_id, open.policy_hash, request_digest(&open));
    for seq in 0..n {
        let bytes = format!("chunk-{seq}\n").into_bytes();
        let signature = signer.sign_chunk(seq, blake3::hash(&bytes).as_bytes());
        let frame = Frame::Chunk(ChunkFrame {
            seq,
            bytes,
            signature,
        });
        if io.send(&encode_frame(&frame).unwrap()).await.is_err() {
            return;
        }
    }
    if !stall {
        return; // the connection dies with `io`
    }
    while let Ok(Some(bytes)) = io.recv().await {
        if let Ok(Frame::Ping { seq, ts_ms }) = decode_frame(&bytes, Side::Submitter) {
            let _ = io
                .send(&encode_frame(&Frame::Pong { seq, ts_ms }).unwrap())
                .await;
        }
    }
}

struct Setup {
    opener: Arc<Opener>,
    peers: Vec<PeerId>,
    plugin: PluginId,
    tokens: Arc<dyn CapabilityTokens>,
    _dir: tempfile::TempDir,
}

async fn setup(behaviours: &[Behaviour]) -> Setup {
    let (kernel, plugin, dir) = stream_lines().await;
    let submitter = IdentityKeyPair::generate();
    let tokens = StaticTokens::new();
    let mut executors = HashMap::new();
    let mut peers = Vec::new();
    for b in behaviours {
        let key = IdentityKeyPair::generate();
        let peer = peer_of(&key);
        tokens.paired_with(&key, peer_of(&submitter)).unwrap();
        peers.push(peer);
        executors.insert(peer, Executor { key, behaviour: *b });
    }
    Setup {
        opener: Arc::new(Opener {
            submitter,
            executors,
            kernel,
            opens: Mutex::new(Vec::new()),
        }),
        peers,
        plugin,
        tokens: Arc::new(tokens),
        _dir: dir,
    }
}

impl Setup {
    fn task(&self, n: usize) -> StreamingTask {
        let mut task = StreamingTask::with_defaults(self.plugin.clone(), lines(n).into_bytes());
        task.timeout_ms = 20_000;
        task.channel.heartbeat_ms = 200;
        task.retry = RetryPolicy {
            max_attempts: 3,
            backoff_ms: 10,
            max_backoff_ms: 50,
        };
        task
    }

    fn options(&self, registry: &Registry) -> StreamOptions {
        StreamOptions {
            capability: Some(Arc::clone(&self.tokens)),
            metrics: Some(registry.clone()),
            ..StreamOptions::default()
        }
    }

    async fn supervise(&self, task: StreamingTask, options: StreamOptions) -> SupervisedStream {
        deadline(
            "open",
            SupervisedStream::open(
                Arc::clone(&self.opener) as Arc<dyn StreamOpener>,
                task,
                self.peers.clone(),
                options,
            ),
        )
        .await
        .expect("an executor accepts the stream")
    }
}

/// Drain a supervised stream: `(epoch, bytes)` per chunk and the terminal.
async fn drain(s: &mut SupervisedStream) -> (Vec<(u32, Vec<u8>)>, SupervisedPoll) {
    let mut chunks = Vec::new();
    loop {
        match deadline("next", s.next()).await {
            SupervisedPoll::Chunk(c) => chunks.push((c.epoch, c.chunk.bytes)),
            other => return (chunks, other),
        }
    }
}

fn retries(reg: &Registry, cause: &str) -> f64 {
    reg.value(
        names::SCHEDULER_RETRIES,
        &[("kind", "stream"), ("cause", cause)],
    )
    .unwrap_or(0.0)
}

fn stalls(reg: &Registry, outcome: &str) -> f64 {
    reg.value(names::STREAMS_STALLED, &[("outcome", outcome)])
        .unwrap_or(0.0)
}

// ═════════════════════════════════════════════════════════════════════════
// Restart from initial_inputs
// ═════════════════════════════════════════════════════════════════════════

/// An executor that dies before the consumer received any chunk: the stream
/// restarts from its initial input on the next executor — a new stream
/// with a fresh task id and its own capability token, which the healthy
/// executor's gate admits — and the consumer sees one clean epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_lost_before_any_chunk_restarts_on_another_executor() {
    let s = setup(&[Behaviour::CrashAfter(0), Behaviour::Healthy]).await;
    let reg = Registry::new();
    let mut stream = s.supervise(s.task(5), s.options(&reg)).await;
    let (chunks, end) = drain(&mut stream).await;
    let text: Vec<u8> = chunks.iter().flat_map(|(_, b)| b.clone()).collect();
    assert_eq!(text, lines(5).into_bytes());
    assert!(chunks.iter().all(|(epoch, _)| *epoch == 0));
    match end {
        SupervisedPoll::Ended {
            epoch,
            executor,
            end,
        } => {
            assert_eq!(epoch, 0);
            assert_eq!(executor, s.peers[1]);
            assert_eq!(end.chunks, 5);
        }
        other => panic!("expected the end, got {other:?}"),
    }
    let opens = s.opener.opened();
    assert_eq!(opens.len(), 2);
    assert_ne!(opens[0].1, opens[1].1, "a restart is a new stream");
    assert!(opens.iter().all(|(_, _, token)| *token));
    assert_eq!(
        stream.attempts()[0].restarted_because,
        Some(RetryCause::LostAfterSend)
    );
    assert_eq!(retries(&reg, "lost_after_send"), 1.0);
}

/// An unreachable executor is moved past when opening.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_executor_is_skipped_at_open() {
    let s = setup(&[Behaviour::Unreachable, Behaviour::Healthy]).await;
    let reg = Registry::new();
    let mut stream = s.supervise(s.task(3), s.options(&reg)).await;
    assert_eq!(stream.executor(), s.peers[1]);
    let (chunks, end) = drain(&mut stream).await;
    assert_eq!(chunks.len(), 3);
    assert!(matches!(end, SupervisedPoll::Ended { .. }), "{end:?}");
    assert_eq!(retries(&reg, "unreachable"), 1.0);
}

/// After chunks were delivered, a lost stream is not restarted unless the
/// task opts in; when it does, the restart re-delivers the whole output
/// under a new epoch, so the consumer can drop the superseded chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_after_delivery_needs_opt_in_and_marks_a_new_epoch() {
    // Not opted in: the consumer keeps what it got and sees the failure.
    let s = setup(&[Behaviour::CrashAfter(2), Behaviour::Healthy]).await;
    let reg = Registry::new();
    let mut stream = s.supervise(s.task(4), s.options(&reg)).await;
    let (chunks, end) = drain(&mut stream).await;
    assert_eq!(chunks.len(), 2);
    match end {
        SupervisedPoll::Closed(e) => {
            assert!(
                matches!(e, StreamError::Transport(_) | StreamError::PeerLost { .. }),
                "{e}"
            )
        }
        other => panic!("expected the failure, got {other:?}"),
    }
    assert_eq!(s.opener.opened().len(), 1, "not restarted");

    // Opted in: epoch 0 holds the crashed executor's two chunks, epoch 1
    // the whole output again, from sequence 0.
    let s = setup(&[Behaviour::CrashAfter(2), Behaviour::Healthy]).await;
    let mut task = s.task(4);
    task.restart_after_delivery = true;
    let mut stream = s.supervise(task, s.options(&reg)).await;
    let mut got: Vec<(u32, u64, Vec<u8>)> = Vec::new();
    let end = loop {
        match deadline("next", stream.next()).await {
            SupervisedPoll::Chunk(c) => got.push((c.epoch, c.chunk.seq, c.chunk.bytes)),
            other => break other,
        }
    };
    assert!(
        matches!(end, SupervisedPoll::Ended { epoch: 1, .. }),
        "{end:?}"
    );
    let epoch0: Vec<_> = got.iter().filter(|c| c.0 == 0).collect();
    let epoch1: Vec<_> = got.iter().filter(|c| c.0 == 1).collect();
    assert_eq!(epoch0.len(), 2);
    assert_eq!(epoch1.len(), 4);
    assert_eq!(epoch1[0].1, 0, "the new epoch starts again at sequence 0");
    // What a consumer keeps: the chunks of the highest epoch.
    let kept: Vec<u8> = epoch1.iter().flat_map(|c| c.2.clone()).collect();
    assert_eq!(kept, lines(4).into_bytes());
}

/// A final failure — here the executor refuses the stream's capability
/// token — is never restarted, whatever the retry policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_stream_is_not_restarted() {
    let s = setup(&[Behaviour::Healthy, Behaviour::Healthy]).await;
    let reg = Registry::new();
    let options = StreamOptions {
        capability: None,
        ..s.options(&reg)
    };
    let mut stream = s.supervise(s.task(3), options).await;
    let (chunks, end) = drain(&mut stream).await;
    assert!(chunks.is_empty());
    match end {
        SupervisedPoll::Closed(StreamError::PeerAborted { reason, .. }) => {
            assert_eq!(reason, Reason::CapabilityRequired)
        }
        other => panic!("expected the refusal, got {other:?}"),
    }
    assert_eq!(s.opener.opened().len(), 1);
}

// ═════════════════════════════════════════════════════════════════════════
// Stall reactions
// ═════════════════════════════════════════════════════════════════════════

/// A producer stall (credit held, nothing sent) under `Preempt` is
/// cancelled by the scheduler (`Stalled → Cancelled`, ENTANGLE-E0474) and
/// counted; under `PreemptAndReassign` the stream restarts on another
/// executor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_producer_stall_is_preempted_or_reassigned() {
    let s = setup(&[Behaviour::StallAfter(0), Behaviour::Healthy]).await;
    let reg = Registry::new();
    let stalling = |reaction| StreamOptions {
        submitter: SubmitterOptions {
            stall_after: Some(Duration::from_millis(250)),
            ..SubmitterOptions::default()
        },
        stall: StallPolicy {
            reaction,
            ..StallPolicy::default()
        },
        ..s.options(&reg)
    };
    let started = Instant::now();
    let mut stream = s
        .supervise(s.task(3), stalling(StallReaction::Preempt))
        .await;
    let (chunks, end) = drain(&mut stream).await;
    assert!(chunks.is_empty());
    match end {
        SupervisedPoll::Closed(
            e @ StreamError::Preempted {
                kind: StallKind::Producer,
                reassign: false,
                ..
            },
        ) => {
            assert!(e.to_string().starts_with("ENTANGLE-E0474"), "{e}");
        }
        other => panic!("expected a preemption, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(stalls(&reg, "preempted"), 1.0);

    let mut stream = s
        .supervise(s.task(3), stalling(StallReaction::PreemptAndReassign))
        .await;
    let (chunks, end) = drain(&mut stream).await;
    assert_eq!(chunks.len(), 3);
    assert!(
        matches!(end, SupervisedPoll::Ended { executor, .. } if executor == s.peers[1]),
        "{end:?}"
    );
    assert_eq!(stalls(&reg, "reassigned"), 1.0);
    assert_eq!(retries(&reg, "stalled"), 1.0);
}

/// A credit stall (the consumer takes nothing): with `Wait` the executor
/// cancels the stream as unresponsive after twice its credit-exhaustion
/// timeout; with `Extend` the scheduler's `Extend` control frame pushes
/// that cancellation out, and the stream completes once the consumer
/// resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credit_stall_is_extended_through_a_control_frame() {
    let s = setup(&[Behaviour::Healthy]).await;
    let reg = Registry::new();
    let mut task = s.task(12);
    task.channel.credit_window = 2;
    task.channel.credit_exhaustion_timeout_ms = 300;
    task.retry = RetryPolicy::never();

    // Wait: unresponsive after ~600 ms.
    let mut handle = s
        .opener
        .open(s.peers[0], &task, s.options(&reg))
        .await
        .unwrap();
    handle.finish_input().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let mut closed = None;
    for _ in 0..20 {
        match deadline("next", handle.next()).await {
            ChunkPoll::Chunk(_) => continue,
            ChunkPoll::Closed(e) => {
                closed = Some(e);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let e = closed.expect("closed");
    assert!(
        matches!(
            &e,
            StreamError::PeerAborted {
                reason: Reason::SubmitterUnresponsive,
                ..
            }
        ),
        "{e}"
    );
    assert_eq!(stalls(&reg, "waited"), 1.0);

    // Extend by 2 s once: still alive at 1.2 s, and it completes.
    let options = StreamOptions {
        stall: StallPolicy {
            reaction: StallReaction::Extend {
                by: Duration::from_secs(2),
                times: 1,
            },
            ..StallPolicy::default()
        },
        ..s.options(&reg)
    };
    let mut task = task.clone();
    task.id = uuid::Uuid::new_v4();
    task.channel.credit_exhaustion_timeout_ms = 300;
    let mut handle = s.opener.open(s.peers[0], &task, options).await.unwrap();
    handle.finish_input().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let mut n = 0;
    let end = loop {
        match deadline("next", handle.next()).await {
            ChunkPoll::Chunk(_) => n += 1,
            other => break other,
        }
    };
    assert!(matches!(end, ChunkPoll::Ended(_)), "{end:?}");
    assert_eq!(n, 12);
    assert_eq!(stalls(&reg, "extended"), 1.0);
}

/// `Extend { times: 3 }` gives three effective extensions even when each
/// is no longer than the credit-exhaustion timeout: the submitter re-extends
/// before the extension it sent runs out, so the executor never cancels
/// the stream as unresponsive in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_extension_lands_before_the_previous_one_runs_out() {
    let s = setup(&[Behaviour::Healthy]).await;
    let reg = Registry::new();
    let mut task = s.task(12);
    task.channel.credit_window = 2;
    task.channel.credit_exhaustion_timeout_ms = 400;
    task.retry = RetryPolicy::never();
    let options = StreamOptions {
        stall: StallPolicy {
            reaction: StallReaction::Extend {
                by: Duration::from_millis(300),
                times: 3,
            },
            ..StallPolicy::default()
        },
        ..s.options(&reg)
    };
    let mut handle = s.opener.open(s.peers[0], &task, options).await.unwrap();
    handle.finish_input().await.unwrap();
    // Unextended, the executor gives up at about 800 ms (twice the
    // timeout); three extensions of 300 ms carry the stream past 1 s.
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let mut n = 0;
    let end = loop {
        match deadline("next", handle.next()).await {
            ChunkPoll::Chunk(_) => n += 1,
            other => break other,
        }
    };
    assert!(matches!(end, ChunkPoll::Ended(_)), "{end:?}");
    assert_eq!(n, 12);
    assert_eq!(stalls(&reg, "extended"), 3.0);
}

// ═════════════════════════════════════════════════════════════════════════
// Stall blame
// ═════════════════════════════════════════════════════════════════════════

/// An executor that stalls after delivering at least half of the expected
/// output loses reputation (`StalledStream`); one that stalls early does
/// not the first time, but does when it stalls again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalling_late_or_repeatedly_costs_reputation() {
    let s = setup(&[Behaviour::StallAfter(3)]).await;
    let late = s.peers[0];
    let reg = Registry::new();
    let store = Arc::new(ReputationStore::new());
    let options = StreamOptions {
        submitter: SubmitterOptions {
            stall_after: Some(Duration::from_millis(200)),
            ..SubmitterOptions::default()
        },
        stall: StallPolicy {
            reaction: StallReaction::Preempt,
            ..StallPolicy::default()
        },
        reputation: Some(Arc::clone(&store)),
        ..s.options(&reg)
    };
    // 3 chunks of "chunk-<i>\n" = 24 bytes, of 40 expected: past half.
    let mut task = s.task(3);
    task.expected_output_bytes = Some(40);
    task.retry = RetryPolicy::never();
    let mut stream = s.supervise(task, options.clone()).await;
    let (chunks, end) = drain(&mut stream).await;
    assert_eq!(chunks.len(), 3);
    assert!(
        matches!(end, SupervisedPoll::Closed(StreamError::Preempted { .. })),
        "{end:?}"
    );
    let record = store.record(&late, PolicyKind::None);
    assert_eq!((record.total, record.correct), (1, 0), "penalised once");

    // Early stall (3 of 1000 expected bytes): no blame the first time…
    let s = setup(&[Behaviour::StallAfter(3)]).await;
    let early = s.peers[0];
    let store = Arc::new(ReputationStore::new());
    let options = StreamOptions {
        reputation: Some(Arc::clone(&store)),
        capability: Some(Arc::clone(&s.tokens)),
        ..options
    };
    for round in 0..2 {
        let mut task = s.task(3);
        task.expected_output_bytes = Some(1_000);
        task.retry = RetryPolicy::never();
        let preempted = stalls(&reg, "preempted");
        let mut stream = s.supervise(task, options.clone()).await;
        let (chunks, end) = drain(&mut stream).await;
        // The stall was seen (and preempted) both times: the first round's
        // "no blame" is the repeat rule, not a stall that went unnoticed.
        assert_eq!(chunks.len(), 3, "round {round}");
        assert!(
            matches!(
                end,
                SupervisedPoll::Closed(StreamError::Preempted {
                    kind: StallKind::Producer,
                    ..
                })
            ),
            "round {round}: {end:?}"
        );
        assert_eq!(stalls(&reg, "preempted"), preempted + 1.0, "round {round}");
        let record = store.record(&early, PolicyKind::None);
        match round {
            0 => assert_eq!(record.total, 0, "an early first stall is not blamed"),
            _ => assert_eq!(
                (record.total, record.correct),
                (1, 0),
                "a repeated stall is"
            ),
        }
    }
}

/// A credit stall is the consumer's doing: it never counts towards the
/// executor's repeated-stall blame. Here the consumer stops reading (a
/// credit stall), resumes, and only then does the executor stall while
/// holding credit — its first producer stall, which is not blamed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credit_stall_never_counts_towards_producer_stall_blame() {
    let s = setup(&[Behaviour::StallAfter(2)]).await;
    let executor = s.peers[0];
    let reg = Registry::new();
    let store = Arc::new(ReputationStore::new());
    let options = StreamOptions {
        submitter: SubmitterOptions {
            stall_after: Some(Duration::from_millis(200)),
            ..SubmitterOptions::default()
        },
        reputation: Some(Arc::clone(&store)),
        ..s.options(&reg)
    };
    let mut task = s.task(2);
    task.channel.credit_window = 2;
    task.channel.credit_exhaustion_timeout_ms = 200;
    task.expected_output_bytes = Some(1_000);
    task.retry = RetryPolicy::never();
    let mut handle = s.opener.open(executor, &task, options).await.unwrap();
    handle.finish_input().await.unwrap();
    // The consumer takes nothing: the executor has used its window.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(stalls(&reg, "waited"), 1.0, "the credit stall was seen");
    // The consumer resumes; the executor now holds credit and sends nothing.
    for _ in 0..2 {
        match deadline("next", handle.next()).await {
            ChunkPoll::Chunk(_) => {}
            other => panic!("expected a chunk, got {other:?}"),
        }
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(stalls(&reg, "waited"), 2.0, "the producer stall was seen");
    let record = store.record(&executor, PolicyKind::None);
    assert_eq!(
        record.total, 0,
        "one producer stall (after a credit stall) is not a repeated stall"
    );
    handle.cancel().await;
}

/// An executor that has answered and waits for the submitter's next input
/// is not a stalled producer, however long the submitter takes: a
/// multi-turn stream with `stall_after` set is neither preempted nor
/// blamed while the submitter is slow, and runs to its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiting_for_the_submitters_next_input_is_not_a_producer_stall() {
    let s = setup(&[Behaviour::Healthy]).await;
    let executor = s.peers[0];
    let reg = Registry::new();
    let store = Arc::new(ReputationStore::new());
    let options = StreamOptions {
        submitter: SubmitterOptions {
            stall_after: Some(Duration::from_millis(200)),
            ..SubmitterOptions::default()
        },
        stall: StallPolicy {
            reaction: StallReaction::Preempt,
            ..StallPolicy::default()
        },
        reputation: Some(Arc::clone(&store)),
        ..s.options(&reg)
    };
    let mut task = s.task(1);
    task.retry = RetryPolicy::never();
    let mut handle = s.opener.open(executor, &task, options).await.unwrap();
    let mut chunks = 0;
    for turn in ["turn 1\n", "turn 2\n"] {
        match deadline("next", handle.next()).await {
            ChunkPoll::Chunk(_) => chunks += 1,
            other => panic!("expected a chunk before {turn:?}, got {other:?}"),
        }
        // The human takes a while to type the next turn.
        tokio::time::sleep(Duration::from_millis(700)).await;
        handle
            .send_input(turn.as_bytes().to_vec())
            .await
            .expect("the stream is still open");
    }
    handle.finish_input().await.expect("still open");
    let end = loop {
        match deadline("next", handle.next()).await {
            ChunkPoll::Chunk(_) => chunks += 1,
            other => break other,
        }
    };
    assert!(matches!(end, ChunkPoll::Ended(_)), "{end:?}");
    assert_eq!(chunks, 3, "the initial line and one per turn");
    assert_eq!(stalls(&reg, "preempted"), 0.0);
    // The completed stream credits the executor; nothing penalised it.
    let record = store.record(&executor, PolicyKind::None);
    assert_eq!(record.total, record.correct, "{record:?}");
}
