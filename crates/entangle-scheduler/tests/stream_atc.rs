//! Streaming tasks — spec §16.4 ATC-INT-4 / ATC-INT-6 and §16.5 ATC-STR-1,
//! -2, -3 — plus end-to-end runs of the real `stream-lines` plugin.
//!
//! Three kinds of test live here:
//!
//! * **deterministic** — the two pure state machines wired together through
//!   the real frame codec, on a simulated clock. This is how the 5 s / 15 s
//!   timing propositions are checked exactly, without waiting;
//! * **real time, scaled down** — the async drivers on tokio time over an
//!   in-memory duplex, with 100–400 ms intervals instead of 5 s;
//! * **end to end** — the `stream-lines` wasm component executed by a
//!   `StreamServer` on one node and consumed by another, over a duplex or
//!   over two loopback `mesh.iroh` endpoints.
//!
//! The timing tests assert a strict lower bound (nothing fires early) and a
//! generous upper bound (a loaded CI box schedules late, never early).

use std::sync::Arc;
use std::time::{Duration, Instant};

use entangle_mesh_iroh::{
    duplex_pair, FramedStream, IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_SCHEDULER,
    ALPN_STREAM, MAX_FRAME_BYTES,
};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::stream::frame::{
    decode_frame, encode_frame, AcceptedFrame, ChunkFrame, Frame, OpenFrame, CHUNK_FRAME_OVERHEAD,
    CONTROL_FRAME_MAX,
};
use entangle_scheduler::stream::{
    open_stream, request_digest, validate_submit, verify_transcript, ChunkPoll, ChunkSigner,
    ChunkVerifier, ExecutorConfig, ExecutorMachine, ExecutorState, Reason, SendOutcome, Side,
    StalledEvent, StreamCeilings, StreamError, StreamEvent, StreamHandle, StreamOptions,
    StreamOutcome, StreamServer, SubmitterMachine, SubmitterOptions, SubmitterState,
};
use entangle_scheduler::work_unit::PolicyEnvelope;
use entangle_scheduler::{ReputationStore, StaticAllowlist};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{
    ChannelSpec, IntegrityPolicy, MetricRef, PartialResultPolicy, PolicyKind, StreamingTask,
};
use tokio::sync::mpsc;

/// Ceiling on any single await, so a hang is a named failure.
const TEST_DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(TEST_DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {TEST_DEADLINE:?}"),
    }
}

// ── fixtures ────────────────────────────────────────────────────────────────

const STREAM_LINES_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/stream-lines.wasm"
);
const HELLO_PONG_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../entangle-host/tests/fixtures/hello-pong.wasm"
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

/// Write a signed plugin package and return its id.
fn write_package(
    dir: &std::path::Path,
    publisher: &IdentityKeyPair,
    name: &str,
    wasm: &[u8],
) -> PluginId {
    let id = format!("{}/{name}@0.1.0", publisher.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n\
         description = \"streaming test plugin\"\n"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    let bundle = sign_artifact(wasm, manifest.as_bytes(), publisher);
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    id.parse().unwrap()
}

/// A kernel with `stream-lines` (and `hello-pong`, a one-shot plugin)
/// loaded.
struct Plugins {
    kernel: Arc<Kernel>,
    stream_lines: PluginId,
    hello_pong: PluginId,
    _dirs: Vec<tempfile::TempDir>,
}

async fn plugins() -> Plugins {
    plugins_with(None).await
}

/// [`plugins`] on a kernel that records into `metrics`.
async fn plugins_with(metrics: Option<entangle_observability::Registry>) -> Plugins {
    let publisher = IdentityKeyPair::generate();
    let mut kernel = Kernel::new(KernelConfig::default(), keyring_for(&publisher)).expect("kernel");
    if let Some(registry) = metrics {
        kernel = kernel.with_metrics(registry);
    }
    let kernel = Arc::new(kernel);
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let stream_lines = write_package(
        a.path(),
        &publisher,
        "stream-lines",
        &std::fs::read(STREAM_LINES_WASM)
            .expect("stream-lines.wasm fixture (see fixtures/build.sh)"),
    );
    let hello_pong = write_package(
        b.path(),
        &publisher,
        "hello-pong",
        &std::fs::read(HELLO_PONG_WASM).expect("hello-pong.wasm fixture"),
    );
    kernel
        .load_plugin_from_dir(a.path())
        .await
        .expect("load stream-lines");
    kernel
        .load_plugin_from_dir(b.path())
        .await
        .expect("load hello-pong");
    assert_eq!(kernel.plugin_world(&stream_lines), Some("stream-plugin"));
    assert_eq!(kernel.plugin_world(&hello_pong), Some("plugin"));
    Plugins {
        kernel,
        stream_lines,
        hello_pong,
        _dirs: vec![a, b],
    }
}

fn plugin_id() -> PluginId {
    "0123456789abcdef0123456789abcdef/stream-lines@0.1.0"
        .parse()
        .unwrap()
}

fn lines(n: usize, width: usize) -> String {
    (0..n)
        .map(|i| format!("{:<w$}\n", format!("line {i:03}"), w = width - 1))
        .collect()
}

/// Test ceilings: sub-second heartbeats and stall timeouts allowed.
fn fast_ceilings() -> StreamCeilings {
    StreamCeilings {
        min_heartbeat_ms: 10,
        min_credit_exhaustion_timeout_ms: 10,
        ..StreamCeilings::default()
    }
}

/// A `StreamServer` for `executor` serving `kernel` to `allowed`.
fn server(
    plugins: &Plugins,
    executor: &IdentityKeyPair,
    allowed: &[PeerId],
) -> (StreamServer, mpsc::UnboundedReceiver<(PeerId, StreamEvent)>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let allowlist: StaticAllowlist = allowed.iter().copied().collect();
    let s = StreamServer::new(
        Arc::clone(&plugins.kernel),
        Arc::new(allowlist),
        executor.clone(),
    )
    .with_ceilings(fast_ceilings())
    .with_events(tx);
    (s, rx)
}

fn peer_of(key: &IdentityKeyPair) -> PeerId {
    PeerId::from_public_key_bytes(key.public().as_bytes())
}

fn pub_of(key: &IdentityKeyPair) -> [u8; 32] {
    *key.public().as_bytes()
}

/// An in-memory stream between `submitter` and `executor`, each end
/// reporting the other's key as its authenticated remote identity.
fn duplex(submitter: &IdentityKeyPair, executor: &IdentityKeyPair) -> (FramedStream, FramedStream) {
    duplex_pair(
        pub_of(submitter),
        pub_of(executor),
        MAX_FRAME_BYTES,
        64 * 1024,
    )
}

async fn send_frame(io: &mut FramedStream, frame: &Frame) {
    io.send(&encode_frame(frame).unwrap()).await.unwrap();
}

async fn recv_frame(io: &mut FramedStream, from: Side) -> Option<Frame> {
    deadline("receiving a frame", io.recv())
        .await
        .unwrap()
        .map(|bytes| decode_frame(&bytes, from).unwrap())
}

// ── deterministic two-machine simulation ────────────────────────────────────

/// Both ends of one stream on a simulated clock, frames through the codec.
struct Sim {
    exec: ExecutorMachine,
    sub: SubmitterMachine,
    now: Instant,
    t0: Instant,
    exec_events: Vec<(Instant, StreamEvent)>,
}

impl Sim {
    fn new(task: &StreamingTask) -> Self {
        Self::new_lossy(task, &no_loss, &no_loss)
    }

    /// Like [`Sim::new`], with the given frame loss from the very first
    /// frame on.
    fn new_lossy(
        task: &StreamingTask,
        lose_to_sub: &dyn Fn(&Frame) -> bool,
        lose_to_exec: &dyn Fn(&Frame) -> bool,
    ) -> Self {
        let t0 = Instant::now();
        let key = IdentityKeyPair::from_seed(&[7; 32]);
        let mut sub =
            SubmitterMachine::new(task, pub_of(&key), SubmitterOptions::default(), t0).unwrap();
        let Some(Frame::Open(open)) = sub.poll_transmit() else {
            panic!("first frame must be Open");
        };
        let env = PolicyEnvelope::open(open.policy.clone(), open.policy_hash).unwrap();
        let limits = StreamCeilings::default()
            .accept(&open.channel, open.timeout_ms)
            .unwrap();
        let exec = ExecutorMachine::new(
            ExecutorConfig {
                task_id: task.id,
                policy_hash: env.hash(),
                request: request_digest(&open),
                limits,
                local_peer: peer_of(&key),
            },
            ChunkSigner::new(key, open.task_id, env.hash(), request_digest(&open)),
            t0,
        );
        let mut sim = Self {
            exec,
            sub,
            now: t0,
            t0,
            exec_events: Vec::new(),
        };
        sim.pump(lose_to_sub, lose_to_exec);
        sim
    }

    fn pump(
        &mut self,
        lose_to_sub: &dyn Fn(&Frame) -> bool,
        lose_to_exec: &dyn Fn(&Frame) -> bool,
    ) {
        loop {
            let mut moved = false;
            while let Some(f) = self.exec.poll_transmit() {
                moved = true;
                if !lose_to_sub(&f) {
                    let f = decode_frame(&encode_frame(&f).unwrap(), Side::Executor).unwrap();
                    let _ = self.sub.on_frame(f, self.now);
                }
            }
            while let Some(f) = self.sub.poll_transmit() {
                moved = true;
                if !lose_to_exec(&f) {
                    let f = decode_frame(&encode_frame(&f).unwrap(), Side::Submitter).unwrap();
                    let _ = self.exec.on_frame(f, self.now);
                }
            }
            while let Some(e) = self.exec.poll_event() {
                self.exec_events.push((self.now, e));
            }
            if !moved {
                return;
            }
        }
    }

    /// Advance the clock to `until`, firing every timer at its exact
    /// deadline on the way.
    fn advance(
        &mut self,
        until: Instant,
        lose_to_sub: &dyn Fn(&Frame) -> bool,
        lose_to_exec: &dyn Fn(&Frame) -> bool,
    ) {
        loop {
            let next = [self.exec.poll_timeout(), self.sub.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            match next {
                Some(at) if at <= until => {
                    self.now = self.now.max(at);
                    self.exec.on_timeout(self.now);
                    self.sub.on_timeout(self.now);
                    self.pump(lose_to_sub, lose_to_exec);
                }
                _ => {
                    self.now = until;
                    return;
                }
            }
        }
    }
}

fn no_loss(_: &Frame) -> bool {
    false
}

fn is_pong(f: &Frame) -> bool {
    matches!(f, Frame::Pong { .. })
}

fn assert_within(what: &str, actual: Duration, expected: Duration, tolerance: Duration) {
    let lo = expected.saturating_sub(tolerance);
    let hi = expected + tolerance;
    assert!(
        actual >= lo && actual <= hi,
        "{what}: {actual:?} is outside {expected:?} ± {tolerance:?}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// ATC-INT-4 — streaming + Deterministic rejected at submit time
// ════════════════════════════════════════════════════════════════════════════

/// ATC-INT-4: GIVEN a StreamingTask with Integrity::Deterministic, WHEN the
/// submitter submits it, THEN the call returns
/// Err(InvalidIntegrityForStreaming) with a hint to use TrustedExecutor —
/// and nothing is dialled.
#[tokio::test]
async fn atc_int_4_streaming_deterministic_rejected_at_submit() {
    let mut task = StreamingTask::with_defaults(plugin_id(), b"prompt".to_vec());
    task.integrity = IntegrityPolicy::Deterministic { replicas: 3 };

    let err = validate_submit(&task).unwrap_err();
    match &err {
        StreamError::InvalidIntegrityForStreaming { policy, hint, .. } => {
            assert_eq!(*policy, PolicyKind::Deterministic);
            assert!(hint.contains("TrustedExecutor"), "{hint}");
        }
        other => panic!("expected InvalidIntegrityForStreaming, got {other}"),
    }
    let text = err.to_string();
    assert!(text.starts_with("ENTANGLE-E0350"), "{text}");
    assert!(
        text.contains("hint") && text.contains("TrustedExecutor"),
        "{text}"
    );

    // The client entry point refuses before dialling: the target address is
    // a port nothing listens on, and the call still returns at once with the
    // integrity error rather than a connect error after the dial timeout.
    let transport = MeshIroh::start(
        MeshIrohConfig {
            alpn: ALPN_STREAM.to_vec(),
            connect_timeout: Duration::from_secs(5),
            ..MeshIrohConfig::loopback()
        },
        &IdentityKeyPair::generate(),
    )
    .await
    .unwrap();
    let nowhere = IrohPeer::new(
        pub_of(&IdentityKeyPair::generate()),
        "127.0.0.1:9".parse().unwrap(),
    );
    let started = Instant::now();
    let err = open_stream(&transport, &nowhere, &task, StreamOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(err, StreamError::InvalidIntegrityForStreaming { .. }),
        "{err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "nothing was dialled"
    );

    // The submitter state machine and the stream handle refuse it too.
    let exec = IdentityKeyPair::generate();
    assert!(matches!(
        SubmitterMachine::new(
            &task,
            pub_of(&exec),
            SubmitterOptions::default(),
            Instant::now()
        ),
        Err(StreamError::InvalidIntegrityForStreaming { .. })
    ));
    let (sub_io, _exec_io) = duplex(&IdentityKeyPair::generate(), &exec);
    assert!(matches!(
        StreamHandle::start(sub_io, &task, StreamOptions::default()),
        Err(StreamError::InvalidIntegrityForStreaming { .. })
    ));
    transport.shutdown().await;
}

/// ATC-INT-4 (the rest of the §7.5 rule): SemanticEquivalent is refused the
/// same way; TrustedExecutor and None are accepted.
#[test]
fn atc_int_4_semantic_equivalent_rejected_trusted_executor_and_none_accepted() {
    let mut task = StreamingTask::with_defaults(plugin_id(), vec![]);
    task.integrity = IntegrityPolicy::SemanticEquivalent {
        replicas: 3,
        quorum: 2,
        metric: MetricRef {
            plugin: plugin_id(),
            publisher_key: [1; 32],
            artifact_blake3: [2; 32],
        },
        threshold: 0.2,
    };
    match validate_submit(&task) {
        Err(StreamError::InvalidIntegrityForStreaming { policy, hint, .. }) => {
            assert_eq!(policy, PolicyKind::SemanticEquivalent);
            assert!(hint.contains("TrustedExecutor"));
        }
        other => panic!("expected InvalidIntegrityForStreaming, got {other:?}"),
    }

    task.integrity = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![PeerId::from_public_key_bytes(&[3; 32])],
    };
    let env = validate_submit(&task).expect("TrustedExecutor is valid for a stream");
    assert_eq!(env.policy(), &task.integrity);

    task.integrity = IntegrityPolicy::None;
    validate_submit(&task).expect("None is valid for a stream");
}

// ════════════════════════════════════════════════════════════════════════════
// ATC-INT-6 — max_total_bytes enforced on both ends
// ════════════════════════════════════════════════════════════════════════════

/// ATC-INT-6, executor side: the executor refuses the chunk that would
/// carry the stream past max_total_bytes and closes with
/// Reason::TotalBytesExceeded; the submitter keeps what fit (policy Keep).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atc_int_6_executor_closes_at_max_total_bytes() {
    let plugins = plugins().await;
    let submitter = IdentityKeyPair::generate();
    let executor = IdentityKeyPair::generate();
    let (srv, _events) = server(&plugins, &executor, &[peer_of(&submitter)]);

    let mut task =
        StreamingTask::with_defaults(plugins.stream_lines.clone(), lines(40, 30).into_bytes());
    task.channel.max_chunk_bytes = 64;
    task.channel.max_total_bytes = 1024;
    task.partial_result = PartialResultPolicy::Keep;

    let (sub_io, exec_io) = duplex(&submitter, &executor);
    let served = tokio::spawn(async move { srv.handle(exec_io).await });
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    handle.finish_input().await.unwrap();
    let result = deadline("collecting", handle.collect()).await;

    match &result.outcome {
        StreamOutcome::Interrupted(StreamError::PeerAborted {
            by: Side::Executor,
            reason: Reason::TotalBytesExceeded,
            ..
        }) => {}
        other => panic!("expected the executor to close with TotalBytesExceeded, got {other:?}"),
    }
    // 34 lines of 30 bytes fit in 1024; the 35th would make 1050.
    assert_eq!(result.received_bytes, 34 * 30);
    assert_eq!(result.bytes(), lines(34, 30).into_bytes());

    let report = deadline("executor", served).await.unwrap().unwrap();
    assert_eq!(
        report.outcome,
        Err(StreamError::StreamBytesExceeded {
            limit: 1024,
            attempted: 35 * 30
        })
    );
    assert_eq!(
        report.bytes_sent,
        34 * 30,
        "the executor never exceeded the cap"
    );
}

fn signed_chunk(signer: &ChunkSigner, seq: u64, bytes: Vec<u8>) -> Frame {
    let signature = signer.sign_chunk(seq, blake3::hash(&bytes).as_bytes());
    Frame::Chunk(ChunkFrame {
        seq,
        bytes,
        signature,
    })
}

/// Wait until a framed end sees an `Error` frame; return its reason.
async fn error_reason(io: &mut FramedStream, from: Side) -> Reason {
    loop {
        match recv_frame(io, from).await {
            Some(Frame::Error { reason, .. }) => return reason,
            Some(_) => continue,
            None => panic!("stream ended without an Error frame"),
        }
    }
}

/// A hand-driven peer on the raw byte level — the stand-in for a malicious
/// or broken executor. It writes length-prefixed frames itself, so it can
/// also write a frame *header* with no body behind it.
struct RawPeer {
    io: tokio::io::DuplexStream,
}

/// A framed end for the code under test (owned by `framed_owner`, whose
/// remote identity is `raw_identity`) and a [`RawPeer`] on the other side.
fn raw_pair(raw_identity: &IdentityKeyPair) -> (FramedStream, RawPeer) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let (read, write) = tokio::io::split(a);
    (
        FramedStream::from_parts(write, read, pub_of(raw_identity), MAX_FRAME_BYTES),
        RawPeer { io: b },
    )
}

impl RawPeer {
    async fn send_frame(&mut self, frame: &Frame) {
        use tokio::io::AsyncWriteExt as _;
        let body = encode_frame(frame).unwrap();
        self.io
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        self.io.write_all(&body).await.unwrap();
    }

    /// A frame header announcing `len` bytes, and no body.
    async fn send_header_only(&mut self, len: u32) {
        use tokio::io::AsyncWriteExt as _;
        self.io.write_all(&len.to_be_bytes()).await.unwrap();
    }

    /// A frame header announcing `len` bytes, then just `prefix` of its
    /// body.
    async fn send_header_and_prefix(&mut self, len: u32, prefix: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        self.io.write_all(&len.to_be_bytes()).await.unwrap();
        self.io.write_all(prefix).await.unwrap();
    }

    /// The next frame from the framed end (sent by `from`), or `None` at its
    /// end of stream.
    async fn recv_frame(&mut self, from: Side) -> Option<Frame> {
        use tokio::io::AsyncReadExt as _;
        let mut header = [0u8; 4];
        match deadline("raw header", self.io.read_exact(&mut header)).await {
            Ok(_) => {}
            Err(_) => return None,
        }
        let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
        deadline("raw body", self.io.read_exact(&mut body))
            .await
            .ok()?;
        Some(decode_frame(&body, from).unwrap())
    }

    /// Act as an executor: read `Open`, answer `Accepted` honestly, and
    /// return a signer for `key`.
    async fn accept(&mut self, key: &IdentityKeyPair) -> (OpenFrame, ChunkSigner) {
        let Some(Frame::Open(open)) = self.recv_frame(Side::Submitter).await else {
            panic!("expected Open");
        };
        self.send_frame(&Frame::Accepted(AcceptedFrame {
            observed_policy_hash: open.policy_hash,
            channel: open.channel,
            input_window: 4,
            timeout_ms: open.timeout_ms,
        }))
        .await;
        let signer = ChunkSigner::new(
            key.clone(),
            open.task_id,
            open.policy_hash,
            request_digest(&open),
        );
        (open, signer)
    }

    async fn error_reason(&mut self, from: Side) -> Reason {
        loop {
            match self.recv_frame(from).await {
                Some(Frame::Error { reason, .. }) => return reason,
                Some(_) => continue,
                None => panic!("stream ended without an Error frame"),
            }
        }
    }
}

/// ATC-INT-6, submitter side: an executor that does not self-close at
/// max_total_bytes is torn down by the submitter with StreamBytesExceeded —
/// from the frame header alone, before the oversized chunk is allocated —
/// and loses reputation.
#[tokio::test]
async fn atc_int_6_submitter_tears_down_an_executor_that_does_not_self_close() {
    let executor = IdentityKeyPair::generate();
    let mut task = StreamingTask::with_defaults(plugin_id(), vec![]);
    task.channel.max_chunk_bytes = 4096;
    task.channel.max_total_bytes = 5000;
    let reputation = Arc::new(ReputationStore::new());
    let before = reputation.get(&peer_of(&executor), PolicyKind::None);

    let (sub_io, mut raw) = raw_pair(&executor);
    let mut handle = StreamHandle::start(
        sub_io,
        &task,
        StreamOptions {
            reputation: Some(Arc::clone(&reputation)),
            ..StreamOptions::default()
        },
    )
    .unwrap();
    let (_open, signer) = raw.accept(&executor).await;
    // 3000 bytes: within both caps.
    raw.send_frame(&signed_chunk(&signer, 0, vec![b'a'; 3000]))
        .await;
    // Then the header of another 3000-byte chunk (6000 in total) and no
    // body at all. A submitter that allocated or read the body before
    // checking the budget would hang here; this one refuses the header.
    raw.send_header_only(3000 + CHUNK_FRAME_OVERHEAD as u32)
        .await;

    match deadline("first chunk", handle.next()).await {
        ChunkPoll::Chunk(c) => assert_eq!(c.bytes.len(), 3000),
        other => panic!("expected the in-budget chunk, got {other:?}"),
    }
    match deadline("teardown", handle.next()).await {
        ChunkPoll::Closed(StreamError::StreamBytesExceeded { limit, attempted }) => {
            assert_eq!(limit, 5000);
            assert!(attempted > 5000, "{attempted}");
        }
        other => panic!("expected StreamBytesExceeded, got {other:?}"),
    }
    assert_eq!(
        raw.error_reason(Side::Submitter).await,
        Reason::TotalBytesExceeded,
        "the submitter tells the executor why"
    );
    let report = handle.finish().await;
    assert_eq!(report.context.received_bytes, 3000);
    assert!(
        reputation.get(&peer_of(&executor), PolicyKind::None) < before,
        "an executor that overruns the cap loses reputation"
    );

    // The precise check holds too for small frames that overrun the budget:
    // 60 + 60 > 100, every frame far under the frame cap.
    let mut small = StreamingTask::with_defaults(plugin_id(), vec![]);
    small.channel.max_chunk_bytes = 64;
    small.channel.max_total_bytes = 100;
    let (sub_io, mut raw) = raw_pair(&executor);
    let mut handle = StreamHandle::start(sub_io, &small, StreamOptions::default()).unwrap();
    let (_open, signer) = raw.accept(&executor).await;
    raw.send_frame(&signed_chunk(&signer, 0, vec![1; 60])).await;
    raw.send_frame(&signed_chunk(&signer, 1, vec![2; 60])).await;
    assert!(matches!(handle.next().await, ChunkPoll::Chunk(_)));
    assert_eq!(
        handle.next().await,
        ChunkPoll::Closed(StreamError::StreamBytesExceeded {
            limit: 100,
            attempted: 120
        })
    );

    // And a single chunk over max_chunk_bytes is refused from its header.
    let (sub_io, mut raw) = raw_pair(&executor);
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    raw.accept(&executor).await;
    raw.send_header_only(64 * 1024 * 1024).await;
    assert!(matches!(
        deadline("oversized chunk", handle.next()).await,
        ChunkPoll::Closed(StreamError::ChunkSizeExceeded { limit: 4096, .. })
    ));
}

/// ATC-INT-6 with its GIVEN as written, max_total_bytes = 1024: the chunk
/// that would cross the cap is refused from its frame header (and the two
/// bytes after it that say it is a chunk) although its frame is smaller
/// than the largest control frame — its body is never read.
#[tokio::test]
async fn atc_int_6_crossing_chunk_refused_before_its_body_at_1024_bytes() {
    let executor = IdentityKeyPair::generate();
    let mut task = StreamingTask::with_defaults(plugin_id(), vec![]);
    task.channel.max_total_bytes = 1024;

    let (sub_io, mut raw) = raw_pair(&executor);
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    let (_open, signer) = raw.accept(&executor).await;
    raw.send_frame(&signed_chunk(&signer, 0, vec![b'a'; 1000]))
        .await;
    // 1000 more bytes would make 2000; the frame is ~1.1 KiB, under the
    // 2 KiB control-frame bound. Its header and kind, and nothing else.
    let next = encode_frame(&signed_chunk(&signer, 1, vec![b'b'; 1000])).unwrap();
    assert!(next.len() < CONTROL_FRAME_MAX, "{}", next.len());
    raw.send_header_and_prefix(next.len() as u32, &next[..2])
        .await;

    match deadline("first chunk", handle.next()).await {
        ChunkPoll::Chunk(c) => assert_eq!(c.bytes.len(), 1000),
        other => panic!("expected the in-budget chunk, got {other:?}"),
    }
    match deadline("teardown", handle.next()).await {
        ChunkPoll::Closed(StreamError::StreamBytesExceeded { limit, attempted }) => {
            assert_eq!(limit, 1024);
            assert!(attempted > 1024, "{attempted}");
        }
        other => panic!("expected StreamBytesExceeded from the header, got {other:?}"),
    }
    assert_eq!(
        raw.error_reason(Side::Submitter).await,
        Reason::TotalBytesExceeded
    );
}

/// Only chunk frames get the chunk budget: any other frame is held to the
/// control-frame bound, from its header and kind, even while the budget
/// would allow a far larger chunk.
#[tokio::test]
async fn an_oversized_control_frame_is_refused_before_its_body() {
    let executor = IdentityKeyPair::generate();
    let mut task = StreamingTask::with_defaults(plugin_id(), vec![]);
    task.channel.max_chunk_bytes = 64 * 1024;

    let (sub_io, mut raw) = raw_pair(&executor);
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    raw.accept(&executor).await;
    // A Pong announcing 8 KiB: within the chunk budget, over the bound.
    let pong = encode_frame(&Frame::Pong { seq: 0, ts_ms: 0 }).unwrap();
    raw.send_header_and_prefix(8 * 1024, &pong[..2]).await;

    match deadline("teardown", handle.next()).await {
        ChunkPoll::Closed(StreamError::Protocol {
            by: Side::Executor,
            detail,
        }) => assert!(detail.contains("control frame"), "{detail}"),
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ATC-STR-1 — credit exhaustion stalls within task_timeout ± 0.5 s
// ════════════════════════════════════════════════════════════════════════════

/// ATC-STR-1: GIVEN a StreamingTask with task_timeout = 5 s and a submitter
/// that issues no Credit frames after the initial window, WHEN the worker
/// exhausts its credits, THEN within 5 s ± 0.5 s it emits a StalledEvent and
/// is in state Stalled.
#[test]
fn atc_str_1_credit_exhaustion_stalls_at_timeout() {
    let mut task = StreamingTask::with_defaults(plugin_id(), vec![]);
    task.channel.credit_window = 4;
    task.channel.credit_exhaustion_timeout_ms = 5_000;
    // A 1 s heartbeat: three unanswered Pings would close the stream at 3 s,
    // before the 5 s stall, so "still Active" below is only possible if the
    // heartbeats really were answered.
    task.channel.heartbeat_ms = 1_000;
    let mut sim = Sim::new(&task);

    // Some time into the stream, the executor produces its window's worth.
    sim.advance(sim.t0 + Duration::from_millis(1_250), &no_loss, &no_loss);
    for i in 0..4u8 {
        assert!(matches!(
            sim.exec.try_send_chunk(vec![i; 8], sim.now).unwrap(),
            SendOutcome::Sent { .. }
        ));
    }
    let exhausted_at = sim.now;
    // The next chunk has no credit. The submitter never consumes, so it
    // never issues Credit.
    assert!(matches!(
        sim.exec.try_send_chunk(vec![9; 8], sim.now).unwrap(),
        SendOutcome::Blocked(_)
    ));
    sim.pump(&no_loss, &no_loss);

    // Walk the clock forward in 100 ms steps until the executor stalls.
    let mut stalled_at = None;
    for _ in 0..200 {
        let next = sim.now + Duration::from_millis(100);
        sim.advance(next, &no_loss, &no_loss);
        if matches!(sim.exec.state(), ExecutorState::Stalled { .. }) {
            stalled_at = Some(sim.now);
            break;
        }
        assert_eq!(sim.exec.state(), ExecutorState::Active, "no early stall");
    }
    let stalled_at = stalled_at.expect("the executor must stall");
    assert_within(
        "stall after credit exhaustion",
        stalled_at - exhausted_at,
        Duration::from_secs(5),
        Duration::from_millis(500),
    );

    let (at, event) = sim
        .exec_events
        .iter()
        .find_map(|(at, e)| match e {
            StreamEvent::Stalled(s) => Some((*at, s.clone())),
            _ => None,
        })
        .expect("a StalledEvent was emitted");
    let StalledEvent {
        task_id,
        last_seq,
        bytes_emitted,
        waited,
        ..
    } = event;
    assert_eq!(task_id, task.id);
    assert_eq!(last_seq, Some(3));
    assert_eq!(bytes_emitted, 32);
    assert_within(
        "StalledEvent.waited",
        waited,
        Duration::from_secs(5),
        Duration::from_millis(500),
    );
    assert_within(
        "StalledEvent time",
        at - exhausted_at,
        Duration::from_secs(5),
        Duration::from_millis(500),
    );
    // Heartbeats kept the stream alive throughout: this is a stall, not a loss.
    assert_eq!(sim.sub.state(), SubmitterState::Active);
}

/// ATC-STR-1 in real time, scaled down (400 ms credit timeout), through the
/// async drivers and the real plugin: a consumer that takes nothing stalls
/// the executor; consuming resumes it and the stream completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atc_str_1_stall_and_resume_in_real_time() {
    let plugins = plugins().await;
    let submitter = IdentityKeyPair::generate();
    let executor = IdentityKeyPair::generate();
    let (srv, mut events) = server(&plugins, &executor, &[peer_of(&submitter)]);

    let mut task =
        StreamingTask::with_defaults(plugins.stream_lines.clone(), lines(20, 10).into_bytes());
    task.channel.credit_window = 2;
    task.channel.heartbeat_ms = 100;
    task.channel.credit_exhaustion_timeout_ms = 400;

    let (sub_io, exec_io) = duplex(&submitter, &executor);
    let served = tokio::spawn(async move { srv.handle(exec_io).await });
    let started = Instant::now();
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    handle.finish_input().await.unwrap();

    // Take nothing; wait for the stall.
    let stalled = loop {
        match deadline("StalledEvent", events.recv()).await {
            Some((peer, StreamEvent::Stalled(s))) => {
                assert_eq!(peer, peer_of(&submitter));
                break s;
            }
            Some(_) => continue,
            None => panic!("event channel closed"),
        }
    };
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(400),
        "stalled early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_400),
        "stalled late: {elapsed:?}"
    );
    assert_eq!(stalled.last_seq, Some(1), "two chunks of credit were spent");

    // Now consume: credit flows, the executor resumes, every line arrives.
    let mut got = Vec::new();
    loop {
        match deadline("next chunk", handle.next()).await {
            ChunkPoll::Chunk(c) => got.extend_from_slice(&c.bytes),
            ChunkPoll::Ended(end) => {
                assert_eq!(end.chunks, 20);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(got, lines(20, 10).into_bytes());
    let report = deadline("executor", served).await.unwrap().unwrap();
    assert_eq!(report.outcome, Ok(()));
    assert!(report
        .events
        .iter()
        .any(|e| matches!(e, StreamEvent::Resumed { .. })));
}

// ════════════════════════════════════════════════════════════════════════════
// ATC-STR-2 — three missed pongs close the channel within 15 s ± 2 s
// ════════════════════════════════════════════════════════════════════════════

/// ATC-STR-2: GIVEN an active stream (5 s heartbeat), WHEN the network drops
/// Pong frames for three consecutive 5 s windows, THEN the channel closes
/// with Reason::PeerLost within 15 s ± 2 s — on whichever end loses its
/// pongs.
#[test]
fn atc_str_2_three_missed_pings_close_channel() {
    let task = StreamingTask::with_defaults(plugin_id(), vec![]);
    assert_eq!(task.channel.heartbeat_ms, 5_000, "spec default");
    let tolerance = Duration::from_secs(2);

    // Pongs to the executor are dropped from the start.
    let mut sim = Sim::new_lossy(&task, &no_loss, &is_pong);
    let mut closed_at = None;
    for _ in 0..400 {
        let next = sim.now + Duration::from_millis(100);
        sim.advance(next, &no_loss, &is_pong);
        if matches!(sim.exec.state(), ExecutorState::Closed(_)) {
            closed_at = Some(sim.now);
            break;
        }
    }
    let closed_at = closed_at.expect("the executor must give up on its peer");
    assert_eq!(sim.exec.state(), ExecutorState::Closed(Reason::PeerLost));
    assert_eq!(sim.exec.error(), Some(&StreamError::PeerLost { missed: 3 }));
    assert_within(
        "executor PeerLost",
        closed_at - sim.t0,
        Duration::from_secs(15),
        tolerance,
    );

    // Pongs to the submitter are dropped from the start.
    let mut sim = Sim::new_lossy(&task, &is_pong, &no_loss);
    let mut closed_at = None;
    for _ in 0..400 {
        let next = sim.now + Duration::from_millis(100);
        sim.advance(next, &is_pong, &no_loss);
        if matches!(sim.sub.state(), SubmitterState::Closed(_)) {
            closed_at = Some(sim.now);
            break;
        }
    }
    let closed_at = closed_at.expect("the submitter must give up on its peer");
    assert_eq!(sim.sub.state(), SubmitterState::Closed(Reason::PeerLost));
    assert_within(
        "submitter PeerLost",
        closed_at - sim.t0,
        Duration::from_secs(15),
        tolerance,
    );
    // It told the executor, which closes too.
    assert!(matches!(
        sim.exec.error(),
        Some(StreamError::PeerAborted {
            reason: Reason::PeerLost,
            ..
        })
    ));
}

/// ATC-STR-2 mid-stream: pongs flow for a while, then stop. The channel
/// closes three heartbeat windows after the first ping whose pong was lost.
#[test]
fn atc_str_2_pong_loss_mid_stream_closes_three_windows_later() {
    let task = StreamingTask::with_defaults(plugin_id(), vec![]);
    let mut sim = Sim::new(&task);
    sim.advance(sim.t0 + Duration::from_millis(22_500), &no_loss, &no_loss);
    assert_eq!(sim.exec.state(), ExecutorState::Active);
    let drop_from = sim.now;
    let mut closed_at = None;
    for _ in 0..400 {
        let next = sim.now + Duration::from_millis(100);
        sim.advance(next, &no_loss, &is_pong);
        if matches!(sim.exec.state(), ExecutorState::Closed(_)) {
            closed_at = Some(sim.now);
            break;
        }
    }
    let closed_at = closed_at.expect("closed");
    assert_eq!(sim.exec.state(), ExecutorState::Closed(Reason::PeerLost));
    // First unanswered ping: the next 5 s tick after the drop (t0 + 25 s).
    let first_lost_ping = sim.t0 + Duration::from_secs(25);
    assert_within(
        "PeerLost after the first lost pong",
        closed_at - first_lost_ping,
        Duration::from_secs(15),
        Duration::from_secs(2),
    );
    assert!(closed_at - drop_from < Duration::from_secs(20));
}

/// ATC-STR-2 in real time, scaled down (100 ms heartbeat): an executor that
/// accepts and then never answers a ping is declared lost by the submitter
/// after three heartbeats; a submitter that goes silent is declared lost by
/// the executor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atc_str_2_peer_lost_in_real_time() {
    let submitter = IdentityKeyPair::generate();
    let executor = IdentityKeyPair::generate();
    let mut task = StreamingTask::with_defaults(plugin_id(), vec![]);
    task.channel.heartbeat_ms = 100;

    // Submitter side: a raw executor that accepts, then never pongs.
    let (sub_io, mut raw) = raw_pair(&executor);
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    raw.accept(&executor).await;
    let accepted = Instant::now();
    let silent = tokio::spawn(async move {
        // Read (and ignore) everything, answer nothing.
        while raw.recv_frame(Side::Submitter).await.is_some() {}
    });
    match deadline("PeerLost", handle.next()).await {
        ChunkPoll::Closed(StreamError::PeerLost { missed: 3 }) => {}
        other => panic!("expected PeerLost, got {other:?}"),
    }
    let elapsed = accepted.elapsed();
    assert!(
        elapsed >= Duration::from_millis(300),
        "lost early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_300),
        "lost late: {elapsed:?}"
    );
    drop(handle);
    let _ = silent.await;

    // Executor side: the real server against a submitter that sends Open
    // and then goes silent (it never pongs and never grants credit).
    let plugins = plugins().await;
    let (srv, _events) = server(&plugins, &executor, &[peer_of(&submitter)]);
    let mut task =
        StreamingTask::with_defaults(plugins.stream_lines.clone(), b"a\nb\nc\n".to_vec());
    task.channel.heartbeat_ms = 100;
    let mut sub = SubmitterMachine::new(
        &task,
        pub_of(&executor),
        SubmitterOptions::default(),
        Instant::now(),
    )
    .unwrap();
    let open = sub.poll_transmit().unwrap();
    let (mut sub_io, exec_io) = duplex(&submitter, &executor);
    let started = Instant::now();
    let served = tokio::spawn(async move { srv.handle(exec_io).await });
    send_frame(&mut sub_io, &open).await;
    let reason = error_reason(&mut sub_io, Side::Executor).await;
    assert_eq!(reason, Reason::PeerLost);
    let report = deadline("executor", served).await.unwrap().unwrap();
    assert_eq!(report.outcome, Err(StreamError::PeerLost { missed: 3 }));
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
}

// ════════════════════════════════════════════════════════════════════════════
// ATC-STR-3 — every chunk is signed by the executor; forgeries are refused
// ════════════════════════════════════════════════════════════════════════════

/// ATC-STR-3: GIVEN an executor with NodeId N issuing chunks, WHEN the
/// submitter receives them, THEN each chunk's signature verifies against
/// N's public key, AND a chunk signed by N' ≠ N is rejected with
/// BadChunkSignature and the stream aborts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atc_str_3_forged_chunk_rejected() {
    let submitter = IdentityKeyPair::generate();
    let n = IdentityKeyPair::generate();
    let n_prime = IdentityKeyPair::generate();

    // Honest executor N (the real plugin): every chunk verifies against N.
    let plugins = plugins().await;
    let (srv, _events) = server(&plugins, &n, &[peer_of(&submitter)]);
    let mut task =
        StreamingTask::with_defaults(plugins.stream_lines.clone(), b"one\ntwo\nthree\n".to_vec());
    task.partial_result = PartialResultPolicy::KeepSigned;
    let (sub_io, exec_io) = duplex(&submitter, &n);
    let served = tokio::spawn(async move { srv.handle(exec_io).await });
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    handle.finish_input().await.unwrap();
    let result = deadline("collect", handle.collect()).await;
    assert!(result.is_complete(), "{:?}", result.outcome);
    assert_eq!(result.executor_key, pub_of(&n));
    let verifier = ChunkVerifier::new(
        pub_of(&n),
        *task.id.as_bytes(),
        result.policy_hash,
        result.request_digest,
    );
    let impostor = ChunkVerifier::new(
        pub_of(&n_prime),
        *task.id.as_bytes(),
        result.policy_hash,
        result.request_digest,
    );
    for chunk in &result.chunks {
        let sig = chunk.signature.expect("complete streams keep signatures");
        let h = *blake3::hash(&chunk.bytes).as_bytes();
        verifier
            .verify_chunk(chunk.seq, &h, &sig)
            .expect("each chunk verifies against N's public key");
        assert!(impostor.verify_chunk(chunk.seq, &h, &sig).is_err());
    }
    let signed = result.signed_chunks().unwrap();
    verify_transcript(
        pub_of(&n),
        *task.id.as_bytes(),
        result.policy_hash,
        result.request_digest,
        &signed,
    )
    .unwrap();
    assert_eq!(
        deadline("executor", served).await.unwrap().unwrap().outcome,
        Ok(())
    );

    // A stream whose transport authenticated N, carrying a chunk signed by
    // N': the first (genuine) chunk is delivered, the forgery is rejected
    // and the stream aborts.
    let task = StreamingTask::with_defaults(plugin_id(), vec![]);
    let (sub_io, mut raw) = raw_pair(&n);
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    let (open, genuine) = raw.accept(&n).await;
    let forger = ChunkSigner::new(
        n_prime.clone(),
        open.task_id,
        open.policy_hash,
        request_digest(&open),
    );
    raw.send_frame(&signed_chunk(&genuine, 0, b"real".to_vec()))
        .await;
    raw.send_frame(&signed_chunk(&forger, 1, b"fake".to_vec()))
        .await;
    raw.send_frame(&signed_chunk(&genuine, 2, b"after".to_vec()))
        .await;
    match deadline("genuine chunk", handle.next()).await {
        ChunkPoll::Chunk(c) => assert_eq!(c.bytes, b"real"),
        other => panic!("{other:?}"),
    }
    match deadline("forged chunk", handle.next()).await {
        ChunkPoll::Closed(StreamError::BadChunkSignature {
            seq: 1, executor, ..
        }) => {
            assert_eq!(executor, peer_of(&n).to_hex());
        }
        other => panic!("expected BadChunkSignature, got {other:?}"),
    }
    assert_eq!(
        raw.error_reason(Side::Submitter).await,
        Reason::BadChunkSignature,
        "the stream aborts"
    );
    let report = handle.finish().await;
    assert_eq!(
        report.context.received_chunks, 1,
        "nothing after the forgery is accepted"
    );
}

/// ATC-STR-3: a replayed or reordered chunk — validly signed by N, but with
/// the wrong sequence number — is rejected with BadChunkSignature too.
#[tokio::test]
async fn atc_str_3_replayed_and_reordered_chunks_rejected() {
    let n = IdentityKeyPair::generate();
    for case in ["replay", "reorder"] {
        let task = StreamingTask::with_defaults(plugin_id(), vec![]);
        let (sub_io, mut raw) = raw_pair(&n);
        let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
        let (_open, signer) = raw.accept(&n).await;
        let c0 = signed_chunk(&signer, 0, b"zero".to_vec());
        let c1 = signed_chunk(&signer, 1, b"one".to_vec());
        let expected_seq = match case {
            "replay" => {
                raw.send_frame(&c0).await;
                raw.send_frame(&c0).await;
                0
            }
            _ => {
                raw.send_frame(&c1).await;
                1
            }
        };
        if case == "replay" {
            assert!(matches!(handle.next().await, ChunkPoll::Chunk(c) if c.seq == 0));
        }
        match deadline(case, handle.next()).await {
            ChunkPoll::Closed(StreamError::BadChunkSignature { seq, detail, .. }) => {
                assert_eq!(seq, expected_seq, "{case}");
                let word = if case == "replay" {
                    "replayed"
                } else {
                    "out-of-order"
                };
                assert!(detail.contains(word), "{case}: {detail}");
            }
            other => panic!("{case}: expected BadChunkSignature, got {other:?}"),
        }
        assert_eq!(
            raw.error_reason(Side::Submitter).await,
            Reason::BadChunkSignature
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// The executor gate, clamping, and plugin outcomes (StreamServer over duplex)
// ════════════════════════════════════════════════════════════════════════════

/// An unlisted peer is refused before anything it sends is decoded: it gets
/// NotAuthorized without having sent a single byte.
#[tokio::test]
async fn an_unauthorized_peer_is_refused_before_anything_is_decoded() {
    let plugins = plugins().await;
    let stranger = IdentityKeyPair::generate();
    let executor = IdentityKeyPair::generate();
    let (srv, _events) = server(&plugins, &executor, &[]);
    let (mut sub_io, exec_io) = duplex(&stranger, &executor);
    let served = tokio::spawn(async move { srv.handle(exec_io).await });
    // Nothing sent at all.
    match recv_frame(&mut sub_io, Side::Executor).await {
        Some(Frame::Error { reason, .. }) => assert_eq!(reason, Reason::NotAuthorized),
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert!(
        recv_frame(&mut sub_io, Side::Executor).await.is_none(),
        "then the stream ends"
    );
    assert!(matches!(
        served.await.unwrap(),
        Err(StreamError::PeerAborted {
            reason: Reason::NotAuthorized,
            ..
        })
    ));
    assert!(
        plugins.kernel.list_plugins().len() == 2,
        "nothing was loaded or run"
    );
}

/// Requested limits are clamped to the executor's ceilings and reported in
/// `Accepted`; a one-shot plugin or an unknown plugin is refused.
#[tokio::test]
async fn the_executor_clamps_limits_and_refuses_non_stream_plugins() {
    let plugins = plugins().await;
    let submitter = IdentityKeyPair::generate();
    let executor = IdentityKeyPair::generate();
    let ceilings = StreamCeilings::default();

    let mut greedy = StreamingTask::with_defaults(plugins.stream_lines.clone(), vec![]);
    greedy.channel = ChannelSpec {
        max_chunk_bytes: 16 * 1024 * 1024,
        max_total_bytes: u64::MAX,
        credit_window: u32::MAX,
        heartbeat_ms: u32::MAX,
        credit_exhaustion_timeout_ms: u64::MAX,
    };
    greedy.timeout_ms = u64::MAX;
    let (srv, _events) = server(&plugins, &executor, &[peer_of(&submitter)]);
    let mut sub = SubmitterMachine::new(
        &greedy,
        pub_of(&executor),
        SubmitterOptions::default(),
        Instant::now(),
    )
    .unwrap();
    let (mut sub_io, exec_io) = duplex(&submitter, &executor);
    let served = tokio::spawn(async move { srv.handle(exec_io).await });
    send_frame(&mut sub_io, &sub.poll_transmit().unwrap()).await;
    match recv_frame(&mut sub_io, Side::Executor).await {
        Some(Frame::Accepted(a)) => {
            assert_eq!(a.channel.max_chunk_bytes, ceilings.max_chunk_bytes);
            assert_eq!(a.channel.max_total_bytes, ceilings.max_total_bytes);
            assert_eq!(a.channel.credit_window, ceilings.max_credit_window);
            assert_eq!(a.channel.heartbeat_ms, ceilings.max_heartbeat_ms);
            assert_eq!(
                a.channel.credit_exhaustion_timeout_ms,
                ceilings.max_credit_exhaustion_timeout_ms
            );
            assert_eq!(a.timeout_ms, ceilings.max_timeout_ms);
            assert_eq!(a.input_window, ceilings.input_window);
        }
        other => panic!("expected Accepted, got {other:?}"),
    }
    send_frame(
        &mut sub_io,
        &Frame::Cancel {
            reason: Reason::Cancelled,
        },
    )
    .await;
    let _ = deadline("executor", served).await;

    for (plugin, why) in [
        (plugins.hello_pong.clone(), "is a `plugin` plugin"),
        (
            format!("{}/missing@0.1.0", "0".repeat(32)).parse().unwrap(),
            "not loaded",
        ),
    ] {
        let (srv, _events) = server(&plugins, &executor, &[peer_of(&submitter)]);
        let task = StreamingTask::with_defaults(plugin, vec![]);
        let (sub_io, exec_io) = duplex(&submitter, &executor);
        let served = tokio::spawn(async move { srv.handle(exec_io).await });
        let handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
        let result = deadline("collect", handle.collect()).await;
        match &result.outcome {
            StreamOutcome::Interrupted(StreamError::PeerAborted {
                reason: Reason::PluginNotLoaded,
                message,
                ..
            }) => assert!(message.contains(why), "{message}"),
            other => panic!("expected PluginNotLoaded, got {other:?}"),
        }
        assert!(served.await.unwrap().is_err());
    }
}

/// A plugin that fails mid-stream (here: a non-UTF-8 inbound chunk after
/// two good lines) interrupts the stream; the partial result follows the
/// task's PartialResultPolicy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plugin_failure_mid_stream_honours_the_partial_result_policy() {
    let plugins = plugins().await;
    let submitter = IdentityKeyPair::generate();
    let executor = IdentityKeyPair::generate();
    for (policy, kept, signed) in [
        (PartialResultPolicy::Discard, &b""[..], false),
        (PartialResultPolicy::Keep, &b"a\nb\n"[..], false),
        (PartialResultPolicy::KeepSigned, &b"a\nb\n"[..], true),
    ] {
        let (srv, _events) = server(&plugins, &executor, &[peer_of(&submitter)]);
        let mut task =
            StreamingTask::with_defaults(plugins.stream_lines.clone(), b"a\nb\n".to_vec());
        task.partial_result = policy;
        let (sub_io, exec_io) = duplex(&submitter, &executor);
        let served = tokio::spawn(async move { srv.handle(exec_io).await });
        let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
        handle.send_input(vec![0xff, 0xfe]).await.unwrap();
        let result = deadline("collect", handle.collect()).await;
        match &result.outcome {
            StreamOutcome::Interrupted(StreamError::PeerAborted {
                reason: Reason::PluginFailed,
                message,
                ..
            }) => assert!(message.contains("UTF-8"), "{message}"),
            other => panic!("{policy:?}: expected PluginFailed, got {other:?}"),
        }
        assert_eq!(result.received_bytes, 4, "{policy:?}");
        assert_eq!(result.bytes(), kept, "{policy:?}");
        assert_eq!(
            result.signed_chunks().is_some() && !result.chunks.is_empty(),
            signed
        );
        let report = deadline("executor", served).await.unwrap().unwrap();
        assert!(matches!(report.outcome, Err(StreamError::Plugin(_))));
    }
}

/// Cancelling mid-stream stops the plugin: the executor sends nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_mid_stream_stops_the_plugin() {
    let plugins = plugins().await;
    let submitter = IdentityKeyPair::generate();
    let executor = IdentityKeyPair::generate();
    let (srv, _events) = server(&plugins, &executor, &[peer_of(&submitter)]);
    let mut task =
        StreamingTask::with_defaults(plugins.stream_lines.clone(), lines(500, 8).into_bytes());
    task.channel.credit_window = 2;
    let (sub_io, exec_io) = duplex(&submitter, &executor);
    let served = tokio::spawn(async move { srv.handle(exec_io).await });
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    assert!(matches!(
        deadline("first", handle.next()).await,
        ChunkPoll::Chunk(_)
    ));
    handle.cancel().await;
    let report = deadline("executor", served).await.unwrap().unwrap();
    assert_eq!(
        report.outcome,
        Err(StreamError::Cancelled {
            by: Side::Submitter
        })
    );
    assert!(
        report.chunks_sent < 10,
        "the plugin was stopped: {}",
        report.chunks_sent
    );
    assert!(matches!(
        handle.next().await,
        ChunkPoll::Chunk(_) | ChunkPoll::Closed(StreamError::Cancelled { .. })
    ));
}

/// The executor's stream metrics count a submitter's cancel as
/// `cancelled`, not as a plugin error: the driver refuses the chunk the
/// plugin is blocked on (and closes its input) before it drops the
/// invocation, so the plugin fails first — that failure is the teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_stream_is_counted_as_cancelled_not_as_a_plugin_error() {
    use entangle_observability::catalog::names;
    let registry = entangle_observability::Registry::new();
    let plugins = plugins_with(Some(registry.clone())).await;
    let submitter = IdentityKeyPair::generate();
    let executor = IdentityKeyPair::generate();
    let (srv, _events) = server(&plugins, &executor, &[peer_of(&submitter)]);
    let mut task =
        StreamingTask::with_defaults(plugins.stream_lines.clone(), lines(500, 8).into_bytes());
    task.channel.credit_window = 2;
    let (sub_io, exec_io) = duplex(&submitter, &executor);
    let served = tokio::spawn(async move { srv.handle(exec_io).await });
    let mut handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    assert!(matches!(
        deadline("first", handle.next()).await,
        ChunkPoll::Chunk(_)
    ));
    handle.cancel().await;
    let report = deadline("executor", served).await.unwrap().unwrap();
    assert!(matches!(report.outcome, Err(StreamError::Cancelled { .. })));

    // The invocation ends (or is aborted) as the executor finishes; give the
    // runtime a moment to record it.
    let plugin = plugins.stream_lines.to_string();
    let outcome = |o: &str| {
        registry.value(
            names::PLUGIN_STREAMS,
            &[("plugin", plugin.as_str()), ("outcome", o)],
        )
    };
    let recorded = deadline("the stream's metric", async {
        loop {
            if ["ok", "error", "cancelled"]
                .iter()
                .any(|o| outcome(o).is_some())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    recorded.await;
    let scrape = registry.render();
    assert_eq!(outcome("cancelled"), Some(1.0), "{scrape}");
    assert_eq!(outcome("error"), None, "{scrape}");
    assert!(
        !scrape
            .lines()
            .any(|l| l.starts_with(names::PLUGIN_ERRORS) && l.contains(&plugin)),
        "a cancel is not a plugin error: {scrape}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// End to end over two loopback mesh.iroh nodes
// ════════════════════════════════════════════════════════════════════════════

fn loopback(alpn: &[u8], extra: Vec<Vec<u8>>) -> MeshIrohConfig {
    MeshIrohConfig {
        alpn: alpn.to_vec(),
        extra_alpns: extra,
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        ..MeshIrohConfig::loopback()
    }
}

fn address(transport: &MeshIroh) -> IrohPeer {
    let addr = transport
        .local_addrs()
        .into_iter()
        .find(|a| a.ip().is_loopback())
        .expect("loopback socket");
    IrohPeer::new(transport.local_public_key(), addr)
}

/// The real `stream-lines` component streams across two loopback iroh
/// nodes: chunks arrive in order, verify against the executor's NodeId, the
/// inbound stream reaches the plugin, and the one-shot scheduler protocol
/// keeps working on the same endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_lines_end_to_end_over_two_loopback_iroh_nodes() {
    let plugins = plugins().await;
    let a_key = IdentityKeyPair::generate();
    let b_key = IdentityKeyPair::generate();

    // Node B: one endpoint serving entangle/scheduler/1 and entangle/stream/1.
    let b = Arc::new(
        MeshIroh::start(loopback(ALPN_SCHEDULER, vec![ALPN_STREAM.to_vec()]), &b_key)
            .await
            .unwrap(),
    );
    let allow = || -> StaticAllowlist { [peer_of(&a_key)].into_iter().collect() };
    let (events_tx, _events_rx) = mpsc::unbounded_channel();
    let stream_server = Arc::new(
        StreamServer::new(
            Arc::clone(&plugins.kernel),
            Arc::new(allow()),
            b_key.clone(),
        )
        .with_events(events_tx),
    );
    tokio::spawn(entangle_scheduler::serve_streams(
        Arc::clone(&b),
        stream_server,
    ));
    let task_server = Arc::new(entangle_scheduler::RemoteTaskServer::new(
        Arc::clone(&plugins.kernel),
        Arc::new(allow()),
        peer_of(&b_key),
    ));
    tokio::spawn(entangle_scheduler::serve_tasks(Arc::clone(&b), task_server));

    // Node A: the submitter.
    let a = MeshIroh::start(loopback(ALPN_SCHEDULER, vec![]), &a_key)
        .await
        .unwrap();
    let b_addr = address(&b);

    let mut task = StreamingTask::with_defaults(
        plugins.stream_lines.clone(),
        b"alpha\nbeta\ngamma\n".to_vec(),
    );
    task.integrity = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![peer_of(&b_key)],
    };
    task.partial_result = PartialResultPolicy::KeepSigned;
    let mut handle = deadline(
        "open_stream",
        open_stream(&a, &b_addr, &task, StreamOptions::default()),
    )
    .await
    .expect("stream opens");
    assert_eq!(handle.executor(), peer_of(&b_key));
    handle.send_input(b"delta\nepsilon".to_vec()).await.unwrap();
    handle.finish_input().await.unwrap();

    let mut chunks = Vec::new();
    let end = loop {
        match deadline("next chunk", handle.next()).await {
            ChunkPoll::Chunk(c) => {
                assert_eq!(c.seq, chunks.len() as u64, "in order");
                chunks.push(c);
            }
            ChunkPoll::Ended(end) => break end,
            other => panic!("unexpected {other:?}"),
        }
    };
    let text: Vec<&[u8]> = chunks.iter().map(|c| c.bytes.as_slice()).collect();
    assert_eq!(
        text,
        [
            &b"alpha\n"[..],
            b"beta\n",
            b"gamma\n",
            b"delta\n",
            b"epsilon"
        ]
    );
    assert_eq!(end.chunks, 5);
    let report = handle.finish().await;
    assert!(matches!(report.outcome, StreamOutcome::Complete(_)));
    let signed: Vec<_> = chunks.into_iter().map(Into::into).collect();
    let transcript = verify_transcript(
        b.local_public_key(),
        *task.id.as_bytes(),
        report.context.policy_hash,
        report.context.request_digest,
        &signed,
    )
    .expect("the transcript verifies against node B's public key");
    assert_eq!(transcript, end.transcript);

    // TrustedExecutor naming someone else: refused before dialling B.
    let mut other = task.clone();
    other.id = uuid::Uuid::new_v4();
    other.integrity = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![PeerId::from_public_key_bytes(&[9; 32])],
    };
    assert!(matches!(
        open_stream(&a, &b_addr, &other, StreamOptions::default()).await,
        Err(StreamError::ExecutorNotAllowed { .. })
    ));

    // The one-shot protocol shares B's endpoint.
    let directory = entangle_scheduler::PeerDirectory::new();
    directory.insert(b_addr.clone());
    let scheduler_a = MeshIroh::start(loopback(ALPN_SCHEDULER, vec![]), &a_key)
        .await
        .unwrap();
    let client =
        entangle_scheduler::RemoteDispatch::new(Arc::new(scheduler_a), Arc::new(directory));
    let one_shot = entangle_types::task::OneShotTask::with_defaults(
        plugins.hello_pong.clone(),
        b"mesh".to_vec(),
    );
    let out = deadline("one-shot", client.dispatch(&one_shot, peer_of(&b_key)))
        .await
        .expect("one-shot dispatch on the shared endpoint");
    assert_eq!(out, b"Hello, mesh!");

    a.shutdown().await;
    b.shutdown().await;
}

/// A stream that ends before the plugin returns (cancel, PeerLost, a size
/// cap) drops the `invoke_stream` future, which must still publish `Idled`
/// for the `Activated` it published, or lifecycle subscribers see the plugin
/// as active forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_aborted_stream_still_publishes_idled() {
    use entangle_runtime::LifecyclePhase;

    let plugins = plugins().await;
    let mut sub = plugins.kernel.bus().subscribe();
    // Keep the driver end alive so the guest parks in `next-chunk` instead
    // of seeing its input close and returning.
    let (port, _driver) = entangle_host::stream_port(1);
    let kernel = plugins.kernel.clone();
    let id = plugins.stream_lines.clone();
    let run = tokio::spawn(async move {
        kernel
            .invoke_stream(&id, b"", port, 30_000)
            .await
            .map(|_| ())
    });

    let activated = tokio::time::timeout(TEST_DEADLINE, sub.recv())
        .await
        .expect("Activated in time")
        .expect("recv");
    assert_eq!(activated.payload.phase, LifecyclePhase::Activated);
    // The stream ends early: the executor driver drops the plugin future.
    tokio::time::sleep(Duration::from_millis(200)).await;
    run.abort();
    let _ = run.await;

    let idled = tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .expect("Idled must follow an aborted stream")
        .expect("recv");
    assert_eq!(idled.payload.phase, LifecyclePhase::Idled);
}
