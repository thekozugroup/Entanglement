//! Failure handling (spec §7.6): retries after a worker crash or a lost
//! peer, never onto a replica holder, and speculative backup copies of
//! stragglers — against real `RemoteTaskServer`s behind real capability
//! gates, reached through an in-process link that can make each worker
//! misbehave deterministically.
//!
//! Every worker runs a real kernel with a real plugin. Each one's
//! `RemoteTaskServer` requires a capability token rooted at its own
//! identity, so a retry or a backup copy that reaches a worker and runs has,
//! by construction, presented a fresh valid token.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use entangle_mesh_iroh::IrohPeer;
use entangle_observability::catalog::names;
use entangle_observability::Registry;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::capability::{CapabilityGate, HeldToken, StaticTokens};
use entangle_scheduler::transport::{DialTarget, Link, LinkError, Outbound, StreamIo};
use entangle_scheduler::wire::{
    decode_request, decode_response, ControlAction, RemoteErrorCode, RemoteOutcome,
    RemoteTaskResponse, RequestFrame,
};
use entangle_scheduler::{
    AttemptKind, AttemptOutcome, DispatchError, Dispatcher, RemoteDispatch, RemoteTaskServer,
    RetryCause, SpeculationConfig, StaticAllowlist, TransportKind, TransportRouter, WorkerInfo,
    WorkerPool,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{IntegrityPolicy, OneShotTask, RetryPolicy};
use parking_lot::Mutex;

const TEST_DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(TEST_DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {TEST_DEADLINE:?}"),
    }
}

const HELLO_PONG_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../entangle-host/tests/fixtures/hello-pong.wasm"
);
/// `spin:<ms>` busy-loops for that long, then echoes.
const STRESS_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../entangle-host/tests/fixtures/stress.wasm"
);

fn keyring_for(publisher: &IdentityKeyPair) -> Keyring {
    let key = publisher.public();
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: key.fingerprint(),
        public_key: *key.as_bytes(),
        publisher_name: "test-publisher".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

/// A kernel with `wasm` loaded as `<publisher>/demo@0.1.0`. Two kernels
/// loading different components under the same id model two workers that
/// run the same task at very different speeds.
async fn kernel_with(
    publisher: &IdentityKeyPair,
    wasm: &str,
) -> (Arc<Kernel>, PluginId, tempfile::TempDir) {
    kernel_with_manifest(publisher, wasm, "").await
}

/// [`kernel_with`], with `extra` lines in the manifest's `[plugin]` table.
async fn kernel_with_manifest(
    publisher: &IdentityKeyPair,
    wasm: &str,
    extra: &str,
) -> (Arc<Kernel>, PluginId, tempfile::TempDir) {
    let kernel =
        Arc::new(Kernel::new(KernelConfig::default(), keyring_for(publisher)).expect("kernel"));
    let dir = tempfile::tempdir().expect("tempdir");
    let id = format!("{}/demo@0.1.0", publisher.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\ndescription = \"failure-handling test plugin\"\n{extra}\n"
    );
    let bytes = std::fs::read(wasm).expect("fixture");
    std::fs::write(dir.path().join("entangle.toml"), manifest.as_bytes()).unwrap();
    std::fs::write(dir.path().join("plugin.wasm"), &bytes).unwrap();
    let bundle = sign_artifact(&bytes, manifest.as_bytes(), publisher);
    std::fs::write(
        dir.path().join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    kernel.load_plugin_from_dir(dir.path()).await.expect("load");
    (kernel, id.parse().unwrap(), dir)
}

/// How a worker treats the next request it gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    /// Answers normally.
    Normal,
    /// Takes the frame (it was sent) and then the connection dies: a worker
    /// crash mid-task. Behaves normally afterwards.
    CrashOnce,
    /// Takes the frame and the connection dies, every time.
    CrashAlways,
    /// Cannot be connected to.
    Unreachable,
    /// Holds the frame this long before handing it to the worker.
    Late(Duration),
}

struct Worker {
    key: [u8; 32],
    server: Arc<RemoteTaskServer>,
}

/// One link reaching every worker by peer id, as the submitter `from`.
struct Workers {
    from: PeerId,
    workers: HashMap<PeerId, Worker>,
    behaviour: Mutex<HashMap<PeerId, Behaviour>>,
    /// Every frame delivered (or taken) per worker: `("task", task id)` or
    /// `("cancel", task id)`.
    log: Mutex<Vec<(PeerId, &'static str, [u8; 16])>>,
}

impl std::fmt::Debug for Workers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Workers")
    }
}

impl Workers {
    fn set(&self, peer: PeerId, b: Behaviour) {
        self.behaviour.lock().insert(peer, b);
    }

    fn frames_to(&self, peer: PeerId, kind: &str) -> usize {
        self.log
            .lock()
            .iter()
            .filter(|(p, k, _)| *p == peer && *k == kind)
            .count()
    }
}

#[async_trait::async_trait]
impl Link for Workers {
    fn kind(&self) -> TransportKind {
        TransportKind::Iroh
    }
    fn target(&self, peer: &PeerId) -> Option<DialTarget> {
        let w = self.workers.get(peer)?;
        Some(DialTarget::Iroh(IrohPeer::new(
            w.key,
            "127.0.0.1:9".parse().ok()?,
        )))
    }
    async fn request(
        &self,
        target: &DialTarget,
        outbound: &Outbound<'_>,
    ) -> Result<Vec<u8>, LinkError> {
        let peer = target.peer_id();
        let behaviour = *self
            .behaviour
            .lock()
            .get(&peer)
            .unwrap_or(&Behaviour::Normal);
        if behaviour == Behaviour::Unreachable {
            return Err(LinkError::Connect("connection refused".into()));
        }
        let frame = outbound.frame();
        let (kind, id) = match decode_request(&frame).map(|r| r.frame) {
            Ok(RequestFrame::Task(t)) => ("task", t.task_id),
            Ok(RequestFrame::Control(c)) => match c.action {
                ControlAction::Cancel => ("cancel", c.task_id),
                _ => ("control", c.task_id),
            },
            Err(_) => ("garbage", [0; 16]),
        };
        self.log.lock().push((peer, kind, id));
        match behaviour {
            Behaviour::CrashOnce if kind == "task" => {
                self.set(peer, Behaviour::Normal);
                return Err(LinkError::Transport(
                    "connection lost: worker crashed".into(),
                ));
            }
            Behaviour::CrashAlways if kind == "task" => {
                return Err(LinkError::Transport(
                    "connection lost: worker crashed".into(),
                ));
            }
            Behaviour::Late(d) if kind == "task" => tokio::time::sleep(d).await,
            _ => {}
        }
        let worker = self.workers.get(&peer).expect("known worker");
        // The worker runs the frame on its own task, as a remote node would:
        // a submitter that drops its request (a cancelled copy) does not
        // stop the worker — only a `Cancel` frame does.
        let server = Arc::clone(&worker.server);
        let from = self.from;
        let answer =
            tokio::spawn(async move { server.handle_via(from, frame, TransportKind::Iroh).await })
                .await
                .map_err(|e| LinkError::Transport(format!("worker task failed: {e}")))?;
        if kind == "cancel" {
            if let Ok(RemoteTaskResponse {
                outcome: RemoteOutcome::Ack { .. },
                ..
            }) = decode_response(&answer, 0)
            {
                self.log.lock().push((peer, "cancel-ack", id));
            }
        }
        Ok(answer)
    }
    async fn open_stream(&self, _target: &DialTarget) -> Result<StreamIo, LinkError> {
        Err(LinkError::Connect("no streams here".into()))
    }
}

/// A cluster: a submitter and named workers, each with its own identity,
/// gate and kernel, and a dispatcher whose pool ranks them in `ranks` order
/// (first = best).
struct Cluster {
    submitter: PeerId,
    peers: Vec<PeerId>,
    workers: Arc<Workers>,
    servers: Vec<Arc<RemoteTaskServer>>,
    plugin: PluginId,
    registry: Registry,
    _dirs: Vec<tempfile::TempDir>,
    submitter_kernel: Arc<Kernel>,
}

impl Cluster {
    /// The dispatcher: every worker in the pool, worker `i` advertising a
    /// load of `i / 10` so placement ranks them in order; tokens for every
    /// worker; the given speculation.
    fn dispatcher(&self, tokens: &StaticTokens, speculation: SpeculationConfig) -> Dispatcher {
        let pool = WorkerPool::new();
        for (i, peer) in self.peers.iter().enumerate() {
            pool.upsert(WorkerInfo {
                peer_id: *peer,
                display_name: format!("worker-{i}"),
                cpu_cores: 16.0,
                memory_bytes: 64 << 30,
                gpu: None,
                npu: None,
                network_bandwidth_bps: 1_000_000_000,
                rtt_ms: 1,
                load: i as f32 / 10.0,
                cost: 1.0,
            });
        }
        let router = TransportRouter::new(self.submitter)
            .with_link(Arc::clone(&self.workers) as Arc<dyn Link>)
            .with_capability_tokens(Arc::new(tokens.clone()));
        Dispatcher::new(pool, Arc::clone(&self.submitter_kernel), self.submitter)
            .with_strict_remote(true)
            .with_remote(Arc::new(RemoteDispatch::with_router(Arc::new(router))))
            .with_metrics(self.registry.clone())
            .with_speculation(speculation)
    }

    fn task(&self, input: &[u8], integrity: IntegrityPolicy) -> OneShotTask {
        let mut task = OneShotTask::with_defaults(self.plugin.clone(), input.to_vec());
        task.integrity = integrity;
        task.timeout_ms = 10_000;
        task.retry = RetryPolicy {
            max_attempts: 3,
            backoff_ms: 10,
            max_backoff_ms: 50,
        };
        task
    }

    fn retries(&self, cause: &str) -> f64 {
        self.registry
            .value(
                names::SCHEDULER_RETRIES,
                &[("kind", "one_shot"), ("cause", cause)],
            )
            .unwrap_or(0.0)
    }

    fn speculative(&self, event: &str) -> f64 {
        self.registry
            .value(names::SCHEDULER_SPECULATIVE, &[("event", event)])
            .unwrap_or(0.0)
    }
}

/// The tokens pairing leaves the submitter holding: one per worker, minted
/// by that worker's identity. Rebuilt from the servers' gates' keys.
fn tokens_for(c: &Cluster, identities: &[IdentityKeyPair]) -> StaticTokens {
    let tokens = StaticTokens::new();
    for (peer, id) in c.peers.iter().zip(identities) {
        tokens.insert(*peer, HeldToken::minted(id, c.submitter).expect("mint"));
    }
    tokens
}

/// Workers running the given fixtures (all as the same plugin id), and the
/// tokens pairing would leave the submitter holding for them.
async fn cluster_with_tokens(fixtures: &[&str]) -> (Cluster, StaticTokens) {
    let publisher = IdentityKeyPair::generate();
    let submitter_key = IdentityKeyPair::generate();
    let submitter = PeerId::from_public_key_bytes(submitter_key.public().as_bytes());
    let mut identities = Vec::new();
    let mut workers = HashMap::new();
    let mut peers = Vec::new();
    let mut servers = Vec::new();
    let mut dirs = Vec::new();
    let mut plugin = None;
    for wasm in fixtures {
        let identity = IdentityKeyPair::generate();
        let key = *identity.public().as_bytes();
        let peer = PeerId::from_public_key_bytes(&key);
        let (kernel, id, dir) = kernel_with(&publisher, wasm).await;
        plugin.get_or_insert(id);
        dirs.push(dir);
        let server = Arc::new(RemoteTaskServer::new(
            kernel,
            Arc::new(StaticAllowlist::new().allow(submitter)),
            Arc::new(CapabilityGate::for_identity(&identity).expect("gate")),
        ));
        workers.insert(
            peer,
            Worker {
                key,
                server: Arc::clone(&server),
            },
        );
        peers.push(peer);
        servers.push(server);
        identities.push(identity);
    }
    let c = Cluster {
        submitter,
        peers,
        workers: Arc::new(Workers {
            from: submitter,
            workers,
            behaviour: Mutex::new(HashMap::new()),
            log: Mutex::new(Vec::new()),
        }),
        servers,
        plugin: plugin.expect("at least one worker"),
        registry: Registry::new(),
        _dirs: dirs,
        submitter_kernel: Arc::new(
            Kernel::new(KernelConfig::default(), keyring_for(&publisher)).expect("kernel"),
        ),
    };
    let tokens = tokens_for(&c, &identities);
    (c, tokens)
}

// ═════════════════════════════════════════════════════════════════════════
// Retry
// ═════════════════════════════════════════════════════════════════════════

/// A worker that crashes after the request was sent: the task is retried on
/// another worker — with a fresh task id and a fresh capability token (the
/// worker's gate admitted it) — and its output returned. Both attempts are
/// in the result and the retry is counted.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_crash_mid_task_is_retried_on_another_worker() {
    let (c, tokens) = cluster_with_tokens(&[HELLO_PONG_WASM, HELLO_PONG_WASM]).await;
    let (a, b) = (c.peers[0], c.peers[1]);
    c.workers.set(a, Behaviour::CrashAlways);
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);
    let task = c.task(b"world", IntegrityPolicy::None);
    let original = task.id;

    let result = deadline("dispatch", d.dispatch_one_shot(task))
        .await
        .expect("the retry on the healthy worker must succeed");
    assert_eq!(result.output, b"Hello, world!");
    assert_eq!(result.chosen.peer_id, b, "the healthy worker produced it");
    assert!(
        result.chosen.reason.contains("failed over"),
        "{}",
        result.chosen.reason
    );

    assert_eq!(result.attempts.len(), 2, "{:?}", result.attempts);
    let (first, retry) = (&result.attempts[0], &result.attempts[1]);
    assert_eq!((first.peer, first.kind), (a, AttemptKind::First));
    assert_eq!(first.task_id, original);
    assert!(
        matches!(&first.outcome, AttemptOutcome::Failed(why) if why.contains("ENTANGLE-E0432")),
        "{:?}",
        first.outcome
    );
    assert_eq!(retry.peer, b);
    assert_eq!(retry.kind, AttemptKind::Retry(RetryCause::LostAfterSend));
    assert_eq!(retry.outcome, AttemptOutcome::Used);
    assert_ne!(retry.task_id, original, "a retry is a new request");
    assert_eq!(c.retries("lost_after_send"), 1.0);
    assert_eq!(c.workers.frames_to(a, "task"), 1);
    assert_eq!(c.workers.frames_to(b, "task"), 1);
}

/// With no other eligible worker, a single-replica task lost after send
/// goes back to the same worker (it may have restarted).
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_with_no_other_worker_retries_the_same_worker() {
    let (c, tokens) = cluster_with_tokens(&[HELLO_PONG_WASM]).await;
    let a = c.peers[0];
    c.workers.set(a, Behaviour::CrashOnce);
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);
    let result = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(b"again", IntegrityPolicy::None)),
    )
    .await
    .expect("the restarted worker answers the retry");
    assert_eq!(result.output, b"Hello, again!");
    assert_eq!(result.attempts.len(), 2);
    assert!(result.attempts.iter().all(|x| x.peer == a));
    assert_eq!(c.workers.frames_to(a, "task"), 2);
}

/// An unreachable worker (nothing delivered) fails over to another; an
/// unreachable worker with no alternative is not dialled again.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_worker_fails_over_but_is_never_retried_in_place() {
    let (c, tokens) = cluster_with_tokens(&[HELLO_PONG_WASM, HELLO_PONG_WASM]).await;
    let (a, b) = (c.peers[0], c.peers[1]);
    c.workers.set(a, Behaviour::Unreachable);
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);
    let ok = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(b"x", IntegrityPolicy::None)),
    )
    .await
    .expect("fails over");
    assert_eq!(ok.chosen.peer_id, b);
    assert_eq!(
        ok.attempts[1].kind,
        AttemptKind::Retry(RetryCause::Unreachable)
    );
    assert_eq!(c.retries("unreachable"), 1.0);

    // Only the unreachable worker left eligible: one attempt, no retry.
    c.workers.set(b, Behaviour::Unreachable);
    let err = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(
            b"y",
            IntegrityPolicy::TrustedExecutor { allowlist: vec![a] },
        )),
    )
    .await
    .expect_err("nothing reachable");
    assert!(
        matches!(err, DispatchError::RemoteTransport { .. }),
        "{err:?}"
    );
    assert_eq!(c.retries("unreachable"), 1.0, "not retried in place");
}

/// What the task itself caused is never retried: a plugin error (here: the
/// plugin is not loaded), a capability-token refusal, and a timeout.
#[tokio::test(flavor = "multi_thread")]
async fn plugin_errors_token_refusals_and_timeouts_are_not_retried() {
    let (c, tokens) = cluster_with_tokens(&[HELLO_PONG_WASM, HELLO_PONG_WASM]).await;
    let (a, b) = (c.peers[0], c.peers[1]);
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);

    // Plugin not loaded on the chosen worker: an answer, final.
    let mut task = c.task(b"x", IntegrityPolicy::None);
    task.plugin = format!("{}/missing@0.1.0", c.plugin.publisher)
        .parse()
        .unwrap();
    let err = deadline("dispatch", d.dispatch_one_shot(task))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            DispatchError::RemoteRejected {
                code: RemoteErrorCode::PluginNotLoaded,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(c.workers.frames_to(b, "task"), 0, "not retried elsewhere");

    // No token for the chosen worker: refused before any work, final.
    let partial = StaticTokens::new();
    let d2 = c.dispatcher(&partial, SpeculationConfig::Off);
    let err = deadline(
        "dispatch",
        d2.dispatch_one_shot(c.task(b"x", IntegrityPolicy::None)),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            DispatchError::RemoteRejected {
                code: RemoteErrorCode::CapabilityRequired,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(c.workers.frames_to(b, "task"), 0);

    // The task's own timeout: the worker does not answer within the
    // request budget. Final, even with a healthy worker available.
    c.workers.set(a, Behaviour::Late(Duration::from_secs(3)));
    let router = TransportRouter::new(c.submitter)
        .with_link(Arc::clone(&c.workers) as Arc<dyn Link>)
        .with_capability_tokens(Arc::new(tokens.clone()));
    let d3 = c
        .dispatcher(&tokens, SpeculationConfig::Off)
        .with_remote(Arc::new(
            RemoteDispatch::with_router(Arc::new(router)).with_overhead(Duration::from_millis(50)),
        ));
    let mut task = c.task(b"slow", IntegrityPolicy::None);
    task.timeout_ms = 200;
    let err = deadline("dispatch", d3.dispatch_one_shot(task))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DispatchError::RemoteTransport { reason, .. } if reason.contains("no answer within")),
        "{err:?}"
    );
    assert_eq!(
        c.workers.frames_to(b, "task"),
        0,
        "a timeout is not retried"
    );
    assert_eq!(c.retries("lost_after_send") + c.retries("unreachable"), 0.0);
}

/// The retry budget is bounded by the task's deadline: a backoff longer
/// than the time left means no retry.
#[tokio::test(flavor = "multi_thread")]
async fn no_retry_starts_after_the_task_deadline() {
    let (c, tokens) = cluster_with_tokens(&[HELLO_PONG_WASM, HELLO_PONG_WASM]).await;
    let a = c.peers[0];
    c.workers.set(a, Behaviour::CrashAlways);
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);
    let mut task = c.task(b"x", IntegrityPolicy::None);
    task.timeout_ms = 150;
    task.retry = RetryPolicy {
        max_attempts: 5,
        backoff_ms: 5_000,
        max_backoff_ms: 5_000,
    };
    let started = Instant::now();
    let err = deadline("dispatch", d.dispatch_one_shot(task))
        .await
        .unwrap_err();
    assert!(
        matches!(err, DispatchError::RemoteTransport { .. }),
        "{err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(c.workers.frames_to(c.peers[1], "task"), 0);

    // And `max_attempts = 1` never retries.
    let mut task = c.task(b"x", IntegrityPolicy::None);
    task.retry = RetryPolicy::never();
    let err = deadline("dispatch", d.dispatch_one_shot(task))
        .await
        .unwrap_err();
    assert!(
        matches!(err, DispatchError::RemoteTransport { .. }),
        "{err:?}"
    );
    assert_eq!(c.workers.frames_to(c.peers[1], "task"), 0);
}

/// A replicated task: the crashed replica is retried on a worker that
/// holds no replica of the task — never on the worker running the other
/// replica — and the result has exactly as many replicas as asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_replica_retry_never_goes_to_a_worker_holding_a_replica() {
    let (c, tokens) =
        cluster_with_tokens(&[HELLO_PONG_WASM, HELLO_PONG_WASM, HELLO_PONG_WASM]).await;
    let (a, b, z) = (c.peers[0], c.peers[1], c.peers[2]);
    c.workers.set(a, Behaviour::CrashAlways);
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);
    let result = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(b"vote", IntegrityPolicy::Deterministic { replicas: 2 })),
    )
    .await
    .expect("two agreeing replicas");
    assert_eq!(result.output, b"Hello, vote!");
    assert_eq!(result.replicas.len(), 2, "no vote added");
    let peers: Vec<PeerId> = result.replicas.iter().map(|r| r.peer).collect();
    assert!(peers.contains(&b) && peers.contains(&z), "{peers:?}");
    assert_eq!(
        c.workers.frames_to(b, "task"),
        1,
        "b ran exactly its own replica"
    );
    assert_eq!(c.workers.frames_to(z, "task"), 1);
    let retry = result
        .attempts
        .iter()
        .find(|x| matches!(x.kind, AttemptKind::Retry(_)))
        .expect("a retry");
    assert_eq!(retry.peer, z);

    // With no worker free of a replica, the crashed replica is not retried
    // at all: the quorum then fails on the missing replica.
    let (c, tokens) = cluster_with_tokens(&[HELLO_PONG_WASM, HELLO_PONG_WASM]).await;
    let (a, b) = (c.peers[0], c.peers[1]);
    c.workers.set(a, Behaviour::CrashAlways);
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);
    let err = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(b"vote", IntegrityPolicy::Deterministic { replicas: 2 })),
    )
    .await
    .expect_err("one replica cannot make a quorum of two");
    assert!(err.to_string().contains("ENTANGLE-E0402"), "{err}");
    assert_eq!(
        c.workers.frames_to(b, "task"),
        1,
        "b was never given a second replica"
    );
    assert_eq!(
        c.workers.frames_to(a, "task"),
        1,
        "a replicated retry never returns to a"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Speculative execution
// ═════════════════════════════════════════════════════════════════════════

/// The best-ranked worker runs the task slowly (a real 6 s busy loop); past
/// the threshold a backup starts on the next worker, which answers first;
/// its result wins and the slow copy is cancelled: its request is dropped
/// and a `Cancel` control frame reaches the slow worker, which acknowledges
/// it (the task was still executing there) and frees its slot.
///
/// (A wasm one-shot guest that computes without host calls is stopped at
/// its next await point — here the end of its busy loop: the one-shot host
/// path does not yield at epoch ticks. The submitter does not wait for it.)
#[tokio::test(flavor = "multi_thread")]
async fn a_straggler_gets_a_backup_and_the_first_valid_result_wins() {
    let (c, tokens) = cluster_with_tokens(&[STRESS_WASM, HELLO_PONG_WASM]).await;
    let (slow, fast) = (c.peers[0], c.peers[1]);
    let d = c.dispatcher(
        &tokens,
        SpeculationConfig::After(Duration::from_millis(200)),
    );
    let started = Instant::now();
    let result = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(b"spin:6000", IntegrityPolicy::None)),
    )
    .await
    .expect("the backup answers");
    let took = started.elapsed();
    assert_eq!(
        result.output, b"Hello, spin:6000!",
        "the fast worker's answer"
    );
    assert_eq!(result.chosen.peer_id, fast);
    assert!(took < Duration::from_millis(5_000), "{took:?}");
    assert!(took >= Duration::from_millis(200), "{took:?}");

    assert_eq!(result.attempts.len(), 2);
    assert_eq!(result.attempts[0].peer, slow);
    assert_eq!(result.attempts[0].outcome, AttemptOutcome::Cancelled);
    assert_eq!(result.attempts[1].kind, AttemptKind::Speculative);
    assert_eq!(result.attempts[1].outcome, AttemptOutcome::Used);
    assert_eq!(c.speculative("launched"), 1.0);
    assert_eq!(c.speculative("won"), 1.0);
    assert_eq!(c.speculative("cancelled"), 1.0);

    // The slow worker got the Cancel frame while it still ran the task,
    // acknowledged it, and freed the task's slot.
    deadline("cancel reaches the slow worker", async {
        loop {
            if c.workers.frames_to(slow, "cancel-ack") == 1 && c.servers[0].in_flight_len() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(c.workers.frames_to(slow, "cancel"), 1);
    assert_eq!(
        c.workers.frames_to(fast, "cancel"),
        0,
        "the winner is not cancelled"
    );
}

/// A fast first attempt never gets a backup; with speculation off a slow
/// one never does either.
#[tokio::test(flavor = "multi_thread")]
async fn no_backup_below_the_threshold_or_with_speculation_off() {
    let (c, tokens) = cluster_with_tokens(&[HELLO_PONG_WASM, HELLO_PONG_WASM]).await;
    let d = c.dispatcher(&tokens, SpeculationConfig::After(Duration::from_secs(5)));
    let r = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(b"q", IntegrityPolicy::None)),
    )
    .await
    .unwrap();
    assert_eq!(r.attempts.len(), 1);
    assert_eq!(c.speculative("launched"), 0.0);
    assert!(
        d.durations().median(&c.plugin, 1).is_some(),
        "a successful attempt's duration is recorded for the median threshold"
    );

    c.workers
        .set(c.peers[0], Behaviour::Late(Duration::from_millis(400)));
    let off = c.dispatcher(&tokens, SpeculationConfig::Off);
    let r = deadline(
        "dispatch",
        off.dispatch_one_shot(c.task(b"q", IntegrityPolicy::None)),
    )
    .await
    .unwrap();
    assert_eq!(r.attempts.len(), 1);
    assert_eq!(c.workers.frames_to(c.peers[1], "task"), 0);
}

/// Replicated: the slow replica's backup goes to a worker holding no
/// replica — never the one running the other replica — and replaces the
/// slow replica instead of adding a vote.
#[tokio::test(flavor = "multi_thread")]
async fn a_replica_backup_replaces_the_slow_replica_on_a_distinct_worker() {
    let (c, tokens) = cluster_with_tokens(&[STRESS_WASM, HELLO_PONG_WASM, HELLO_PONG_WASM]).await;
    let (slow, b, z) = (c.peers[0], c.peers[1], c.peers[2]);
    let d = c.dispatcher(
        &tokens,
        SpeculationConfig::After(Duration::from_millis(200)),
    );
    let result = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(b"spin:3000", IntegrityPolicy::Deterministic { replicas: 2 })),
    )
    .await
    .expect("b and the backup on z agree");
    assert_eq!(result.output, b"Hello, spin:3000!");
    assert_eq!(result.replicas.len(), 2, "a backup never adds a vote");
    let peers: Vec<PeerId> = result.replicas.iter().map(|r| r.peer).collect();
    assert_eq!(peers, vec![z, b], "slot 0 moved from the slow worker to z");
    assert_eq!(
        c.workers.frames_to(b, "task"),
        1,
        "no backup on the other replica's worker"
    );
    let backup = result
        .attempts
        .iter()
        .find(|x| x.kind == AttemptKind::Speculative)
        .expect("a backup");
    assert_eq!((backup.replica, backup.peer), (0, z));
    assert!(result
        .attempts
        .iter()
        .any(|x| x.peer == slow && x.outcome == AttemptOutcome::Cancelled));
}

// ═════════════════════════════════════════════════════════════════════════
// TrustedExecutor: the executed component is recorded with the result
// ═════════════════════════════════════════════════════════════════════════

/// A `TrustedExecutor` task asks its executor which component it ran and
/// records the digest — the BLAKE3 of the artifact the worker loaded — in
/// the dispatch result (spec §7.5); a task under another policy does not
/// ask remote executors.
#[tokio::test(flavor = "multi_thread")]
async fn a_trusted_executor_result_records_the_executed_component() {
    let (c, tokens) = cluster_with_tokens(&[HELLO_PONG_WASM]).await;
    let a = c.peers[0];
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);
    let expected = *blake3::hash(&std::fs::read(HELLO_PONG_WASM).unwrap()).as_bytes();

    let trusted = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(
            b"audit",
            IntegrityPolicy::TrustedExecutor { allowlist: vec![a] },
        )),
    )
    .await
    .expect("the trusted executor runs it");
    assert_eq!(trusted.output, b"Hello, audit!");
    assert_eq!(trusted.executed_component, Some(expected));
    assert_eq!(trusted.replicas[0].component, Some(expected));

    let plain = deadline(
        "dispatch",
        d.dispatch_one_shot(c.task(b"x", IntegrityPolicy::None)),
    )
    .await
    .unwrap();
    assert_eq!(
        plain.executed_component, None,
        "not asked outside TrustedExecutor"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// §7.5: Deterministic is rejected at submit for a nondeterministic plugin
// ═════════════════════════════════════════════════════════════════════════

/// A plugin whose manifest declares `pure = false` cannot be dispatched as
/// `Deterministic`: the submitter that has it refuses before placing
/// anything (`ENTANGLE-E0470`, suggesting `SemanticEquivalent`); an
/// executor that has it refuses a submitter that does not, before running
/// it — and that refusal is not retried. Other policies still run.
#[tokio::test(flavor = "multi_thread")]
async fn deterministic_is_refused_for_a_plugin_that_declares_nondeterminism() {
    let publisher = IdentityKeyPair::generate();
    // The submitter's own kernel has the plugin: refused at submit.
    let (kernel, plugin, _dir) =
        kernel_with_manifest(&publisher, HELLO_PONG_WASM, "pure = false").await;
    let me = PeerId::from_public_key_bytes(&[42; 32]);
    let local = Dispatcher::new(WorkerPool::new(), Arc::clone(&kernel), me);
    let mut task = OneShotTask::with_defaults(plugin.clone(), b"x".to_vec());
    task.integrity = IntegrityPolicy::Deterministic { replicas: 3 };
    let err = deadline("dispatch", local.dispatch_one_shot(task.clone()))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(matches!(err, DispatchError::Submit(_)), "{err:?}");
    assert!(text.starts_with("ENTANGLE-E0470"), "{text}");
    assert!(
        text.contains("pure = false") && text.contains("SemanticEquivalent"),
        "{text}"
    );
    task.integrity = IntegrityPolicy::None;
    let ok = deadline("dispatch", local.dispatch_one_shot(task))
        .await
        .unwrap();
    assert_eq!(ok.output, b"Hello, x!");
    assert_eq!(
        ok.executed_component,
        Some(*blake3::hash(&std::fs::read(HELLO_PONG_WASM).unwrap()).as_bytes()),
        "a local run records this node's own artifact digest"
    );

    // Only the executors have it (declaring a clock): they refuse.
    let (c, tokens) = cluster_with_declared(&publisher, "nondeterministic = [\"clock\"]").await;
    let d = c.dispatcher(&tokens, SpeculationConfig::Off);
    let mut task = c.task(b"x", IntegrityPolicy::Deterministic { replicas: 1 });
    task.plugin = c.plugin.clone();
    let err = deadline("dispatch", d.dispatch_one_shot(task))
        .await
        .unwrap_err();
    match &err {
        DispatchError::RemoteRejected { code, message, .. } => {
            assert_eq!(*code, RemoteErrorCode::Nondeterministic);
            assert!(message.contains("ENTANGLE-E0470"), "{message}");
        }
        other => panic!("expected the executor's refusal, got {other:?}"),
    }
    assert_eq!(
        c.workers.frames_to(c.peers[1], "task"),
        0,
        "not retried elsewhere"
    );
}

/// Two workers whose plugin manifest carries `extra`.
async fn cluster_with_declared(
    publisher: &IdentityKeyPair,
    extra: &str,
) -> (Cluster, StaticTokens) {
    let submitter = PeerId::from_public_key_bytes(&[43; 32]);
    let mut identities = Vec::new();
    let mut workers = HashMap::new();
    let mut peers = Vec::new();
    let mut servers = Vec::new();
    let mut dirs = Vec::new();
    let mut plugin = None;
    for _ in 0..2 {
        let identity = IdentityKeyPair::generate();
        let key = *identity.public().as_bytes();
        let peer = PeerId::from_public_key_bytes(&key);
        let (kernel, id, dir) = kernel_with_manifest(publisher, HELLO_PONG_WASM, extra).await;
        plugin.get_or_insert(id);
        dirs.push(dir);
        let server = Arc::new(RemoteTaskServer::new(
            kernel,
            Arc::new(StaticAllowlist::new().allow(submitter)),
            Arc::new(CapabilityGate::for_identity(&identity).expect("gate")),
        ));
        workers.insert(
            peer,
            Worker {
                key,
                server: Arc::clone(&server),
            },
        );
        peers.push(peer);
        servers.push(server);
        identities.push(identity);
    }
    let c = Cluster {
        submitter,
        peers,
        workers: Arc::new(Workers {
            from: submitter,
            workers,
            behaviour: Mutex::new(HashMap::new()),
            log: Mutex::new(Vec::new()),
        }),
        servers,
        plugin: plugin.expect("plugin"),
        registry: Registry::new(),
        _dirs: dirs,
        submitter_kernel: Arc::new(
            Kernel::new(KernelConfig::default(), keyring_for(publisher)).expect("kernel"),
        ),
    };
    let tokens = tokens_for(&c, &identities);
    (c, tokens)
}
