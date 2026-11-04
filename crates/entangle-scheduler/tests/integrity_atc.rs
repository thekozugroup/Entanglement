//! §16.4 IntegrityPolicy acceptance criteria, end to end over real QUIC on
//! loopback (spec §7.5, INV-INT-1, INV-INT-2).
//!
//! Every test builds a **submitter** and up to three **workers**, each a
//! separate node in this process with its own identity, kernel and
//! `mesh.iroh` endpoint (relays off, loopback only). Workers run real plugin
//! fixtures (`hello-pong`, `stress`); the submitter verifies with the real
//! stdlib metric component `plugins/metric-bleu-4` (pre-built fixture in
//! `tests/fixtures/`).
//!
//! "Where was the metric instantiated?" is answered two independent ways:
//!
//! * the submitter's `MetricRegistry` counter;
//! * a process-wide `tracing` capture of the host's per-instantiation event
//!   (target `entangle::integrity::metric`), which carries the BLAKE3 of the
//!   component and the **owner** node's peer id. Because the capture is
//!   global, an instantiation on *any* node in this process — workers
//!   included — would be recorded with that node's id.
//!
//! | Test | §16 ID |
//! |---|---|
//! | `atc_int_1_metric_runs_only_on_the_submitter_once_per_pair` | ATC-INT-1 |
//! | `atc_int_2_metric_signed_outside_the_submitter_keyring_is_refused` | ATC-INT-2 |
//! | `atc_int_3_policy_mutation_mid_flight_is_rejected` | ATC-INT-3 |
//! | `atc_int_5_oversized_output_short_circuits_before_the_metric` | ATC-INT-5 |
//!
//! The file also covers the Layer-2 spot-check (§7.5, no §16 ID): colluding
//! replicas caught and downranked, honest replicas confirmed, `p = 0`, and
//! the concurrency bound.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use entangle_mesh_iroh::{IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_SCHEDULER};
use entangle_observability::{catalog::names, Registry};
use entangle_runtime::{IntegrityError, Kernel, KernelConfig, LifecyclePhase};
use entangle_scheduler::reputation::INITIAL_SCORE;
use entangle_scheduler::spot_check::{Exemption, SkipReason, ATTESTATION_FAILURE_EVENT};
use entangle_scheduler::wire::{
    decode_request, decode_response, encode_request, encode_response, ControlFrame,
    RemoteErrorCode, RemoteOutcome, RemoteRequest, RemoteTaskRequest, RemoteTaskResponse,
    RequestFrame,
};
use entangle_scheduler::work_unit::{policy_hash, PolicyEnvelope, PolicyHash};
use entangle_scheduler::{
    DispatchError, Dispatcher, OutputSizeExceededWarning, PeerDirectory, RemoteDispatch,
    RemoteTaskServer, ReplicaStatus, SpotCheck, SpotCheckConfig, SpotCheckVerdict, StaticAllowlist,
    WorkerInfo, WorkerPool, TELEMETRY_TARGET,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::errors::EntangleError;
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::resource::ResourceSpec;
use entangle_types::task::{IntegrityPolicy, MetricRef, OneShotTask, PolicyKind};
use parking_lot::Mutex;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

const TEST_DEADLINE: Duration = Duration::from_secs(60);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(TEST_DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {TEST_DEADLINE:?}"),
    }
}

// ── fixtures ─────────────────────────────────────────────────────────────────

fn fixture(path: &str) -> Vec<u8> {
    let full = format!("{}/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&full).unwrap_or_else(|e| panic!("fixture {full}: {e}"))
}

/// `run(input) = "Hello, <input>!"`.
fn hello_pong() -> Vec<u8> {
    fixture("../entangle-host/tests/fixtures/hello-pong.wasm")
}

/// `run("spin:<ms>")` busy-loops for `<ms>` then returns `spun`.
fn stress() -> Vec<u8> {
    fixture("../entangle-host/tests/fixtures/stress.wasm")
}

/// The stdlib BLEU-4 metric component, built from `plugins/metric-bleu-4`.
fn bleu_metric() -> Vec<u8> {
    fixture("tests/fixtures/metric-bleu-4.wasm")
}

fn keyring_for(keypair: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: keypair.fingerprint(),
        public_key: *keypair.public().as_bytes(),
        publisher_name: "test-publisher".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

/// Write a signed package (`entangle.toml` + `plugin.wasm` + sig) for `name`.
fn write_package(
    dir: &std::path::Path,
    keypair: &IdentityKeyPair,
    name: &str,
    tier: u8,
    wasm: &[u8],
) -> PluginId {
    let id = format!("{}/{name}@0.1.0", keypair.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = {tier}\nruntime = \"wasm\"\n"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    let bundle = sign_artifact(wasm, manifest.as_bytes(), keypair);
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    id.parse().unwrap()
}

// ── trace capture ────────────────────────────────────────────────────────────

/// One captured `tracing` event at an `entangle::*` target.
#[derive(Clone, Debug)]
struct Captured {
    target: String,
    fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

struct Capture(Arc<Mutex<Vec<Captured>>>);

impl<S: tracing::Subscriber> Layer<S> for Capture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.0.lock().push(Captured {
            target: event.metadata().target().to_owned(),
            fields: fields.0,
        });
    }
}

/// The process-wide capture of every event at an `entangle::` target, on
/// every thread. Installed once per test binary; tests filter by the unique
/// peer ids and digests of their own nodes.
fn captured() -> Arc<Mutex<Vec<Captured>>> {
    static STORE: OnceLock<Arc<Mutex<Vec<Captured>>>> = OnceLock::new();
    STORE
        .get_or_init(|| {
            let store = Arc::new(Mutex::new(Vec::new()));
            let filter = tracing_subscriber::filter::Targets::new()
                .with_target("entangle::", tracing::Level::TRACE);
            tracing_subscriber::registry()
                .with(Capture(Arc::clone(&store)).with_filter(filter))
                .init();
            store
        })
        .clone()
}

/// Captured instantiation events, on any node in this process, of the metric
/// component `metric` names: same BLAKE3 **and** same plugin id. Tests run in
/// parallel and share the BLEU fixture bytes, but each signs it with its own
/// fresh publisher key, so the plugin id scopes the events to one test.
fn metric_instantiations(store: &Mutex<Vec<Captured>>, metric: &MetricRef) -> Vec<Captured> {
    let artifact = metric.artifact_hex();
    let plugin = metric.plugin.to_string();
    store
        .lock()
        .iter()
        .filter(|e| {
            e.target == entangle_host::metric::METRIC_TRACE_TARGET
                && e.fields.get("artifact") == Some(&artifact)
                && e.fields.get("metric") == Some(&plugin)
        })
        .cloned()
        .collect()
}

// ── nodes ────────────────────────────────────────────────────────────────────

fn loopback_config() -> MeshIrohConfig {
    MeshIrohConfig {
        alpn: ALPN_SCHEDULER.to_vec(),
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(20),
        ..MeshIrohConfig::loopback()
    }
}

struct Node {
    peer_id: PeerId,
    kernel: Arc<Kernel>,
    transport: Arc<MeshIroh>,
    _packages: Vec<tempfile::TempDir>,
}

impl Node {
    /// A node whose kernel trusts `publisher`.
    async fn start(publisher: &IdentityKeyPair) -> Self {
        let identity = IdentityKeyPair::generate();
        let kernel =
            Arc::new(Kernel::new(KernelConfig::default(), keyring_for(publisher)).expect("kernel"));
        let transport = Arc::new(
            MeshIroh::start(loopback_config(), &identity)
                .await
                .expect("loopback endpoint must bind"),
        );
        Self {
            peer_id: transport.local_peer_id(),
            kernel,
            transport,
            _packages: Vec::new(),
        }
    }

    async fn load(&mut self, publisher: &IdentityKeyPair, name: &str, wasm: &[u8]) -> PluginId {
        let dir = tempfile::tempdir().unwrap();
        let id = write_package(dir.path(), publisher, name, 1, wasm);
        self.kernel
            .load_plugin_from_dir(dir.path())
            .await
            .expect("plugin must load");
        self._packages.push(dir);
        id
    }

    fn address(&self) -> IrohPeer {
        let addr = self
            .transport
            .local_addrs()
            .into_iter()
            .find(|a| a.ip().is_loopback())
            .expect("loopback socket");
        IrohPeer::new(self.transport.local_public_key(), addr)
    }

    /// Serve scheduler work for exactly `submitter`.
    fn serve_for(&self, submitter: PeerId) -> Arc<RemoteTaskServer> {
        let server = Arc::new(RemoteTaskServer::new(
            Arc::clone(&self.kernel),
            Arc::new(StaticAllowlist::new().allow(submitter)),
            self.peer_id,
        ));
        tokio::spawn(entangle_scheduler::serve_tasks(
            Arc::clone(&self.transport),
            Arc::clone(&server),
        ));
        server
    }

    /// Serve as a **malicious** worker: whatever task arrives, answer with
    /// `answer(request)` — executing nothing, honouring no limit.
    fn serve_rogue<F>(&self, answer: F)
    where
        F: Fn(&RemoteTaskRequest) -> RemoteTaskResponse + Send + Sync + 'static,
    {
        let answer = Arc::new(answer);
        tokio::spawn(entangle_mesh_iroh::serve(
            Arc::clone(&self.transport),
            move |_peer, bytes| {
                let answer = Arc::clone(&answer);
                async move {
                    let resp = match decode_request(&bytes) {
                        Ok(RemoteRequest {
                            frame: RequestFrame::Task(task),
                            ..
                        }) => answer(&task),
                        _ => RemoteTaskResponse::err(RemoteErrorCode::MalformedRequest, "rogue"),
                    };
                    encode_response(&resp).unwrap_or_default()
                }
            },
        ));
    }
}

fn worker_info(peer: PeerId) -> WorkerInfo {
    WorkerInfo {
        peer_id: peer,
        display_name: "worker".into(),
        cpu_cores: 16.0,
        memory_bytes: 64 * 1024 * 1024 * 1024,
        gpu: None,
        npu: None,
        network_bandwidth_bps: 1_000_000_000,
        rtt_ms: 1,
        load: 0.0,
        cost: 1.0,
    }
}

/// The submitter's dispatcher, with every node in `workers` in its pool and
/// address book. Returns the remote client too, for control frames.
fn submitter_dispatcher(submitter: &Node, workers: &[&Node]) -> (Dispatcher, Arc<RemoteDispatch>) {
    let pool = WorkerPool::new();
    let directory = PeerDirectory::new();
    for w in workers {
        pool.upsert(worker_info(w.peer_id));
        directory.insert(w.address());
    }
    let client = Arc::new(RemoteDispatch::new(
        Arc::clone(&submitter.transport) as Arc<dyn MeshTransport>,
        Arc::new(directory),
    ));
    let dispatcher = Dispatcher::new(pool, Arc::clone(&submitter.kernel), submitter.peer_id)
        .with_strict_remote(true)
        .with_remote(Arc::clone(&client));
    (dispatcher, client)
}

/// Sign the BLEU metric with `publisher`, load it into the submitter's
/// registry, and return its pinned reference.
fn load_bleu(
    dispatcher: &Dispatcher,
    publisher: &IdentityKeyPair,
) -> (MetricRef, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    write_package(dir.path(), publisher, "metric-bleu-4", 2, &bleu_metric());
    let metric = dispatcher
        .verifier()
        .metrics()
        .load_from_dir(dir.path())
        .expect("a metric signed by a trusted publisher loads");
    (metric, dir)
}

fn semantic(metric: &MetricRef, threshold: f64) -> IntegrityPolicy {
    IntegrityPolicy::SemanticEquivalent {
        replicas: 3,
        quorum: 2,
        metric: metric.clone(),
        threshold,
    }
}

fn task(plugin: PluginId, input: &[u8], integrity: IntegrityPolicy) -> OneShotTask {
    OneShotTask {
        id: uuid::Uuid::new_v4(),
        plugin,
        input: input.to_vec(),
        max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
        max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        resources: ResourceSpec::default(),
        integrity,
        timeout_ms: 20_000,
    }
}

/// Every lifecycle phase `sub` receives within a short quiet period.
async fn drain(
    sub: &mut entangle_ipc::bus::Subscriber<entangle_runtime::LifecycleEvent>,
) -> Vec<LifecyclePhase> {
    drain_for(sub, Duration::from_millis(300)).await
}

/// Like [`drain`] with an explicit quiet window. Negative ("nothing ran")
/// assertions use a long window (`QUIET_NEGATIVE`) so a slow, wrongly started
/// execution under CI load is still caught; they are additionally backed by a
/// positive sentinel where the test can provide one.
async fn drain_for(
    sub: &mut entangle_ipc::bus::Subscriber<entangle_runtime::LifecycleEvent>,
    quiet: Duration,
) -> Vec<LifecyclePhase> {
    let mut phases = Vec::new();
    while let Ok(Ok(env)) = tokio::time::timeout(quiet, sub.recv()).await {
        phases.push(env.payload.phase);
    }
    phases
}

/// Quiet window for assertions that nothing executed.
const QUIET_NEGATIVE: Duration = Duration::from_millis(1500);

fn activations(phases: &[LifecyclePhase]) -> usize {
    phases
        .iter()
        .filter(|p| **p == LifecyclePhase::Activated)
        .count()
}

// ═════════════════════════════════════════════════════════════════════════════
// ATC-INT-1 — verifier locality
// ═════════════════════════════════════════════════════════════════════════════

/// GIVEN a `SemanticEquivalent` task with metric X and 3 worker peers,
/// WHEN it executes end to end,
/// THEN no worker instantiates X, and the submitter instantiates X exactly
/// once per pair compared (3 replicas → 3 pairs → 3 instantiations).
#[tokio::test(flavor = "multi_thread")]
async fn atc_int_1_metric_runs_only_on_the_submitter_once_per_pair() {
    let trace = captured();
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut workers = Vec::new();
    for _ in 0..3 {
        let mut w = Node::start(&publisher).await;
        w.load(&publisher, "hello", &hello_pong()).await;
        w.serve_for(submitter.peer_id);
        workers.push(w);
    }
    let plugin: PluginId = format!("{}/hello@0.1.0", publisher.fingerprint_hex())
        .parse()
        .unwrap();
    let mut buses: Vec<_> = workers.iter().map(|w| w.kernel.bus().subscribe()).collect();

    let (dispatcher, _) = submitter_dispatcher(&submitter, &workers.iter().collect::<Vec<_>>());
    let (metric, _pkg) = load_bleu(&dispatcher, &publisher);
    assert_eq!(dispatcher.verifier().metrics().instantiations(&metric), 0);

    let t = task(plugin, b"world", semantic(&metric, 0.25));
    let h = policy_hash(&t.integrity);
    let result = deadline("semantic dispatch", dispatcher.dispatch_one_shot(t))
        .await
        .expect("three agreeing replicas must be accepted");

    assert_eq!(result.output, b"Hello, world!");
    assert_eq!(result.policy_hash, h);
    assert_eq!(result.pair_agreement, Some((3, 3)));

    // Three replicas, on three distinct remote workers — none on the submitter.
    assert_eq!(result.replicas.len(), 3);
    let mut ran_on: Vec<PeerId> = result.replicas.iter().map(|r| r.peer).collect();
    ran_on.sort();
    let mut expected: Vec<PeerId> = workers.iter().map(|w| w.peer_id).collect();
    expected.sort();
    assert_eq!(ran_on, expected, "one replica per worker");
    assert!(result.replicas.iter().all(|r| r.remote));
    assert_eq!(
        result
            .replicas
            .iter()
            .filter(|r| r.status == ReplicaStatus::Canonical)
            .count(),
        1
    );

    // The submitter instantiated the metric exactly once per pair...
    assert_eq!(dispatcher.verifier().metrics().instantiations(&metric), 3);
    let events = metric_instantiations(&trace, &metric);
    assert_eq!(
        events.len(),
        3,
        "exactly one instantiation per pair: {events:?}"
    );
    let submitter_hex = submitter.peer_id.to_hex();
    for e in &events {
        assert_eq!(
            e.fields.get("owner"),
            Some(&submitter_hex),
            "every instantiation must be on the submitter: {e:?}"
        );
    }

    // ...and no worker ever instantiated it, or even holds it.
    for (w, bus) in workers.iter().zip(buses.iter_mut()) {
        let w_hex = w.peer_id.to_hex();
        assert!(
            !events.iter().any(|e| e.fields.get("owner") == Some(&w_hex)),
            "worker {w_hex} instantiated the metric"
        );
        let loaded = w.kernel.list_plugins();
        assert_eq!(loaded.len(), 1, "a worker holds only the task plugin");
        assert_ne!(loaded[0], metric.plugin);
        // Each worker ran the task exactly once.
        assert_eq!(
            activations(&drain(bus).await),
            1,
            "one execution per worker"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ATC-INT-2 — custom metric must be on the submitter's keyring
// ═════════════════════════════════════════════════════════════════════════════

/// GIVEN a metric signed by a key NOT on the submitter's keyring,
/// WHEN the submitter loads it, or submits a task naming it,
/// THEN both are refused with `MetricNotInKeyring` and nothing is dispatched.
#[tokio::test(flavor = "multi_thread")]
async fn atc_int_2_metric_signed_outside_the_submitter_keyring_is_refused() {
    let publisher = IdentityKeyPair::generate();
    let stranger = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut worker = Node::start(&publisher).await;
    let plugin = worker.load(&publisher, "hello", &hello_pong()).await;
    let server = worker.serve_for(submitter.peer_id);
    let mut bus = worker.kernel.bus().subscribe();
    let (dispatcher, _) = submitter_dispatcher(&submitter, &[&worker]);

    // The stranger's signed metric does not even load.
    let dir = tempfile::tempdir().unwrap();
    write_package(dir.path(), &stranger, "custom-metric", 2, &bleu_metric());
    let err = dispatcher
        .verifier()
        .metrics()
        .load_from_dir(dir.path())
        .expect_err("a metric from an untrusted publisher must not load");
    assert!(
        matches!(err, IntegrityError::MetricNotInKeyring { ref fingerprint, .. }
            if *fingerprint == stranger.fingerprint_hex()),
        "{err}"
    );

    // A work unit naming it is refused at submit time.
    let custom = MetricRef {
        plugin: format!("{}/custom-metric@0.1.0", stranger.fingerprint_hex())
            .parse()
            .unwrap(),
        publisher_key: *stranger.public().as_bytes(),
        artifact_blake3: *blake3::hash(&bleu_metric()).as_bytes(),
    };
    let err = deadline(
        "submit with an untrusted metric",
        dispatcher.dispatch_one_shot(task(plugin, b"world", semantic(&custom, 0.25))),
    )
    .await
    .expect_err("submit must refuse a metric outside the keyring");
    match &err {
        DispatchError::Integrity(IntegrityError::MetricNotInKeyring {
            metric,
            fingerprint,
        }) => {
            assert_eq!(*metric, custom.plugin.to_string());
            assert_eq!(*fingerprint, stranger.fingerprint_hex());
        }
        other => panic!("expected MetricNotInKeyring, got {other:?}"),
    }
    assert!(err.to_string().contains("ENTANGLE-E0307"), "{err}");

    // Nothing was dispatched: the worker never saw a task, and nothing ran.
    assert_eq!(server.in_flight_len(), 0);
    assert!(
        drain_for(&mut bus, QUIET_NEGATIVE).await.is_empty(),
        "the worker must not have run anything"
    );
    assert_eq!(dispatcher.verifier().metrics().total_instantiations(), 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// ATC-INT-3 — policy immutability (INV-INT-1)
// ═════════════════════════════════════════════════════════════════════════════

/// GIVEN a dispatched task with policy hash H (3 replicas in flight),
/// WHEN the submitter sends a control frame that would loosen the policy,
/// THEN every worker rejects it with `PolicyMutation`, the running task keeps
/// H, and every replica's observed policy hash at result time equals H.
#[tokio::test(flavor = "multi_thread")]
async fn atc_int_3_policy_mutation_mid_flight_is_rejected() {
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut workers = Vec::new();
    let mut servers = Vec::new();
    for _ in 0..3 {
        let mut w = Node::start(&publisher).await;
        w.load(&publisher, "stress", &stress()).await;
        servers.push(w.serve_for(submitter.peer_id));
        workers.push(w);
    }
    let plugin: PluginId = format!("{}/stress@0.1.0", publisher.fingerprint_hex())
        .parse()
        .unwrap();
    let (dispatcher, client) =
        submitter_dispatcher(&submitter, &workers.iter().collect::<Vec<_>>());
    let (metric, _pkg) = load_bleu(&dispatcher, &publisher);

    // Long enough to be caught mid-flight; the wait below makes it certain.
    let t = task(plugin, b"spin:3000", semantic(&metric, 0.25));
    let task_id = t.id;
    let original = PolicyEnvelope::seal(&t.integrity).unwrap();
    let h: PolicyHash = original.hash();

    let running = tokio::spawn({
        let dispatcher = dispatcher.clone();
        async move { dispatcher.dispatch_one_shot(t).await }
    });

    // Wait until every worker is executing the task under H.
    for server in &servers {
        deadline("task in flight on every worker", async {
            while server
                .in_flight_policy(&submitter.peer_id, &task_id)
                .is_none()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert_eq!(
            server.in_flight_policy(&submitter.peer_id, &task_id),
            Some(h)
        );
    }

    // Mid-flight, try to rubber-stamp: threshold 0.25 → 10.0.
    let loosened = PolicyEnvelope::seal(&semantic(&metric, 10.0)).unwrap();
    assert_ne!(loosened.hash(), h);
    for w in &workers {
        let err = client
            .send_control(
                w.peer_id,
                ControlFrame::set_policy(task_id, &loosened),
                Duration::from_secs(10),
            )
            .await
            .expect_err("a policy mutation must be rejected");
        match &err {
            DispatchError::Integrity(IntegrityError::PolicyMutation { peer, task_id: id }) => {
                assert_eq!(*peer, w.peer_id.to_hex());
                assert_eq!(*id, task_id.to_string());
            }
            other => panic!("expected PolicyMutation, got {other:?}"),
        }
        assert!(err.to_string().contains("ENTANGLE-E0316"), "{err}");
    }
    // Re-sending the *same* policy is not a mutation: acknowledged with H.
    let ack = client
        .send_control(
            workers[0].peer_id,
            ControlFrame::set_policy(task_id, &original),
            Duration::from_secs(10),
        )
        .await
        .expect("an identical policy is acknowledged");
    assert_eq!(ack, h);
    // The running tasks still hold H.
    for server in &servers {
        assert_eq!(
            server.in_flight_policy(&submitter.peer_id, &task_id),
            Some(h)
        );
    }

    let result = deadline("replicated task", running)
        .await
        .expect("join")
        .expect("the task completes under its original policy");
    assert_eq!(result.output, b"spun");
    assert_eq!(result.policy_hash, h);
    assert_eq!(result.replicas.len(), 3);
    for r in &result.replicas {
        assert!(r.remote);
        assert_eq!(
            r.observed_policy_hash,
            Some(h),
            "replica on {} observed a different policy",
            r.peer
        );
    }

    // Once finished, the task is no longer addressable.
    for server in &servers {
        assert_eq!(server.in_flight_len(), 0);
    }
    let err = client
        .send_control(
            workers[1].peer_id,
            ControlFrame::set_policy(task_id, &loosened),
            Duration::from_secs(10),
        )
        .await
        .expect_err("a finished task cannot be addressed");
    assert!(
        matches!(
            err,
            DispatchError::RemoteRejected {
                code: RemoteErrorCode::UnknownTask,
                ..
            }
        ),
        "{err:?}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// ATC-INT-5 — output-size DoS short-circuit (INV-INT-2)
// ═════════════════════════════════════════════════════════════════════════════

/// GIVEN a `SemanticEquivalent` task with `max_output_bytes = 1024`,
/// WHEN a worker returns 2048 bytes,
/// THEN the submitter fails the task with `OutputSizeExceeded`, never
/// instantiates the metric, emits `OutputSizeExceededWarning { peer_id,
/// declared: 1024, actual: 2048 }` to telemetry, and the worker's reputation
/// is strictly lower than before.
#[tokio::test(flavor = "multi_thread")]
async fn atc_int_5_oversized_output_short_circuits_before_the_metric() {
    let trace = captured();
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;

    // Two honest workers — enough for a metric comparison to happen if the
    // guard were missing — and one that answers with 2048 bytes.
    let mut honest = Vec::new();
    for _ in 0..2 {
        let mut w = Node::start(&publisher).await;
        w.load(&publisher, "hello", &hello_pong()).await;
        w.serve_for(submitter.peer_id);
        honest.push(w);
    }
    let rogue = Node::start(&publisher).await;
    rogue.serve_rogue(|req| RemoteTaskResponse::ok(vec![b'A'; 2048], req.policy_hash));

    let plugin: PluginId = format!("{}/hello@0.1.0", publisher.fingerprint_hex())
        .parse()
        .unwrap();
    let (dispatcher, _) = submitter_dispatcher(&submitter, &[&honest[0], &honest[1], &rogue]);
    let (metric, _pkg) = load_bleu(&dispatcher, &publisher);
    let reputation = dispatcher.verifier().reputation();
    let kind = PolicyKind::SemanticEquivalent;
    let before = reputation.get(&rogue.peer_id, kind);
    assert_eq!(before, INITIAL_SCORE);

    let mut t = task(plugin, b"world", semantic(&metric, 0.25));
    t.max_output_bytes = 1024;
    let err = deadline("oversized replica", dispatcher.dispatch_one_shot(t))
        .await
        .expect_err("an oversized replica must fail the task");
    match &err {
        DispatchError::OutputSizeExceeded(EntangleError::OutputSizeExceeded {
            declared,
            actual,
            peer,
        }) => {
            assert_eq!((*declared, *actual), (1024, 2048));
            assert_eq!(*peer, rogue.peer_id.to_hex());
        }
        other => panic!("expected OutputSizeExceeded, got {other:?}"),
    }
    assert!(err.to_string().contains("ENTANGLE-E0300"), "{err}");

    // The metric was never instantiated — not on the submitter, not anywhere.
    assert_eq!(dispatcher.verifier().metrics().instantiations(&metric), 0);
    assert!(metric_instantiations(&trace, &metric).is_empty());

    // The warning reached telemetry with the offending peer and both sizes.
    let rogue_hex = rogue.peer_id.to_hex();
    let warnings: Vec<Captured> = trace
        .lock()
        .iter()
        .filter(|e| {
            e.target == entangle_scheduler::TELEMETRY_TARGET
                && e.fields.get("event").map(String::as_str)
                    == Some(OutputSizeExceededWarning::EVENT)
                && e.fields.get("peer_id") == Some(&rogue_hex)
        })
        .cloned()
        .collect();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_eq!(
        warnings[0].fields.get("declared").map(String::as_str),
        Some("1024")
    );
    assert_eq!(
        warnings[0].fields.get("actual").map(String::as_str),
        Some("2048")
    );

    // Reputation: strictly lower for the offender, untouched for the honest.
    assert!(reputation.get(&rogue.peer_id, kind) < before);
    for w in &honest {
        assert_eq!(reputation.get(&w.peer_id, kind), INITIAL_SCORE);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Further cross-node integrity behaviour (not §16 IDs)
// ═════════════════════════════════════════════════════════════════════════════

/// `Deterministic { replicas: 3 }` runs one replica on each of three distinct
/// workers and accepts the byte-identical result.
#[tokio::test(flavor = "multi_thread")]
async fn deterministic_replicas_run_on_distinct_workers() {
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut workers = Vec::new();
    for _ in 0..3 {
        let mut w = Node::start(&publisher).await;
        w.load(&publisher, "hello", &hello_pong()).await;
        w.serve_for(submitter.peer_id);
        workers.push(w);
    }
    let plugin: PluginId = format!("{}/hello@0.1.0", publisher.fingerprint_hex())
        .parse()
        .unwrap();
    let mut buses: Vec<_> = workers.iter().map(|w| w.kernel.bus().subscribe()).collect();
    let (dispatcher, _) = submitter_dispatcher(&submitter, &workers.iter().collect::<Vec<_>>());

    let result = deadline(
        "deterministic x3",
        dispatcher.dispatch_one_shot(task(
            plugin,
            b"world",
            IntegrityPolicy::Deterministic { replicas: 3 },
        )),
    )
    .await
    .expect("identical replicas are accepted");
    assert_eq!(result.output, b"Hello, world!");
    let mut peers: Vec<PeerId> = result.replicas.iter().map(|r| r.peer).collect();
    peers.sort();
    peers.dedup();
    assert_eq!(peers.len(), 3, "replicas must land on distinct workers");
    assert!(
        submitter.kernel.list_plugins().is_empty(),
        "nothing ran locally"
    );
    for bus in &mut buses {
        assert_eq!(activations(&drain(bus).await), 1);
    }
}

/// With fewer remote workers than replicas, the remainder runs on the
/// submitter's own kernel.
#[tokio::test(flavor = "multi_thread")]
async fn replicas_without_a_remote_target_run_locally() {
    let publisher = IdentityKeyPair::generate();
    let mut submitter = Node::start(&publisher).await;
    submitter.load(&publisher, "hello", &hello_pong()).await;
    let mut worker = Node::start(&publisher).await;
    let plugin = worker.load(&publisher, "hello", &hello_pong()).await;
    worker.serve_for(submitter.peer_id);
    let (dispatcher, _) = submitter_dispatcher(&submitter, &[&worker]);

    let result = deadline(
        "deterministic x3 with one worker",
        dispatcher.dispatch_one_shot(task(
            plugin,
            b"world",
            IntegrityPolicy::Deterministic { replicas: 3 },
        )),
    )
    .await
    .expect("one remote + two local identical replicas are accepted");
    assert_eq!(result.output, b"Hello, world!");
    let remote: Vec<_> = result.replicas.iter().filter(|r| r.remote).collect();
    assert_eq!(remote.len(), 1);
    assert_eq!(remote[0].peer, worker.peer_id);
    assert_eq!(
        result
            .replicas
            .iter()
            .filter(|r| !r.remote && r.peer == submitter.peer_id)
            .count(),
        2
    );
}

/// A peer whose reputation fell below the exclusion tier (0.80) is not given a
/// replica; its slot falls back to the submitter's own kernel.
#[tokio::test(flavor = "multi_thread")]
async fn an_excluded_peer_is_not_picked_as_a_replica_target() {
    let publisher = IdentityKeyPair::generate();
    let mut submitter = Node::start(&publisher).await;
    submitter.load(&publisher, "hello", &hello_pong()).await;
    let mut good = Node::start(&publisher).await;
    let plugin = good.load(&publisher, "hello", &hello_pong()).await;
    good.serve_for(submitter.peer_id);
    let mut bad = Node::start(&publisher).await;
    bad.load(&publisher, "hello", &hello_pong()).await;
    bad.serve_for(submitter.peer_id);
    let mut bad_bus = bad.kernel.bus().subscribe();
    let (dispatcher, _) = submitter_dispatcher(&submitter, &[&good, &bad]);

    let kind = PolicyKind::Deterministic;
    let rep = dispatcher.verifier().reputation();
    assert!(rep.is_eligible(&bad.peer_id, kind));
    for _ in 0..20 {
        rep.penalize(
            &bad.peer_id,
            kind,
            entangle_scheduler::ReputationReason::DisagreedWithQuorum,
        );
    }
    assert!(
        !rep.is_eligible(&bad.peer_id, kind),
        "setup: bad is excluded"
    );
    assert!(rep.is_eligible(&good.peer_id, kind));

    let result = deadline(
        "deterministic x2 with one excluded worker",
        dispatcher.dispatch_one_shot(task(
            plugin,
            b"world",
            IntegrityPolicy::Deterministic { replicas: 2 },
        )),
    )
    .await
    .expect("good remote + one local replica are accepted");
    assert_eq!(result.output, b"Hello, world!");
    assert!(
        result.replicas.iter().all(|r| r.peer != bad.peer_id),
        "the excluded peer must not be a replica target: {:?}",
        result.replicas
    );
    let remote: Vec<_> = result.replicas.iter().filter(|r| r.remote).collect();
    assert_eq!(remote.len(), 1);
    assert_eq!(remote[0].peer, good.peer_id);
    assert_eq!(
        result.replicas.iter().filter(|r| !r.remote).count(),
        1,
        "the shortfall runs locally"
    );
    assert_eq!(activations(&drain(&mut bad_bus).await), 0);
}

/// A worker whose output disagrees with the accepted quorum is outvoted and
/// loses reputation; the agreeing workers gain standing.
#[tokio::test(flavor = "multi_thread")]
async fn a_dissenting_replica_is_outvoted_and_penalised() {
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut honest = Vec::new();
    for _ in 0..2 {
        let mut w = Node::start(&publisher).await;
        w.load(&publisher, "hello", &hello_pong()).await;
        w.serve_for(submitter.peer_id);
        honest.push(w);
    }
    let liar = Node::start(&publisher).await;
    liar.serve_rogue(|req| {
        RemoteTaskResponse::ok(
            b"Something else entirely, said with confidence".to_vec(),
            req.policy_hash,
        )
    });
    let plugin: PluginId = format!("{}/hello@0.1.0", publisher.fingerprint_hex())
        .parse()
        .unwrap();
    let (dispatcher, _) = submitter_dispatcher(&submitter, &[&honest[0], &honest[1], &liar]);
    let (metric, _pkg) = load_bleu(&dispatcher, &publisher);

    let policy = IntegrityPolicy::SemanticEquivalent {
        replicas: 3,
        quorum: 1,
        metric: metric.clone(),
        threshold: 0.25,
    };
    let result = deadline(
        "semantic with a liar",
        dispatcher.dispatch_one_shot(task(plugin.clone(), b"world", policy)),
    )
    .await
    .expect("the honest pair reaches quorum 1");
    assert_eq!(result.output, b"Hello, world!");
    assert_eq!(result.pair_agreement, Some((1, 3)));
    assert_eq!(dispatcher.verifier().metrics().instantiations(&metric), 3);
    let liar_report = result
        .replicas
        .iter()
        .find(|r| r.peer == liar.peer_id)
        .expect("liar replica reported");
    assert_eq!(liar_report.status, ReplicaStatus::Disagreed);
    let kind = PolicyKind::SemanticEquivalent;
    let rep = dispatcher.verifier().reputation();
    assert!(rep.get(&liar.peer_id, kind) < INITIAL_SCORE);
    for w in &honest {
        assert_eq!(rep.get(&w.peer_id, kind), INITIAL_SCORE);
        assert_eq!(rep.record(&w.peer_id, kind).correct, 1);
    }
    // Reputation is per policy variant: Deterministic standing is untouched.
    assert_eq!(
        rep.get(&liar.peer_id, PolicyKind::Deterministic),
        INITIAL_SCORE
    );

    // With quorum 2, the same outputs are refused.
    let strict = semantic(&metric, 0.25);
    let err = deadline(
        "semantic quorum 2",
        dispatcher.dispatch_one_shot(task(plugin, b"world", strict)),
    )
    .await
    .expect_err("one agreeing pair cannot satisfy quorum 2");
    assert!(
        matches!(
            err,
            DispatchError::Integrity(IntegrityError::QuorumNotReached {
                agreeing: 1,
                pairs: 3,
                required: 2
            })
        ),
        "{err:?}"
    );
}

/// The submitter refuses a replica whose echoed policy hash is not the one it
/// dispatched (INV-INT-1, ENTANGLE-E0315), and the echoing peer loses standing.
#[tokio::test(flavor = "multi_thread")]
async fn a_replica_echoing_another_policy_hash_is_refused() {
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let liar = Node::start(&publisher).await;
    let other = policy_hash(&IntegrityPolicy::Deterministic { replicas: 9 });
    liar.serve_rogue(move |_| RemoteTaskResponse::ok(b"Hello, world!".to_vec(), other));
    let (dispatcher, _) = submitter_dispatcher(&submitter, &[&liar]);
    let plugin: PluginId = format!("{}/hello@0.1.0", publisher.fingerprint_hex())
        .parse()
        .unwrap();

    let err = deadline(
        "single dispatch to a liar",
        dispatcher.dispatch_one_shot(task(plugin, b"world", IntegrityPolicy::None)),
    )
    .await
    .expect_err("a mismatched echo must be refused");
    assert!(
        matches!(
            err,
            DispatchError::Integrity(IntegrityError::PolicyHashMismatch { .. })
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("ENTANGLE-E0315"), "{err}");
    assert!(
        dispatcher
            .verifier()
            .reputation()
            .get(&liar.peer_id, PolicyKind::None)
            < INITIAL_SCORE
    );
}

/// One task frame is one execution, whatever policy it carries: a peer
/// cannot turn `Deterministic { replicas: 16 }` into 16 runs on one worker.
#[tokio::test(flavor = "multi_thread")]
async fn a_replicated_policy_in_one_frame_is_still_one_execution() {
    let publisher = IdentityKeyPair::generate();
    let caller = Node::start(&publisher).await;
    let mut worker = Node::start(&publisher).await;
    let plugin = worker.load(&publisher, "hello", &hello_pong()).await;
    worker.serve_for(caller.peer_id);
    let mut bus = worker.kernel.bus().subscribe();

    let t = task(
        plugin,
        b"world",
        IntegrityPolicy::Deterministic { replicas: 16 },
    );
    let frame = encode_request(&RemoteRequest::for_task(&t).unwrap()).unwrap();
    let raw = deadline(
        "raw frame",
        caller.transport.request(&worker.address(), &frame),
    )
    .await
    .expect("round trip");
    match decode_response(&raw, u64::MAX).unwrap().outcome {
        RemoteOutcome::Ok {
            output,
            observed_policy_hash,
        } => {
            assert_eq!(output, b"Hello, world!");
            assert_eq!(observed_policy_hash, policy_hash(&t.integrity));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        activations(&drain(&mut bus).await),
        1,
        "exactly one execution"
    );
}

/// A task frame whose `policy_hash` does not match its policy bytes is
/// refused before anything runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_with_a_forged_policy_hash_runs_nothing() {
    let publisher = IdentityKeyPair::generate();
    let caller = Node::start(&publisher).await;
    let mut worker = Node::start(&publisher).await;
    let plugin = worker.load(&publisher, "hello", &hello_pong()).await;
    worker.serve_for(caller.peer_id);
    let mut bus = worker.kernel.bus().subscribe();

    let mut req =
        RemoteRequest::for_task(&task(plugin.clone(), b"world", IntegrityPolicy::None)).unwrap();
    let RequestFrame::Task(body) = &mut req.frame else {
        unreachable!()
    };
    body.policy_hash = policy_hash(&IntegrityPolicy::Deterministic { replicas: 2 });
    let raw = deadline(
        "forged frame",
        caller
            .transport
            .request(&worker.address(), &encode_request(&req).unwrap()),
    )
    .await
    .expect("round trip");
    match decode_response(&raw, u64::MAX).unwrap().outcome {
        RemoteOutcome::Err { code, .. } => assert_eq!(code, RemoteErrorCode::PolicyHashMismatch),
        other => panic!("a forged envelope must be refused, got {other:?}"),
    }
    assert!(
        drain_for(&mut bus, QUIET_NEGATIVE).await.is_empty(),
        "nothing may run"
    );

    // Positive sentinel: the bus is live and the worker still serves, so the
    // silence above means the forged frame did not run (not a dead
    // subscription). The honest frame runs exactly once.
    let ok = RemoteRequest::for_task(&task(plugin, b"world", IntegrityPolicy::None)).unwrap();
    let raw = deadline(
        "honest frame",
        caller
            .transport
            .request(&worker.address(), &encode_request(&ok).unwrap()),
    )
    .await
    .expect("round trip");
    assert!(matches!(
        decode_response(&raw, u64::MAX).unwrap().outcome,
        RemoteOutcome::Ok { .. }
    ));
    assert_eq!(activations(&drain(&mut bus).await), 1);
}

/// The committed stdlib metric components compute what their native sources
/// say they compute (`plugins/metric-*/src`), through the real host path:
/// signed package → registry → tier-2 instantiation → `compare`.
#[tokio::test(flavor = "multi_thread")]
async fn stdlib_metric_components_match_their_documented_math() {
    let publisher = IdentityKeyPair::generate();
    let registry = entangle_runtime::MetricRegistry::new(
        Arc::new(parking_lot::RwLock::new(keyring_for(&publisher))),
        "stdlib-check",
    );
    let load = |name: &str, wasm: Vec<u8>| {
        let dir = tempfile::tempdir().unwrap();
        write_package(dir.path(), &publisher, name, 2, &wasm);
        let r = registry
            .load_from_dir(dir.path())
            .expect("stdlib metric loads");
        (r, dir)
    };
    let (bleu, _d1) = load("metric-bleu-4", bleu_metric());
    let (l2, _d2) = load(
        "metric-numerical-l2-relative",
        fixture("tests/fixtures/metric-numerical-l2-relative.wasm"),
    );

    let d = registry
        .compare(&bleu, b"the cat sat on the mat", b"the cat is on the mat")
        .await
        .unwrap();
    assert!(
        (d - (1.0 - (1.0_f64 / 18.0).powf(0.25))).abs() < 1e-12,
        "{d}"
    );
    assert_eq!(
        registry
            .compare(&bleu, b"Hello, world!", b"Hello,  world!")
            .await
            .unwrap(),
        0.0
    );
    assert_eq!(
        registry.compare(&bleu, b"a b c", b"x y z").await.unwrap(),
        1.0
    );

    let d = registry.compare(&l2, b"[3, 4]", b"[3, 4.1]").await.unwrap();
    assert!(
        (d - 0.1 / (9.0_f64 + 4.1 * 4.1).sqrt()).abs() < 1e-12,
        "{d}"
    );
    assert_eq!(
        registry.compare(&l2, b"1 2 3", b"[1, 2, 3]").await.unwrap(),
        0.0
    );
    assert_eq!(
        registry
            .compare(&l2, b"[1, 2]", b"[1, 2, 3]")
            .await
            .unwrap(),
        f64::INFINITY,
        "incomparable is +inf, which the contract allows"
    );
    assert_eq!(registry.instantiations(&bleu), 3);
    assert_eq!(registry.instantiations(&l2), 3);
}

/// A worker refuses a work unit whose metric reference names one publisher
/// and carries another's key (§7.5 Rule 2), before running anything.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_refuses_an_inconsistent_metric_reference() {
    let publisher = IdentityKeyPair::generate();
    let other = IdentityKeyPair::generate();
    let caller = Node::start(&publisher).await;
    let mut worker = Node::start(&publisher).await;
    let plugin = worker.load(&publisher, "hello", &hello_pong()).await;
    worker.serve_for(caller.peer_id);
    let mut bus = worker.kernel.bus().subscribe();

    let forged = MetricRef {
        plugin: format!("{}/metric-bleu-4@0.1.0", publisher.fingerprint_hex())
            .parse()
            .unwrap(),
        publisher_key: *other.public().as_bytes(),
        artifact_blake3: [7; 32],
    };
    let t = task(plugin, b"world", semantic(&forged, 0.25));
    let frame = encode_request(&RemoteRequest::for_task(&t).unwrap()).unwrap();
    let raw = deadline(
        "inconsistent metric frame",
        caller.transport.request(&worker.address(), &frame),
    )
    .await
    .expect("round trip");
    match decode_response(&raw, u64::MAX).unwrap().outcome {
        RemoteOutcome::Err { code, message } => {
            assert_eq!(code, RemoteErrorCode::MalformedRequest);
            assert!(message.contains("publisher key"), "{message}");
        }
        other => panic!("an inconsistent metric reference must be refused, got {other:?}"),
    }
    assert!(drain(&mut bus).await.is_empty(), "nothing may run");
}

/// `TrustedExecutor` only ever places onto an allow-listed peer, even when a
/// better-ranked worker is available.
#[tokio::test(flavor = "multi_thread")]
async fn trusted_executor_places_only_on_allow_listed_peers() {
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut a = Node::start(&publisher).await;
    let mut b = Node::start(&publisher).await;
    let plugin = a.load(&publisher, "hello", &hello_pong()).await;
    b.load(&publisher, "hello", &hello_pong()).await;
    a.serve_for(submitter.peer_id);
    b.serve_for(submitter.peer_id);
    // Identical adverts rank by lower peer id; allow only the other one.
    let (first, second) = if a.peer_id < b.peer_id {
        (&a, &b)
    } else {
        (&b, &a)
    };
    let (dispatcher, _) = submitter_dispatcher(&submitter, &[first, second]);
    assert_eq!(
        entangle_scheduler::rank(
            &[worker_info(first.peer_id), worker_info(second.peer_id)],
            &ResourceSpec::default()
        )
        .unwrap()[0]
            .peer_id,
        first.peer_id
    );

    let policy = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![second.peer_id],
    };
    let result = deadline(
        "trusted executor",
        dispatcher.dispatch_one_shot(task(plugin, b"world", policy)),
    )
    .await
    .expect("the allow-listed peer runs it");
    assert_eq!(result.output, b"Hello, world!");
    assert_eq!(result.chosen.peer_id, second.peer_id);
}

// ═════════════════════════════════════════════════════════════════════════════
// Layer 2 — deterministic-replay spot-checks (spec §7.5)
// ═════════════════════════════════════════════════════════════════════════════

impl Node {
    /// Like [`Node::serve_rogue`], but every answer waits until `gate` is
    /// open — a worker the test keeps busy for as long as it likes.
    fn serve_rogue_gated<F>(&self, gate: tokio::sync::watch::Receiver<bool>, answer: F)
    where
        F: Fn(&RemoteTaskRequest) -> RemoteTaskResponse + Send + Sync + 'static,
    {
        let answer = Arc::new(answer);
        tokio::spawn(entangle_mesh_iroh::serve(
            Arc::clone(&self.transport),
            move |_peer, bytes| {
                let answer = Arc::clone(&answer);
                let mut gate = gate.clone();
                async move {
                    let _ = gate.wait_for(|open| *open).await;
                    let resp = match decode_request(&bytes) {
                        Ok(RemoteRequest {
                            frame: RequestFrame::Task(task),
                            ..
                        }) => answer(&task),
                        _ => RemoteTaskResponse::err(RemoteErrorCode::MalformedRequest, "rogue"),
                    };
                    encode_response(&resp).unwrap_or_default()
                }
            },
        ));
    }
}

/// [`submitter_dispatcher`] with an explicit `load` per worker, so the test
/// decides who ranks first (replica targets) and who is left over (the
/// spot-check's remote executor), with metrics and spot-checks on.
fn spot_checked_dispatcher(
    submitter: &Node,
    workers: &[(&Node, f32)],
    spot: SpotCheckConfig,
    registry: &Registry,
) -> Dispatcher {
    let pool = WorkerPool::new();
    let directory = PeerDirectory::new();
    for (w, load) in workers {
        pool.upsert(WorkerInfo {
            load: *load,
            ..worker_info(w.peer_id)
        });
        directory.insert(w.address());
    }
    let client = Arc::new(RemoteDispatch::new(
        Arc::clone(&submitter.transport) as Arc<dyn MeshTransport>,
        Arc::new(directory),
    ));
    Dispatcher::new(pool, Arc::clone(&submitter.kernel), submitter.peer_id)
        .with_strict_remote(true)
        .with_remote(client)
        .with_metrics(registry.clone())
        .with_spot_checks(spot)
}

const ALWAYS: SpotCheckConfig = SpotCheckConfig {
    probability: 1.0,
    max_concurrent: 4,
};

/// Two workers that collude: whatever arrives, both answer `lie`.
async fn colluders(publisher: &IdentityKeyPair, lie: &'static [u8]) -> Vec<Node> {
    let mut out = Vec::new();
    for _ in 0..2 {
        let liar = Node::start(publisher).await;
        liar.serve_rogue(move |req| RemoteTaskResponse::ok(lie.to_vec(), req.policy_hash));
        out.push(liar);
    }
    out
}

/// Captured `SpotCheckAttestationFailure` events for `task`.
fn attestation_failures(store: &Mutex<Vec<Captured>>, task: uuid::Uuid) -> Vec<Captured> {
    let id = task.to_string();
    store
        .lock()
        .iter()
        .filter(|e| {
            e.target == TELEMETRY_TARGET
                && e.fields.get("event").map(String::as_str) == Some(ATTESTATION_FAILURE_EVENT)
                && e.fields.get("task_id") == Some(&id)
        })
        .cloned()
        .collect()
}

fn sorted(mut peers: Vec<PeerId>) -> Vec<PeerId> {
    peers.sort();
    peers
}

/// Two colluding workers return the same wrong bytes, so
/// `Deterministic { replicas: 2 }` accepts them. The forced spot-check
/// (p = 1) re-runs the task on the submitter's own kernel — the only
/// executor that ran no replica — sees another BLAKE3, and downranks both
/// liars for `Deterministic` (only): a `SpotCheckAttestationFailure` event,
/// the `mismatch` counter and an audit record. The result the caller already
/// has is not changed: the check is detective, not preventive.
#[tokio::test(flavor = "multi_thread")]
async fn a_spot_check_catches_colluding_replicas_and_downranks_them() {
    let trace = captured();
    let publisher = IdentityKeyPair::generate();
    let mut submitter = Node::start(&publisher).await;
    let plugin = submitter.load(&publisher, "hello", &hello_pong()).await;
    let mut local_bus = submitter.kernel.bus().subscribe();
    let liars = colluders(&publisher, b"Hello, liar!").await;
    let registry = Registry::new();
    let dispatcher = spot_checked_dispatcher(
        &submitter,
        &[(&liars[0], 0.0), (&liars[1], 0.0)],
        ALWAYS,
        &registry,
    );

    let t = task(
        plugin,
        b"world",
        IntegrityPolicy::Deterministic { replicas: 2 },
    );
    let task_id = t.id;
    let result = deadline("colluding replicas", dispatcher.dispatch_one_shot(t))
        .await
        .expect("the colluding pair is a hash majority");
    // Detective, not preventive: the caller got the accepted (wrong) output.
    assert_eq!(result.output, b"Hello, liar!");
    assert_eq!(
        sorted(result.replicas.iter().map(|r| r.peer).collect()),
        sorted(liars.iter().map(|l| l.peer_id).collect()),
    );
    let handle = result
        .spot_check
        .handle()
        .expect("p = 1: every accepted Deterministic task is spot-checked")
        .clone();
    let record = deadline("spot-check verdict", handle.outcome())
        .await
        .expect("the spot-check finishes");

    assert_eq!(record.task_id, task_id);
    assert_eq!(record.checker, submitter.peer_id, "no other worker is free");
    assert!(!record.checker_remote);
    assert_eq!(
        record.accepted_blake3,
        *blake3::hash(b"Hello, liar!").as_bytes()
    );
    assert_eq!(
        record.rerun_blake3,
        Some(*blake3::hash(b"Hello, world!").as_bytes())
    );
    match &record.verdict {
        SpotCheckVerdict::Mismatch(e) => {
            assert!(e.to_string().contains("ENTANGLE-E0319"), "{e}");
        }
        other => panic!("expected an attestation failure, got {other:?}"),
    }
    let liar_ids = sorted(liars.iter().map(|l| l.peer_id).collect());
    assert_eq!(sorted(record.implicated.clone()), liar_ids);
    assert_eq!(sorted(record.penalised.clone()), liar_ids);

    let rep = dispatcher.verifier().reputation();
    for liar in &liars {
        let kind = PolicyKind::Deterministic;
        assert!(rep.get(&liar.peer_id, kind) < INITIAL_SCORE);
        let rec = rep.record(&liar.peer_id, kind);
        assert_eq!(
            (rec.correct, rec.total),
            (1, 2),
            "credited when accepted, then downranked by the spot-check"
        );
        assert_eq!(
            rep.get(&liar.peer_id, PolicyKind::SemanticEquivalent),
            INITIAL_SCORE,
            "reputation is per policy variant"
        );
    }
    // The re-run happened here, exactly once.
    assert_eq!(activations(&drain(&mut local_bus).await), 1);

    let events = attestation_failures(&trace, task_id);
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(
        events[0]
            .fields
            .get("error")
            .is_some_and(|e| e.contains("ENTANGLE-E0319")),
        "{events:?}"
    );
    assert_eq!(
        registry.value(
            names::SPOT_CHECKS,
            &[("policy", "deterministic"), ("outcome", "mismatch")]
        ),
        Some(1.0)
    );
    let spot = dispatcher.spot_checks().expect("configured");
    assert_eq!(spot.stats().mismatched, 1);
    assert!(spot.recent().iter().any(|r| r.task_id == task_id));
}

/// `SemanticEquivalent`: two colluders agree (identical bytes) on a wrong
/// answer. The spot-check runs on a third, honest worker — ranked below the
/// replica targets and not one of them — and the submitter's metric puts
/// its output far from the accepted one: both colluders lose
/// `SemanticEquivalent` standing; the honest checker's standing is
/// untouched.
#[tokio::test(flavor = "multi_thread")]
async fn a_semantic_spot_check_on_another_worker_downranks_the_agreeing_liars() {
    let trace = captured();
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let liars = colluders(&publisher, b"Something else entirely, said with confidence").await;
    let mut honest = Node::start(&publisher).await;
    let plugin = honest.load(&publisher, "hello", &hello_pong()).await;
    honest.serve_for(submitter.peer_id);
    let mut honest_bus = honest.kernel.bus().subscribe();
    let registry = Registry::new();
    let dispatcher = spot_checked_dispatcher(
        &submitter,
        &[(&liars[0], 0.0), (&liars[1], 0.0), (&honest, 0.9)],
        ALWAYS,
        &registry,
    );
    let (metric, _pkg) = load_bleu(&dispatcher, &publisher);
    let policy = IntegrityPolicy::SemanticEquivalent {
        replicas: 2,
        quorum: 1,
        metric: metric.clone(),
        threshold: 0.25,
    };

    let t = task(plugin, b"world", policy);
    let task_id = t.id;
    let result = deadline("semantic colluders", dispatcher.dispatch_one_shot(t))
        .await
        .expect("the colluding pair agrees with itself");
    assert_eq!(
        result.output,
        b"Something else entirely, said with confidence"
    );
    assert!(result.replicas.iter().all(|r| r.peer != honest.peer_id));
    let record = deadline(
        "spot-check verdict",
        result.spot_check.handle().expect("scheduled").outcome(),
    )
    .await
    .expect("the spot-check finishes");

    assert_eq!(record.checker, honest.peer_id);
    assert!(record.checker_remote);
    let distance = record.distance.expect("the metric compared the re-run");
    assert!(distance >= 0.25, "{distance}");
    assert!(
        matches!(record.verdict, SpotCheckVerdict::Mismatch(_)),
        "{:?}",
        record.verdict
    );
    let liar_ids = sorted(liars.iter().map(|l| l.peer_id).collect());
    assert_eq!(sorted(record.penalised.clone()), liar_ids);
    let rep = dispatcher.verifier().reputation();
    for liar in &liars {
        assert!(rep.get(&liar.peer_id, PolicyKind::SemanticEquivalent) < INITIAL_SCORE);
        assert_eq!(
            rep.get(&liar.peer_id, PolicyKind::Deterministic),
            INITIAL_SCORE
        );
    }
    assert_eq!(
        rep.record(&honest.peer_id, PolicyKind::SemanticEquivalent)
            .total,
        0,
        "the checker is neither credited nor blamed"
    );
    // One metric instantiation for the replica pair, one for the re-run —
    // both on the submitter.
    assert_eq!(dispatcher.verifier().metrics().instantiations(&metric), 2);
    assert_eq!(activations(&drain(&mut honest_bus).await), 1);
    assert_eq!(attestation_failures(&trace, task_id).len(), 1);
    assert_eq!(
        registry.value(
            names::SPOT_CHECKS,
            &[("policy", "semantic-equivalent"), ("outcome", "mismatch")]
        ),
        Some(1.0)
    );
}

/// Honest replicas pass their spot-checks: the re-run reproduces the
/// accepted output, nobody is penalised, no attestation event fires. A
/// byte-identical `SemanticEquivalent` re-run needs no metric. Exempt tasks
/// are never re-run: a `None` policy, and a task whose accepted output this
/// node's own kernel already produced.
#[tokio::test(flavor = "multi_thread")]
async fn spot_checks_of_honest_replicas_confirm_and_penalise_nobody() {
    let trace = captured();
    let publisher = IdentityKeyPair::generate();
    let mut submitter = Node::start(&publisher).await;
    let plugin = submitter.load(&publisher, "hello", &hello_pong()).await;
    let mut workers = Vec::new();
    for _ in 0..2 {
        let mut w = Node::start(&publisher).await;
        w.load(&publisher, "hello", &hello_pong()).await;
        w.serve_for(submitter.peer_id);
        workers.push(w);
    }
    let registry = Registry::new();
    let dispatcher = spot_checked_dispatcher(
        &submitter,
        &[(&workers[0], 0.0), (&workers[1], 0.0)],
        ALWAYS,
        &registry,
    );
    let (metric, _pkg) = load_bleu(&dispatcher, &publisher);

    // Deterministic: re-run on the submitter, byte-identical.
    let t = task(
        plugin.clone(),
        b"world",
        IntegrityPolicy::Deterministic { replicas: 2 },
    );
    let task_id = t.id;
    let result = deadline("honest deterministic", dispatcher.dispatch_one_shot(t))
        .await
        .expect("accepted");
    let record = deadline(
        "verdict",
        result.spot_check.handle().expect("scheduled").outcome(),
    )
    .await
    .expect("finishes");
    assert!(
        matches!(record.verdict, SpotCheckVerdict::Confirmed),
        "{:?}",
        record.verdict
    );
    assert_eq!(record.rerun_blake3, Some(record.accepted_blake3));
    assert!(record.penalised.is_empty());

    // SemanticEquivalent: identical bytes, so no metric is needed.
    let policy = IntegrityPolicy::SemanticEquivalent {
        replicas: 2,
        quorum: 1,
        metric: metric.clone(),
        threshold: 0.25,
    };
    let result = deadline(
        "honest semantic",
        dispatcher.dispatch_one_shot(task(plugin.clone(), b"world", policy)),
    )
    .await
    .expect("accepted");
    let record = deadline(
        "verdict",
        result.spot_check.handle().expect("scheduled").outcome(),
    )
    .await
    .expect("finishes");
    assert!(matches!(record.verdict, SpotCheckVerdict::Confirmed));
    assert_eq!(record.distance, None, "identical bytes need no metric");
    assert_eq!(
        dispatcher.verifier().metrics().instantiations(&metric),
        1,
        "only the replica pair was compared"
    );

    let rep = dispatcher.verifier().reputation();
    for w in &workers {
        for kind in [PolicyKind::Deterministic, PolicyKind::SemanticEquivalent] {
            assert_eq!(rep.get(&w.peer_id, kind), INITIAL_SCORE);
            let rec = rep.record(&w.peer_id, kind);
            assert_eq!((rec.correct, rec.total), (1, 1), "{kind}");
        }
    }
    assert!(attestation_failures(&trace, task_id).is_empty());
    assert_eq!(
        registry.value(
            names::SPOT_CHECKS,
            &[("policy", "deterministic"), ("outcome", "confirmed")]
        ),
        Some(1.0)
    );
    assert_eq!(
        registry.value(
            names::SPOT_CHECKS,
            &[("policy", "semantic-equivalent"), ("outcome", "confirmed")]
        ),
        Some(1.0)
    );

    // Exempt: the spec leaves `None` (and `TrustedExecutor`) alone...
    let result = deadline(
        "policy none",
        dispatcher.dispatch_one_shot(task(plugin.clone(), b"world", IntegrityPolicy::None)),
    )
    .await
    .expect("accepted");
    assert!(
        matches!(result.spot_check, SpotCheck::Exempt(Exemption::Policy)),
        "{:?}",
        result.spot_check
    );
    // ...and an output this node already reproduced has nothing to attest:
    // three replicas, two remote and one on the submitter's own kernel.
    let result = deadline(
        "deterministic x3 with a local replica",
        dispatcher.dispatch_one_shot(task(
            plugin,
            b"world",
            IntegrityPolicy::Deterministic { replicas: 3 },
        )),
    )
    .await
    .expect("accepted");
    assert!(result.replicas.iter().any(|r| !r.remote));
    assert_eq!(result.spot_check.label(), "exempt-reproduced-locally");
    assert_eq!(dispatcher.spot_checks().unwrap().stats().scheduled, 2);
}

/// `probability = 0` never re-runs anything, however often the colluders
/// win: no penalty, no execution on the would-be checker.
#[tokio::test(flavor = "multi_thread")]
async fn spot_checks_never_run_at_probability_zero() {
    let publisher = IdentityKeyPair::generate();
    let mut submitter = Node::start(&publisher).await;
    let plugin = submitter.load(&publisher, "hello", &hello_pong()).await;
    let mut local_bus = submitter.kernel.bus().subscribe();
    let liars = colluders(&publisher, b"Hello, liar!").await;
    let registry = Registry::new();
    let dispatcher = spot_checked_dispatcher(
        &submitter,
        &[(&liars[0], 0.0), (&liars[1], 0.0)],
        SpotCheckConfig::with_probability(0.0),
        &registry,
    );
    for _ in 0..5 {
        let result = deadline(
            "colluders, p = 0",
            dispatcher.dispatch_one_shot(task(
                plugin.clone(),
                b"world",
                IntegrityPolicy::Deterministic { replicas: 2 },
            )),
        )
        .await
        .expect("accepted");
        assert!(
            matches!(result.spot_check, SpotCheck::Disabled),
            "{:?}",
            result.spot_check
        );
    }
    let rep = dispatcher.verifier().reputation();
    for liar in &liars {
        let rec = rep.record(&liar.peer_id, PolicyKind::Deterministic);
        assert_eq!((rec.correct, rec.total), (5, 5));
    }
    assert!(
        drain_for(&mut local_bus, QUIET_NEGATIVE).await.is_empty(),
        "nothing was re-run on the submitter"
    );
    assert_eq!(
        dispatcher.spot_checks().unwrap().stats(),
        Default::default()
    );
    assert_eq!(dispatcher.spot_checks().unwrap().in_flight(), 0);
}

/// Spot-checks are bounded: with `max_concurrent = 1` and the one running
/// check held on a slow executor, the next sampled task is skipped and
/// counted, not queued. Releasing the executor lets the first check finish.
#[tokio::test(flavor = "multi_thread")]
async fn a_saturated_spot_checker_skips_and_counts() {
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let producers = colluders(&publisher, b"Hello, world!").await;
    let (open, gate) = tokio::sync::watch::channel(false);
    let checker = Node::start(&publisher).await;
    checker.serve_rogue_gated(gate, |req| {
        RemoteTaskResponse::ok(b"Hello, world!".to_vec(), req.policy_hash)
    });
    let plugin: PluginId = format!("{}/hello@0.1.0", publisher.fingerprint_hex())
        .parse()
        .unwrap();
    let registry = Registry::new();
    let dispatcher = spot_checked_dispatcher(
        &submitter,
        &[(&producers[0], 0.0), (&producers[1], 0.0), (&checker, 0.9)],
        SpotCheckConfig {
            probability: 1.0,
            max_concurrent: 1,
        },
        &registry,
    );
    let det = || {
        task(
            plugin.clone(),
            b"world",
            IntegrityPolicy::Deterministic { replicas: 2 },
        )
    };

    let first = deadline("first", dispatcher.dispatch_one_shot(det()))
        .await
        .expect("accepted");
    let held = first
        .spot_check
        .handle()
        .expect("the first check takes the only slot")
        .clone();
    let spot = dispatcher.spot_checks().unwrap();
    assert_eq!(spot.in_flight(), 1);
    let _ = registry.render();
    assert_eq!(registry.value(names::SPOT_CHECKS_INFLIGHT, &[]), Some(1.0));

    let second = deadline("second", dispatcher.dispatch_one_shot(det()))
        .await
        .expect("accepted");
    assert!(
        matches!(second.spot_check, SpotCheck::Skipped(SkipReason::Saturated)),
        "{:?}",
        second.spot_check
    );
    assert_eq!(second.spot_check.label(), "skipped-saturated");
    assert_eq!(
        registry.value(
            names::SPOT_CHECKS,
            &[
                ("policy", "deterministic"),
                ("outcome", "skipped_saturated")
            ]
        ),
        Some(1.0)
    );
    assert_eq!(spot.stats().skipped_saturated, 1);
    assert!(held.try_outcome().is_none(), "still held on the checker");

    open.send_replace(true);
    let record = deadline("released check", held.outcome())
        .await
        .expect("finishes once the checker answers");
    assert_eq!(record.checker, checker.peer_id);
    assert!(matches!(record.verdict, SpotCheckVerdict::Confirmed));
    assert_eq!(spot.in_flight(), 0);
    let stats = spot.stats();
    assert_eq!(
        (stats.scheduled, stats.confirmed, stats.skipped_saturated),
        (1, 1, 1)
    );
}

/// A worker that answers every task frame with `bytes`, echoing the policy
/// hash it was sent: honest-looking, executing nothing.
fn answers(node: &Node, bytes: &'static [u8]) {
    node.serve_rogue(move |req| RemoteTaskResponse::ok(bytes.to_vec(), req.policy_hash));
}

/// A plugin id no test node loads: the workers that receive it are rogue
/// servers that answer without executing anything.
fn unloaded_plugin(publisher: &IdentityKeyPair) -> PluginId {
    format!("{}/hello@0.1.0", publisher.fingerprint_hex())
        .parse()
        .unwrap()
}

/// The `SemanticEquivalent` spot-check compares the re-run with the
/// accepted output in acceptance's canonical pair order — lower output
/// BLAKE3 first — so an asymmetric metric gives the distance acceptance
/// would compute for the same two outputs. BLEU's brevity penalty only
/// punishes a short *candidate* (the first operand): a longer honest re-run
/// whose hash sorts first is within the threshold in canonical order and
/// outside it the other way round, and must be confirmed, not flagged.
#[tokio::test(flavor = "multi_thread")]
async fn a_semantic_spot_check_compares_in_the_canonical_pair_order() {
    const ACCEPTED: &[u8] = b"the cat sat on the mat";
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let producers = [Node::start(&publisher).await, Node::start(&publisher).await];
    let checker = Node::start(&publisher).await;
    let registry = Registry::new();
    let dispatcher = spot_checked_dispatcher(
        &submitter,
        &[(&producers[0], 0.0), (&producers[1], 0.0), (&checker, 0.9)],
        ALWAYS,
        &registry,
    );
    let (metric, _pkg) = load_bleu(&dispatcher, &publisher);

    // A longer re-run whose BLAKE3 sorts before the accepted output's. Its
    // last token matches nothing in the accepted output, so the distances
    // do not depend on which variant is picked.
    let accepted_hash = *blake3::hash(ACCEPTED).as_bytes();
    let rerun: &'static [u8] = (0..256)
        .map(|i| format!("the cat sat on the mat this morning again{i}").into_bytes())
        .find(|c| *blake3::hash(c).as_bytes() < accepted_hash)
        .expect("one of 256 variants hashes below the accepted output")
        .leak();
    let metrics = dispatcher.verifier().metrics();
    let canonical = metrics.compare(&metric, rerun, ACCEPTED).await.unwrap();
    let reversed = metrics.compare(&metric, ACCEPTED, rerun).await.unwrap();
    assert!(canonical < reversed, "{canonical} vs {reversed}");
    let threshold = (canonical + reversed) / 2.0;

    for p in &producers {
        answers(p, ACCEPTED);
    }
    answers(&checker, rerun);
    let policy = IntegrityPolicy::SemanticEquivalent {
        replicas: 2,
        quorum: 1,
        metric: metric.clone(),
        threshold,
    };
    let result = deadline(
        "semantic task",
        dispatcher.dispatch_one_shot(task(unloaded_plugin(&publisher), b"world", policy)),
    )
    .await
    .expect("the two producers agree");
    assert_eq!(result.output, ACCEPTED);
    let record = deadline(
        "spot-check verdict",
        result.spot_check.handle().expect("scheduled").outcome(),
    )
    .await
    .expect("the spot-check finishes");
    assert_eq!(record.checker, checker.peer_id);
    assert_eq!(
        record.distance,
        Some(canonical),
        "the distance acceptance would compute"
    );
    assert!(
        matches!(record.verdict, SpotCheckVerdict::Confirmed),
        "{:?}",
        record.verdict
    );
    assert!(record.penalised.is_empty(), "{:?}", record.penalised);
    let rep = dispatcher.verifier().reputation();
    for p in &producers {
        assert_eq!(
            rep.get(&p.peer_id, PolicyKind::SemanticEquivalent),
            INITIAL_SCORE
        );
    }
}

/// This node's own kernel ran one replica and was outvoted by two
/// colluders returning the same lie. Its output, already in hand, is the
/// spot-check re-run — the trusted kernel contradicts the accepted output —
/// so the colluders behind it lose reputation, even though no other
/// executor is free. Nothing is executed a second time.
#[tokio::test(flavor = "multi_thread")]
async fn an_outvoted_local_replica_is_the_spot_check_of_the_majority() {
    let publisher = IdentityKeyPair::generate();
    let mut submitter = Node::start(&publisher).await;
    let plugin = submitter.load(&publisher, "hello", &hello_pong()).await;
    let mut local_bus = submitter.kernel.bus().subscribe();
    let liars = colluders(&publisher, b"Hello, liar!").await;
    let registry = Registry::new();
    let dispatcher = spot_checked_dispatcher(
        &submitter,
        &[(&liars[0], 0.0), (&liars[1], 0.0)],
        ALWAYS,
        &registry,
    );

    let t = task(
        plugin,
        b"world",
        IntegrityPolicy::Deterministic { replicas: 3 },
    );
    let result = deadline("outvoted local replica", dispatcher.dispatch_one_shot(t))
        .await
        .expect("the colluders are a hash majority");
    assert_eq!(result.output, b"Hello, liar!");
    let local = result
        .replicas
        .iter()
        .find(|r| !r.remote)
        .expect("the third replica ran on the submitter");
    assert_eq!(local.status, ReplicaStatus::Disagreed);
    let record = deadline(
        "spot-check verdict",
        result
            .spot_check
            .handle()
            .expect("scheduled: the outvoted local replica is the re-run")
            .outcome(),
    )
    .await
    .expect("the spot-check finishes");
    assert_eq!(record.checker, submitter.peer_id);
    assert!(!record.checker_remote);
    assert!(record.reused_replica, "no second execution was needed");
    assert_eq!(
        record.rerun_blake3,
        Some(*blake3::hash(b"Hello, world!").as_bytes())
    );
    assert!(
        matches!(record.verdict, SpotCheckVerdict::Mismatch(_)),
        "{:?}",
        record.verdict
    );
    let liar_ids = sorted(liars.iter().map(|l| l.peer_id).collect());
    assert_eq!(sorted(record.penalised.clone()), liar_ids);
    let rep = dispatcher.verifier().reputation();
    for liar in &liars {
        let rec = rep.record(&liar.peer_id, PolicyKind::Deterministic);
        assert_eq!(
            (rec.correct, rec.total),
            (1, 2),
            "credited by the majority, then downranked by the trusted kernel's output"
        );
    }
    assert_eq!(
        activations(&drain(&mut local_bus).await),
        1,
        "the replica was the only execution here"
    );
}

/// A checker that cannot run the task does not end the spot-check: the
/// next eligible executor re-runs it. Workers do not advertise which plugins
/// they hold, so a live worker without the plugin is the ordinary case —
/// here it ranks better than the one that has it, yet every sampled task is
/// still attested.
#[tokio::test(flavor = "multi_thread")]
async fn a_spot_check_moves_on_when_its_checker_cannot_run_the_task() {
    let publisher = IdentityKeyPair::generate();
    let submitter = Node::start(&publisher).await;
    let mut producer = Node::start(&publisher).await;
    let plugin = producer.load(&publisher, "hello", &hello_pong()).await;
    producer.serve_for(submitter.peer_id);
    let without = Node::start(&publisher).await;
    without.serve_for(submitter.peer_id);
    let mut with = Node::start(&publisher).await;
    with.load(&publisher, "hello", &hello_pong()).await;
    with.serve_for(submitter.peer_id);
    let registry = Registry::new();
    let dispatcher = spot_checked_dispatcher(
        &submitter,
        &[(&producer, 0.0), (&without, 0.5), (&with, 0.9)],
        ALWAYS,
        &registry,
    );

    for round in 0..3 {
        let result = deadline(
            "deterministic task",
            dispatcher.dispatch_one_shot(task(
                plugin.clone(),
                b"world",
                IntegrityPolicy::Deterministic { replicas: 1 },
            )),
        )
        .await
        .expect("accepted");
        assert_eq!(result.replicas[0].peer, producer.peer_id);
        let record = deadline(
            "spot-check verdict",
            result.spot_check.handle().expect("scheduled").outcome(),
        )
        .await
        .expect("the spot-check finishes");
        assert!(
            matches!(record.verdict, SpotCheckVerdict::Confirmed),
            "round {round}: {:?}",
            record.verdict
        );
        assert_eq!(record.checker, with.peer_id, "round {round}");
        assert!(
            record
                .unavailable
                .iter()
                .all(|(peer, _)| *peer == without.peer_id),
            "round {round}: {:?}",
            record.unavailable
        );
        assert!(record.penalised.is_empty(), "{:?}", record.penalised);
    }
    assert_eq!(dispatcher.spot_checks().unwrap().stats().inconclusive, 0);
}
