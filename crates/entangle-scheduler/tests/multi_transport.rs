//! The scheduler over more than one transport (spec §6.1, §6.1.1, §6.7),
//! with real transports on loopback.
//!
//! Each worker node runs both a `mesh.iroh` endpoint (`entangle/scheduler/1`
//! plus `entangle/stream/1`) and a `mesh.tailscale` listener on 127.0.0.1
//! serving the same two protocols by sub-protocol selection, behind one
//! task server and one stream server. The submitter learns the worker's
//! tailnet address the way the daemon does — a discovery round over an
//! injected `tailscale status` listing 127.0.0.1 — and its tailnet liveness
//! from an injected watch channel, so "the tailnet is active / stopped" is
//! under the test's control.
//!
//! Covered: a one-shot task and a `stream-lines` stream executed over the
//! tailnet; the §6.1 order when a peer is known on both transports; the
//! tailnet candidate skipped while the tailnet is not active; fallback to
//! the next candidate on a connect failure; no retry of an application
//! error on another transport; `[mesh] preferred` and per-peer overrides;
//! the allowlist gate refusing an unlisted peer on the tailnet path before
//! anything it sent is decoded; `traceparent` propagation and the
//! `transport` span attribute and metric label.

use std::sync::{Arc, Once};
use std::time::Duration;

use entangle_mesh_iroh::{
    IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_SCHEDULER, ALPN_STREAM,
};
use entangle_mesh_tailscale::{
    AclMode, AddressPolicy, LivenessSnapshot, MeshTailscale, MeshTailscaleConfig, PeerAllowlist,
    StaticAllowlist as TailnetAllowlist, TailnetState, TailscaleStatus,
};
use entangle_observability::catalog::names;
use entangle_observability::context::{hex_string, AttrValue, SpanLayer, SpanRecord, SpanSink};
use entangle_observability::Registry;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::stream::frame::{decode_frame, Frame};
use entangle_scheduler::stream::{
    verify_transcript, ChunkPoll, Reason, Side, StreamOptions, StreamOutcome,
};
use entangle_scheduler::transport::DialTarget;
use entangle_scheduler::wire::{decode_response, RemoteErrorCode, RemoteOutcome};
use entangle_scheduler::{
    DispatchError, Dispatcher, IrohLink, PeerDirectory, RemoteDispatch, RemoteTaskServer,
    RoutePolicy, StaticAllowlist, StreamServer, TailscaleLink, TransportKind, TransportRouter,
    WorkerInfo, WorkerPool,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{IntegrityPolicy, OneShotTask, PartialResultPolicy, StreamingTask};
use parking_lot::Mutex;
use tokio::sync::watch;
use tracing::Instrument as _;

const DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {DEADLINE:?}"),
    }
}

// ── plugins ─────────────────────────────────────────────────────────────────

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

fn write_package(
    dir: &std::path::Path,
    publisher: &IdentityKeyPair,
    name: &str,
    wasm: &[u8],
) -> PluginId {
    let id = format!("{}/{name}@0.1.0", publisher.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n\
         description = \"multi-transport test plugin\"\n"
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

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{}/{path}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

// ── nodes ───────────────────────────────────────────────────────────────────

fn iroh_config() -> MeshIrohConfig {
    MeshIrohConfig {
        alpn: ALPN_SCHEDULER.to_vec(),
        extra_alpns: vec![ALPN_STREAM.to_vec()],
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        ..MeshIrohConfig::loopback()
    }
}

fn tailnet_config(acl: AclMode, allow: &[PeerId]) -> MeshTailscaleConfig {
    let allowlist: Arc<dyn PeerAllowlist> = Arc::new(TailnetAllowlist::new(allow.iter().copied()));
    MeshTailscaleConfig {
        acl_mode: acl,
        allowlist: Some(allowlist),
        port: 0,
        bind_ip: [127, 0, 0, 1].into(),
        // Loopback is not a tailnet address.
        address_policy: AddressPolicy::Any,
        max_frame_bytes: entangle_mesh_iroh::MAX_FRAME_BYTES,
        handshake_timeout: Duration::from_secs(10),
        request_timeout: Duration::from_secs(10),
        ..MeshTailscaleConfig::default()
    }
}

fn peer_of(key: &IdentityKeyPair) -> PeerId {
    PeerId::from_public_key_bytes(key.public().as_bytes())
}

/// A worker: both transports, one task server and one stream server on both.
struct Worker {
    key: IdentityKeyPair,
    peer_id: PeerId,
    iroh: Arc<MeshIroh>,
    tailnet: MeshTailscale,
    /// The task server's metrics (`entangle_remote_serve_total`).
    served: Registry,
    hello: PluginId,
    lines: PluginId,
    _dirs: Vec<tempfile::TempDir>,
}

impl Worker {
    /// `allowed`: who may run work (the scheduler allowlist). `acl`: the
    /// tailnet transport's own gate, whose allowlist is `allowed` too.
    async fn start(allowed: &[PeerId], acl: AclMode) -> Self {
        let publisher = IdentityKeyPair::generate();
        let kernel =
            Arc::new(Kernel::new(KernelConfig::default(), keyring_for(&publisher)).unwrap());
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let hello = write_package(
            a.path(),
            &publisher,
            "hello-pong",
            &fixture("../entangle-host/tests/fixtures/hello-pong.wasm"),
        );
        let lines = write_package(
            b.path(),
            &publisher,
            "stream-lines",
            &fixture("tests/fixtures/stream-lines.wasm"),
        );
        kernel.load_plugin_from_dir(a.path()).await.unwrap();
        kernel.load_plugin_from_dir(b.path()).await.unwrap();

        let key = IdentityKeyPair::generate();
        let peer_id = peer_of(&key);
        let iroh = Arc::new(MeshIroh::start(iroh_config(), &key).await.unwrap());
        let tailnet = MeshTailscale::start(&key, tailnet_config(acl, allowed))
            .await
            .unwrap();
        let allow: StaticAllowlist = allowed.iter().copied().collect();
        let allow = Arc::new(allow);
        let served = Registry::new();
        let tasks = Arc::new(
            RemoteTaskServer::new(Arc::clone(&kernel), allow.clone(), peer_id)
                .with_metrics(served.clone()),
        );
        let streams = Arc::new(StreamServer::new(kernel, allow, key.clone()));
        tokio::spawn(entangle_scheduler::serve_tasks(
            Arc::clone(&iroh),
            Arc::clone(&tasks),
        ));
        tokio::spawn(entangle_scheduler::serve_streams(
            Arc::clone(&iroh),
            Arc::clone(&streams),
        ));
        tokio::spawn(entangle_scheduler::serve_tailscale(
            tailnet.clone(),
            Some(tasks),
            Some(streams),
        ));
        Self {
            key,
            peer_id,
            iroh,
            tailnet,
            served,
            hello,
            lines,
            _dirs: vec![a, b],
        }
    }

    fn iroh_address(&self) -> IrohPeer {
        let addr = self
            .iroh
            .local_addrs()
            .into_iter()
            .find(|a| a.ip().is_loopback())
            .unwrap();
        IrohPeer::new(self.iroh.local_public_key(), addr)
    }

    fn served(&self, outcome: &str, transport: &str) -> f64 {
        self.served
            .value(
                names::REMOTE_SERVE,
                &[("outcome", outcome), ("transport", transport)],
            )
            .unwrap_or(0.0)
    }
}

/// The submitting node: its own identity on both transports.
struct Submitter {
    key: IdentityKeyPair,
    peer_id: PeerId,
    iroh: Arc<MeshIroh>,
    tailnet: MeshTailscale,
    liveness: watch::Sender<LivenessSnapshot>,
}

fn snapshot(state: TailnetState) -> LivenessSnapshot {
    LivenessSnapshot {
        state: Some(state),
        since: None,
        transitions: 1,
    }
}

impl Submitter {
    async fn start() -> Self {
        let key = IdentityKeyPair::generate();
        let iroh = Arc::new(MeshIroh::start(iroh_config(), &key).await.unwrap());
        let tailnet = MeshTailscale::start(&key, tailnet_config(AclMode::EntangleOnTop, &[]))
            .await
            .unwrap();
        let (liveness, _) = watch::channel(snapshot(TailnetState::Active));
        Self {
            peer_id: peer_of(&key),
            key,
            iroh,
            tailnet,
            liveness,
        }
    }

    /// A discovery round, as the daemon runs it: `tailscale status` lists
    /// one online peer at 127.0.0.1, probed on `worker`'s port.
    async fn discover(&self, worker: &Worker) {
        let json = r#"{"BackendState":"Running","Self":{"Online":true},
          "Peer":{"w":{"Online":true,"DNSName":"w.tail.ts.net.","TailscaleIPs":["127.0.0.1"]}}}"#;
        let status = TailscaleStatus::parse(json).unwrap();
        let found = self
            .tailnet
            .discover_on_port(&status, worker.tailnet.local_addr().port())
            .await;
        assert_eq!(
            found.iter().map(|p| p.peer_id).collect::<Vec<_>>(),
            [worker.peer_id],
            "discovery finds the worker on the tailnet"
        );
    }

    fn tailnet_link(&self) -> Arc<TailscaleLink> {
        Arc::new(TailscaleLink::new(
            self.tailnet.clone(),
            self.liveness.subscribe(),
        ))
    }

    fn iroh_link(&self, worker: &Worker) -> Arc<IrohLink> {
        let book = PeerDirectory::new();
        book.insert(worker.iroh_address());
        Arc::new(
            IrohLink::new(
                Arc::clone(&self.iroh) as Arc<dyn MeshTransport>,
                Arc::new(book),
            )
            .with_streams(Arc::clone(&self.iroh)),
        )
    }

    /// A router knowing `worker` on both transports.
    fn router(&self, worker: &Worker, policy: RoutePolicy) -> Arc<TransportRouter> {
        Arc::new(
            TransportRouter::new(self.peer_id)
                .with_link(self.iroh_link(worker))
                .with_link(self.tailnet_link())
                .with_policy(policy),
        )
    }

    fn set_tailnet(&self, state: TailnetState) {
        self.liveness.send_replace(snapshot(state));
    }
}

fn one_shot(plugin: &PluginId, input: &[u8]) -> OneShotTask {
    let mut task = OneShotTask::with_defaults(plugin.clone(), input.to_vec());
    task.timeout_ms = 10_000;
    task
}

async fn run(
    client: &RemoteDispatch,
    task: &OneShotTask,
    peer: PeerId,
) -> (Result<Vec<u8>, DispatchError>, Option<TransportKind>) {
    let envelope = entangle_scheduler::PolicyEnvelope::seal(&task.integrity).unwrap();
    let (result, kind) = deadline(
        "dispatch",
        client.dispatch_sealed_routed(task, peer, &envelope),
    )
    .await;
    (result.map(|r| r.output), kind)
}

// ── one-shot and stream over the tailnet ───────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_one_shot_task_runs_over_the_tailscale_transport() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;

    // The tailnet is the only transport A has.
    let router = Arc::new(TransportRouter::new(a.peer_id).with_link(a.tailnet_link()));
    let pool = WorkerPool::new();
    pool.upsert(WorkerInfo {
        peer_id: b.peer_id,
        display_name: "b".into(),
        cpu_cores: 16.0,
        memory_bytes: 64 << 30,
        gpu: None,
        npu: None,
        network_bandwidth_bps: 1_000_000_000,
        rtt_ms: 1,
        load: 0.0,
        cost: 1.0,
    });
    let metrics = Registry::new();
    let a_kernel = Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap());
    let dispatcher = Dispatcher::new(pool, a_kernel, a.peer_id)
        .with_strict_remote(true)
        .with_remote(Arc::new(RemoteDispatch::with_router(Arc::clone(&router))))
        .with_metrics(metrics.clone());
    let result = deadline(
        "dispatch over the tailnet",
        dispatcher.dispatch_one_shot(one_shot(&b.hello, b"tailnet")),
    )
    .await
    .expect("the task ran on B over mesh.tailscale");
    assert_eq!(result.output, b"Hello, tailnet!");
    assert_eq!(result.replicas[0].peer, b.peer_id);

    assert_eq!(
        router.last_route(&b.peer_id).map(|r| r.transport),
        Some(TransportKind::Tailscale),
        "the chosen transport is recorded for the peer"
    );
    assert_eq!(
        metrics.value(
            names::REMOTE_DISPATCH,
            &[("outcome", "ok"), ("transport", "tailscale")]
        ),
        Some(1.0)
    );
    assert_eq!(b.served("ok", "tailscale"), 1.0);
    assert_eq!(b.served("ok", "iroh"), 0.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_lines_stream_runs_over_the_tailscale_transport() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;
    let metrics = Registry::new();
    let router = TransportRouter::new(a.peer_id)
        .with_link(a.tailnet_link())
        .with_metrics(metrics.clone());

    let mut task = StreamingTask::with_defaults(b.lines.clone(), b"alpha\nbeta\ngamma\n".to_vec());
    task.integrity = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![b.peer_id],
    };
    task.partial_result = PartialResultPolicy::KeepSigned;
    let mut handle = deadline(
        "open a stream over the tailnet",
        router.open_stream(b.peer_id, &task, StreamOptions::default()),
    )
    .await
    .expect("stream opens over mesh.tailscale");
    assert_eq!(handle.executor(), b.peer_id);
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
    let report = handle.finish().await;
    assert!(matches!(report.outcome, StreamOutcome::Complete(_)));
    let signed: Vec<_> = chunks.into_iter().map(Into::into).collect();
    let transcript = verify_transcript(
        *b.key.public().as_bytes(),
        *task.id.as_bytes(),
        report.context.policy_hash,
        report.context.request_digest,
        &signed,
    )
    .expect("every chunk verifies against B's key, which the tailnet handshake authenticated");
    assert_eq!(transcript, end.transcript);
    assert_eq!(
        router.last_route(&b.peer_id).map(|r| r.transport),
        Some(TransportKind::Tailscale)
    );
    assert_eq!(
        metrics.value(
            names::REMOTE_STREAM_OPENS,
            &[("outcome", "ok"), ("transport", "tailscale")]
        ),
        Some(1.0)
    );
}

// ── selection ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_on_both_transports_uses_tailscale_first_and_iroh_while_the_tailnet_is_down() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;
    let router = a.router(&b, RoutePolicy::new());
    let client = RemoteDispatch::with_router(Arc::clone(&router));
    let plan: Vec<_> = router
        .plan(&b.peer_id)
        .candidates
        .iter()
        .map(|c| c.transport)
        .collect();
    assert_eq!(plan, [TransportKind::Tailscale, TransportKind::Iroh]);

    let (out, kind) = run(&client, &one_shot(&b.hello, b"one"), b.peer_id).await;
    assert_eq!(out.unwrap(), b"Hello, one!");
    assert_eq!(kind, Some(TransportKind::Tailscale));

    // `tailscale logout`: liveness confirms `stopped`. The tailnet
    // candidate is skipped (not dialled), and iroh carries the task.
    a.set_tailnet(TailnetState::Stopped {
        reason: "NeedsLogin".into(),
    });
    let plan = router.plan(&b.peer_id);
    assert_eq!(plan.candidates.len(), 1);
    assert!(plan
        .skipped
        .iter()
        .any(|s| s.transport == TransportKind::Tailscale && s.reason.contains("NeedsLogin")));
    let (out, kind) = run(&client, &one_shot(&b.hello, b"two"), b.peer_id).await;
    assert_eq!(out.unwrap(), b"Hello, two!");
    assert_eq!(kind, Some(TransportKind::Iroh));
    assert_eq!(
        router.last_route(&b.peer_id).map(|r| r.transport),
        Some(TransportKind::Iroh)
    );
    assert_eq!(
        (b.served("ok", "tailscale"), b.served("ok", "iroh")),
        (1.0, 1.0)
    );

    // A peer reachable only over the tailnet is unreachable meanwhile.
    let tailnet_only = RemoteDispatch::with_router(Arc::new(
        TransportRouter::new(a.peer_id).with_link(a.tailnet_link()),
    ));
    let (out, kind) = run(&tailnet_only, &one_shot(&b.hello, b"three"), b.peer_id).await;
    let err = out.unwrap_err().to_string();
    assert!(
        err.contains("ENTANGLE-E0430") && err.contains("NeedsLogin"),
        "{err}"
    );
    assert_eq!(kind, None, "nothing was dialled");
    assert_eq!(b.served("ok", "tailscale"), 1.0);

    // Back to active: the tailnet is preferred again.
    a.set_tailnet(TailnetState::Active);
    let (_, kind) = run(&client, &one_shot(&b.hello, b"four"), b.peer_id).await;
    assert_eq!(kind, Some(TransportKind::Tailscale));
}

/// `mesh.local`: an mDNS sighting's LAN address, dialled over the iroh
/// endpoint, is the cheapest candidate and goes first (spec §6.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lan_sighting_is_tried_before_the_tailnet_and_the_internet() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;
    let sightings = PeerDirectory::new();
    sightings.insert(b.iroh_address());
    let local = IrohLink::local(
        Arc::clone(&a.iroh) as Arc<dyn MeshTransport>,
        Arc::new(sightings),
    )
    .with_streams(Arc::clone(&a.iroh));
    let router = Arc::new(
        TransportRouter::new(a.peer_id)
            .with_link(a.iroh_link(&b))
            .with_link(a.tailnet_link())
            .with_link(Arc::new(local)),
    );
    let plan: Vec<_> = router
        .plan(&b.peer_id)
        .candidates
        .iter()
        .map(|c| c.transport)
        .collect();
    assert_eq!(
        plan,
        [
            TransportKind::Local,
            TransportKind::Tailscale,
            TransportKind::Iroh
        ]
    );
    let client = RemoteDispatch::with_router(Arc::clone(&router));
    let (out, kind) = run(&client, &one_shot(&b.hello, b"lan"), b.peer_id).await;
    assert_eq!(out.unwrap(), b"Hello, lan!");
    assert_eq!(kind, Some(TransportKind::Local));
    // The worker counts it under the transport that carried it.
    assert_eq!(b.served("ok", "iroh"), 1.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_failure_on_the_first_candidate_falls_back_to_the_next() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;
    // B's tailnet listener goes away after discovery: dialling it is refused.
    b.tailnet.shutdown().await;
    let router = a.router(&b, RoutePolicy::new());
    let client = RemoteDispatch::with_router(Arc::clone(&router));
    let (out, kind) = run(&client, &one_shot(&b.hello, b"fallback"), b.peer_id).await;
    assert_eq!(out.unwrap(), b"Hello, fallback!");
    assert_eq!(kind, Some(TransportKind::Iroh));
    assert_eq!(b.served("ok", "iroh"), 1.0);

    // Streams fall back the same way.
    let mut task = StreamingTask::with_defaults(b.lines.clone(), b"x\n".to_vec());
    task.integrity = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![b.peer_id],
    };
    let mut handle = deadline(
        "open_stream with fallback",
        router.open_stream(b.peer_id, &task, StreamOptions::default()),
    )
    .await
    .expect("iroh carries the stream");
    handle.finish_input().await.unwrap();
    let result = deadline("collect", handle.collect()).await;
    assert!(
        matches!(result.outcome, StreamOutcome::Complete(_)),
        "{:?}",
        result.outcome
    );

    // A peer rejected by the tailnet transport's ACL (not on its allowlist)
    // is a setup failure too: nothing was sent, so iroh is tried — where
    // the scheduler's own allowlist answers.
    let c = Submitter::start().await;
    let d = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    c.discover(&d).await;
    let (out, kind) = run(
        &RemoteDispatch::with_router(c.router(&d, RoutePolicy::new())),
        &one_shot(&d.hello, b"c"),
        d.peer_id,
    )
    .await;
    assert_eq!(kind, Some(TransportKind::Iroh));
    assert!(
        matches!(
            out,
            Err(DispatchError::RemoteRejected {
                code: RemoteErrorCode::NotAuthorized,
                ..
            })
        ),
        "{out:?}"
    );
}

/// A `local` candidate whose LAN address never answers (a sighting left
/// behind when the peer left the LAN, or a spoofed one) gives way to the
/// tailnet inside the task's budget: it does not hold the dispatch for the
/// endpoint's whole connect timeout, longer than a short task's budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_lan_candidate_gives_way_to_the_tailnet_within_the_budget() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;
    // The daemon's endpoint keeps iroh's default connect timeout (15 s). A
    // fresh one, so no path to B is cached from an earlier connection.
    let lan = MeshIroh::start(
        MeshIrohConfig {
            connect_timeout: entangle_mesh_iroh::DEFAULT_CONNECT_TIMEOUT,
            ..iroh_config()
        },
        &a.key,
    )
    .await
    .unwrap();
    // Takes datagrams and never answers.
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let sightings = PeerDirectory::new();
    sightings.insert(IrohPeer::new(
        b.iroh.local_public_key(),
        blackhole.local_addr().unwrap(),
    ));
    let local = IrohLink::local(Arc::new(lan) as Arc<dyn MeshTransport>, Arc::new(sightings));
    let router = Arc::new(
        TransportRouter::new(a.peer_id)
            .with_link(Arc::new(local))
            .with_link(a.tailnet_link()),
    );
    let client =
        RemoteDispatch::with_router(Arc::clone(&router)).with_overhead(Duration::from_secs(2));
    let mut task = one_shot(&b.hello, b"lan-gone");
    // A 6 s budget: shorter than the LAN dial's own timeout.
    task.timeout_ms = 4_000;
    let (out, kind) = run(&client, &task, b.peer_id).await;
    assert_eq!(out.unwrap(), b"Hello, lan-gone!");
    assert_eq!(kind, Some(TransportKind::Tailscale));
    assert_eq!(b.served("ok", "tailscale"), 1.0);

    // The next dispatch does not wait on the dead LAN route again.
    let started = std::time::Instant::now();
    let (out, kind) = run(&client, &task, b.peer_id).await;
    assert_eq!(out.unwrap(), b"Hello, lan-gone!");
    assert_eq!(kind, Some(TransportKind::Tailscale));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the second dispatch dialled the silent LAN address first again ({:?})",
        started.elapsed()
    );
    drop(blackhole);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_application_error_from_the_peer_is_not_retried_on_another_transport() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;
    let client = RemoteDispatch::with_router(a.router(&b, RoutePolicy::new()));
    let missing: PluginId = "0123456789abcdef0123456789abcdef/missing@1.0.0"
        .parse()
        .unwrap();
    let (out, kind) = run(&client, &one_shot(&missing, b"x"), b.peer_id).await;
    assert!(
        matches!(
            out,
            Err(DispatchError::RemoteRejected {
                code: RemoteErrorCode::PluginNotLoaded,
                ..
            })
        ),
        "{out:?}"
    );
    assert_eq!(kind, Some(TransportKind::Tailscale));
    assert_eq!(b.served("plugin-not-loaded", "tailscale"), 1.0);
    assert_eq!(
        b.served("plugin-not-loaded", "iroh"),
        0.0,
        "the refusal is final: the task is not sent again over iroh"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preferred_and_per_peer_overrides_choose_the_transport() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;

    // `[mesh] preferred = "iroh"`.
    let preferred = RoutePolicy::new().with_preferred(Some(TransportKind::Iroh));
    let client = RemoteDispatch::with_router(a.router(&b, preferred.clone()));
    let (_, kind) = run(&client, &one_shot(&b.hello, b"p"), b.peer_id).await;
    assert_eq!(kind, Some(TransportKind::Iroh));

    // A per-peer override beats `preferred`.
    let overridden = preferred.with_override(b.peer_id, vec![TransportKind::Tailscale]);
    let router = a.router(&b, overridden);
    let client = RemoteDispatch::with_router(Arc::clone(&router));
    let (_, kind) = run(&client, &one_shot(&b.hello, b"o"), b.peer_id).await;
    assert_eq!(kind, Some(TransportKind::Tailscale));
    // ... and is exact: with the tailnet down there is no fallback to iroh.
    a.set_tailnet(TailnetState::Uninstalled);
    let (out, kind) = run(&client, &one_shot(&b.hello, b"n"), b.peer_id).await;
    assert!(out.unwrap_err().to_string().contains("ENTANGLE-E0430"));
    assert_eq!(kind, None);
    assert_eq!(
        (b.served("ok", "iroh"), b.served("ok", "tailscale")),
        (1.0, 1.0)
    );
}

// ── the allowlist gate on the tailnet path ──────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_allowlist_refuses_an_unlisted_peer_on_the_tailscale_path_before_decoding() {
    let stranger = Submitter::start().await;
    let friend = PeerId::from_public_key_bytes(&[7; 32]);

    // entangle-on-top: the tailnet transport drops the stranger after the
    // handshake, before it can select a protocol or send a frame.
    let b = Worker::start(&[friend], AclMode::EntangleOnTop).await;
    stranger.discover(&b).await;
    let target = stranger.tailnet.candidate(&b.peer_id).unwrap();
    let err = stranger
        .tailnet
        .connect_protocol(&target, ALPN_SCHEDULER)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("rejected us"), "{err}");
    let tailnet_only = RemoteDispatch::with_router(Arc::new(
        TransportRouter::new(stranger.peer_id).with_link(stranger.tailnet_link()),
    ));
    let (out, _) = run(&tailnet_only, &one_shot(&b.hello, b"x"), b.peer_id).await;
    assert!(out.unwrap_err().to_string().contains("ENTANGLE-E0431"));
    assert_eq!(
        b.served.value(
            names::REMOTE_SERVE,
            &[("outcome", "not-authorized"), ("transport", "tailscale")]
        ),
        None,
        "nothing reached the task server"
    );

    // trust-tailnet: the transport admits any authenticated peer, and the
    // scheduler's allowlist refuses it before decoding: a frame that is not
    // even a valid envelope is answered NotAuthorized, not MalformedRequest.
    let open = Worker::start(&[friend], AclMode::TrustTailnet).await;
    stranger.discover(&open).await;
    let target = stranger.tailnet.candidate(&open.peer_id).unwrap();
    let mut conn = stranger
        .tailnet
        .connect_protocol(&target, ALPN_SCHEDULER)
        .await
        .expect("trust-tailnet admits the authenticated stranger");
    let answer = conn
        .request(b"\xff\xfe not a scheduler frame")
        .await
        .unwrap();
    match decode_response(&answer, 0).unwrap().outcome {
        RemoteOutcome::Err { code, .. } => assert_eq!(code, RemoteErrorCode::NotAuthorized),
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert_eq!(open.served("not-authorized", "tailscale"), 1.0);
    assert_eq!(open.served("malformed-request", "tailscale"), 0.0);

    // And a stream is refused before its Open frame is read.
    let conn = stranger
        .tailnet
        .connect_protocol(&target, ALPN_STREAM)
        .await
        .unwrap();
    let (_send, mut recv) = conn.into_stream().unwrap().split();
    let first = deadline("refusal", recv.recv()).await.unwrap().unwrap();
    match decode_frame(&first, Side::Executor).unwrap() {
        Frame::Error { reason, .. } => assert_eq!(reason, Reason::NotAuthorized),
        other => panic!("expected an Error frame, got {}", other.name()),
    }
}

// ── tracing over the tailnet ────────────────────────────────────────────────

#[derive(Default)]
struct Spans(Mutex<Vec<SpanRecord>>);

impl SpanSink for Spans {
    fn emit(&self, span: SpanRecord) {
        self.0.lock().push(span);
    }
}

fn spans() -> &'static Arc<Spans> {
    use tracing_subscriber::prelude::*;
    static SINK: std::sync::OnceLock<Arc<Spans>> = std::sync::OnceLock::new();
    static INIT: Once = Once::new();
    let sink = SINK.get_or_init(|| Arc::new(Spans::default()));
    INIT.call_once(|| {
        use tracing_subscriber::filter::filter_fn;
        let sub = tracing_subscriber::registry().with(
            SpanLayer::new(sink.clone())
                .with_filter(filter_fn(entangle_observability::context::is_exported)),
        );
        tracing::subscriber::set_global_default(sub).expect("this test binary owns the subscriber");
    });
    sink
}

fn span(name: &str, plugin: &str) -> SpanRecord {
    let found: Vec<_> = spans()
        .0
        .lock()
        .iter()
        .filter(|s| s.name == name)
        .filter(|s| {
            s.attributes
                .iter()
                .any(|(k, v)| k == "plugin" && matches!(v, AttrValue::Str(x) if x == plugin))
        })
        .cloned()
        .collect();
    assert_eq!(found.len(), 1, "one {name} span for {plugin}");
    found.into_iter().next().unwrap()
}

fn attr(span: &SpanRecord, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| match v {
            AttrValue::Str(s) => s.clone(),
            other => format!("{other:?}"),
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_one_shot_task_over_the_tailnet_continues_the_submitters_trace() {
    spans();
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;
    let client = RemoteDispatch::with_router(Arc::new(
        TransportRouter::new(a.peer_id).with_link(a.tailnet_link()),
    ));
    let submit = tracing::info_span!(target: "entangle_test", "test.submit");
    let (out, kind) = run(&client, &one_shot(&b.hello, b"trace"), b.peer_id)
        .instrument(submit)
        .await;
    assert_eq!(out.unwrap(), b"Hello, trace!");
    assert_eq!(kind, Some(TransportKind::Tailscale));

    let plugin = b.hello.to_string();
    let worker = span("remote.task.execute", &plugin);
    let client = span("remote.dispatch", &plugin);
    assert_eq!(
        hex_string(&worker.trace_id),
        hex_string(&client.trace_id),
        "the traceparent rode the tailnet frame"
    );
    assert_eq!(worker.parent_span_id, Some(client.span_id));
    assert_eq!(attr(&client, "transport").as_deref(), Some("tailscale"));
    assert_eq!(attr(&worker, "transport").as_deref(), Some("tailscale"));
}

/// `send_control_over` probes one specific path (what `entangle diag mesh
/// --probe` does), whatever the routing policy would pick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_probe_reaches_the_peer_over_the_tailnet_path() {
    let a = Submitter::start().await;
    let b = Worker::start(&[a.peer_id], AclMode::EntangleOnTop).await;
    a.discover(&b).await;
    let target = DialTarget::Tailscale(a.tailnet.candidate(&b.peer_id).unwrap());
    let frame = entangle_scheduler::ControlFrame {
        task_id: [3; 16],
        action: entangle_scheduler::ControlAction::SetPolicy {
            policy: Vec::new(),
            policy_hash: entangle_scheduler::work_unit::hash_canonical(&[]),
        },
    };
    let err = entangle_scheduler::send_control_over(
        a.tailnet_link().as_ref(),
        &target,
        frame,
        Duration::from_secs(10),
    )
    .await
    .unwrap_err();
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
    let _ = (&a.key, &b.key);
}
