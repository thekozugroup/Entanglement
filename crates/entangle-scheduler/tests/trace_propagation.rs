//! Distributed tracing across a remote dispatch (spec §9.6), over real QUIC
//! on loopback.
//!
//! Two nodes live in one process. The submitter dispatches a task inside a
//! span; the worker's `remote.task.execute` span must carry the *same trace
//! id*, with the submitter's `remote.dispatch` span as its parent: the
//! `traceparent` rode in the task frame. Further tests pin that the worker
//! never lets a `traceparent` influence authorization, and that a peer built
//! before the extension existed still interoperates.

use std::sync::{Arc, Once};
use std::time::Duration;

use entangle_mesh_iroh::{IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_SCHEDULER};
use entangle_observability::context::{hex_string, SpanLayer, SpanRecord, SpanSink};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::capability::{CapabilityGate, StaticTokens};
use entangle_scheduler::wire::{
    decode_response, encode_request, encode_response, RemoteErrorCode, RemoteOutcome,
    RemoteRequest, RemoteTaskRequest, RemoteTaskResponse, RequestFrame, TRACE_EXTENSION_TAG,
};
use entangle_scheduler::{
    Dispatcher, PeerDirectory, RemoteDispatch, RemoteTaskServer, StaticAllowlist, WorkerInfo,
    WorkerPool,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::resource::ResourceSpec;
use entangle_types::task::{IntegrityPolicy, OneShotTask};
use parking_lot::Mutex;
use tracing::Instrument as _;
use tracing_subscriber::prelude::*;

const DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {DEADLINE:?}"),
    }
}

// ── span capture (global: spawned server tasks run on other threads) ─────────

#[derive(Default)]
struct Spans(Mutex<Vec<SpanRecord>>);
impl SpanSink for Spans {
    fn emit(&self, span: SpanRecord) {
        self.0.lock().push(span);
    }
}

fn spans() -> &'static Arc<Spans> {
    static SINK: std::sync::OnceLock<Arc<Spans>> = std::sync::OnceLock::new();
    static INIT: Once = Once::new();
    let sink = SINK.get_or_init(|| Arc::new(Spans::default()));
    INIT.call_once(|| {
        // The same filter the daemon installs: only `entangle*` spans, so
        // third-party spans (iroh) are never created.
        use tracing_subscriber::filter::filter_fn;
        use tracing_subscriber::Layer as _;
        let sub = tracing_subscriber::registry().with(
            SpanLayer::new(sink.clone())
                .with_filter(filter_fn(entangle_observability::context::is_exported)),
        );
        tracing::subscriber::set_global_default(sub).expect("this test binary owns the subscriber");
    });
    sink
}

fn find(name: &str, plugin: Option<&str>) -> Vec<SpanRecord> {
    spans()
        .0
        .lock()
        .iter()
        .filter(|s| s.name == name)
        .filter(|s| {
            plugin.is_none_or(|p| {
                s.attributes.iter().any(|(k, v)| {
                    k == "plugin"
                        && matches!(v, entangle_observability::context::AttrValue::Str(x) if x == p)
                })
            })
        })
        .cloned()
        .collect()
}

// ── fixtures (same shape as remote_dispatch.rs) ──────────────────────────────

fn hello_pong_wasm() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong.wasm fixture")
}

fn keyring_for(keypair: &IdentityKeyPair) -> Keyring {
    let pub_key = keypair.public();
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "test-publisher".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

fn write_plugin_package(dir: &std::path::Path, keypair: &IdentityKeyPair, wasm: &[u8]) -> PluginId {
    let id = format!("{}/trace-demo@0.1.0", keypair.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\ndescription = \"trace test\"\n"
    );
    std::fs::write(dir.join("entangle.toml"), manifest.as_bytes()).unwrap();
    std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    let bundle = sign_artifact(wasm, manifest.as_bytes(), keypair);
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap().as_bytes(),
    )
    .unwrap();
    id.parse().unwrap()
}

fn loopback_config() -> MeshIrohConfig {
    MeshIrohConfig {
        alpn: ALPN_SCHEDULER.to_vec(),
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(10),
        ..MeshIrohConfig::loopback()
    }
}

struct Node {
    identity: IdentityKeyPair,
    peer_id: PeerId,
    kernel: Arc<Kernel>,
    transport: Arc<MeshIroh>,
}

impl Node {
    async fn start(publisher: &IdentityKeyPair) -> Self {
        let identity = IdentityKeyPair::generate();
        let kernel =
            Arc::new(Kernel::new(KernelConfig::default(), keyring_for(publisher)).unwrap());
        let transport = Arc::new(MeshIroh::start(loopback_config(), &identity).await.unwrap());
        Self {
            peer_id: transport.local_peer_id(),
            identity,
            kernel,
            transport,
        }
    }

    fn address(&self) -> IrohPeer {
        let addr = self
            .transport
            .local_addrs()
            .into_iter()
            .find(|a| a.ip().is_loopback())
            .unwrap();
        IrohPeer::new(self.transport.local_public_key(), addr)
    }

    fn serve(&self, allowlist: StaticAllowlist) {
        let server = Arc::new(RemoteTaskServer::new(
            Arc::clone(&self.kernel),
            Arc::new(allowlist),
            Arc::new(CapabilityGate::for_identity(&self.identity).unwrap()),
        ));
        tokio::spawn(entangle_scheduler::serve_tasks(
            Arc::clone(&self.transport),
            server,
        ));
    }
}

fn dispatcher_for(local: &Node, remote: &Node) -> Dispatcher {
    dispatcher_with(local, remote, true)
}

/// `local`'s dispatcher to `remote`, holding the token `remote` issued it
/// when `paired` (a peer built before capability tokens issued none).
fn dispatcher_with(local: &Node, remote: &Node, paired: bool) -> Dispatcher {
    let pool = WorkerPool::new();
    pool.upsert(WorkerInfo {
        peer_id: remote.peer_id,
        display_name: "worker".into(),
        cpu_cores: 16.0,
        memory_bytes: 64 << 30,
        gpu: None,
        npu: None,
        network_bandwidth_bps: 1_000_000_000,
        rtt_ms: 1,
        load: 0.0,
        cost: 1.0,
    });
    let directory = PeerDirectory::new();
    directory.insert(remote.address());
    Dispatcher::new(pool, Arc::clone(&local.kernel), local.peer_id)
        .with_strict_remote(true)
        .with_remote(Arc::new(
            RemoteDispatch::new(
                Arc::clone(&local.transport) as Arc<dyn MeshTransport>,
                Arc::new(directory),
            )
            .with_capability_tokens({
                // What pairing leaves `local` holding: the token `remote` minted for it.
                let tokens = StaticTokens::new();
                if paired {
                    tokens.paired_with(&remote.identity, local.peer_id).unwrap();
                }
                Arc::new(tokens)
            }),
        ))
}

fn task_for(plugin: PluginId, input: &[u8]) -> OneShotTask {
    OneShotTask {
        id: uuid::Uuid::new_v4(),
        plugin,
        input: input.to_vec(),
        max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
        max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        resources: ResourceSpec::default(),
        integrity: IntegrityPolicy::None,
        timeout_ms: 10_000,
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

/// The product: a remote execution's span is a child of the submitter's span.
#[tokio::test(flavor = "multi_thread")]
async fn a_remote_dispatch_continues_the_submitters_trace_on_the_worker() {
    spans();
    let publisher = IdentityKeyPair::generate();
    let a = Node::start(&publisher).await;
    let b = Node::start(&publisher).await;
    let dir = tempfile::tempdir().unwrap();
    let plugin = write_plugin_package(dir.path(), &publisher, &hello_pong_wasm());
    b.kernel.load_plugin_from_dir(dir.path()).await.unwrap();
    b.serve(StaticAllowlist::new().allow(a.peer_id));
    let dispatcher = dispatcher_for(&a, &b);

    let submit = tracing::info_span!(target: "entangle_test", "test.submit");
    let result = deadline(
        "dispatch",
        dispatcher
            .dispatch_one_shot(task_for(plugin.clone(), b"trace"))
            .instrument(submit),
    )
    .await
    .expect("remote dispatch");
    assert_eq!(result.output, b"Hello, trace!");
    assert!(!result.replicas[0].peer.to_hex().is_empty());

    // Spans are emitted when they close; the worker's closes before it answers.
    let plugin_s = plugin.to_string();
    let worker = find("remote.task.execute", Some(&plugin_s));
    let client = find("remote.dispatch", Some(&plugin_s));
    let root = find("test.submit", None);
    let all: Vec<_> = spans().0.lock().iter().map(|s| s.name.clone()).collect();
    assert_eq!(
        (worker.len(), client.len(), root.len()),
        (1, 1, 1),
        "{all:?}"
    );
    let (worker, client, root) = (&worker[0], &client[0], &root[0]);

    assert_eq!(
        hex_string(&worker.trace_id),
        hex_string(&root.trace_id),
        "the worker's span must be in the submitter's trace"
    );
    assert_eq!(client.trace_id, root.trace_id);
    assert_eq!(
        worker.parent_span_id,
        Some(client.span_id),
        "the worker span is a child of the submitter's remote.dispatch span"
    );
    // And the submitter side nests: submit -> task.dispatch -> remote.dispatch.
    let dispatch = find("task.dispatch", Some(&plugin_s));
    assert_eq!(dispatch[0].parent_span_id, Some(root.span_id));
    assert_eq!(client.parent_span_id, Some(dispatch[0].span_id));
    // The worker's own kernel span hangs under the worker span.
    let invoke = find("plugin.invoke", Some(&plugin_s));
    assert!(
        invoke
            .iter()
            .any(|s| s.parent_span_id == Some(worker.span_id) && s.trace_id == root.trace_id),
        "plugin.invoke on the worker is a child of remote.task.execute"
    );
}

/// A `traceparent` is a hint about which trace to join, never a credential:
/// an unauthorized peer is refused and the worker records no span for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_traceparent_never_helps_an_unauthorized_peer() {
    spans();
    let publisher = IdentityKeyPair::generate();
    let (stranger, worker) = (Node::start(&publisher).await, Node::start(&publisher).await);
    worker.serve(StaticAllowlist::new()); // nobody is authorized

    let forged_trace = "5b8aa5a2d2c872e8321cf37308d69df2";
    let plugin: PluginId = "0123456789abcdef0123456789abcdef/forged@1.0.0"
        .parse()
        .unwrap();
    let task = task_for(plugin.clone(), b"x");
    let mut body = match RemoteRequest::for_task(&task).unwrap().frame {
        RequestFrame::Task(t) => t,
        RequestFrame::Control(_) => unreachable!(),
    };
    body.traceparent = Some(format!("00-{forged_trace}-051581bf3cb55c13-01"));
    let frame = encode_request(&RemoteRequest::task(body)).unwrap();
    assert!(frame.contains(&TRACE_EXTENSION_TAG));

    let raw = deadline(
        "request",
        stranger.transport.request(&worker.address(), &frame),
    )
    .await
    .unwrap();
    match decode_response(&raw, u64::MAX).unwrap().outcome {
        RemoteOutcome::Err { code, .. } => assert_eq!(code, RemoteErrorCode::NotAuthorized),
        other => panic!("an unauthorized peer got {other:?}"),
    }
    let plugin_s = plugin.to_string();
    assert!(
        find("remote.task.execute", Some(&plugin_s)).is_empty(),
        "no execution span (and so no trace membership) before authorization"
    );
}

/// A peer that predates the extension rejects the frame as malformed
/// (trailing bytes). The dispatcher resends the same task without it, and
/// remembers not to attach it for that peer again.
#[tokio::test(flavor = "multi_thread")]
async fn a_pre_extension_peer_still_interoperates() {
    spans();
    let publisher = IdentityKeyPair::generate();
    let a = Node::start(&publisher).await;
    let legacy = Node::start(&publisher).await;

    // The old decoder: postcard, then "no trailing bytes".
    let seen: Arc<Mutex<Vec<bool>>> = Arc::default(); // true = frame carried the extension
    let seen2 = Arc::clone(&seen);
    tokio::spawn(entangle_mesh_iroh::serve(
        Arc::clone(&legacy.transport),
        move |_peer, bytes: Vec<u8>| {
            let seen = Arc::clone(&seen2);
            async move {
                let (req, rest) = postcard::take_from_bytes::<RemoteRequest>(&bytes).unwrap();
                seen.lock().push(!rest.is_empty());
                let resp = if !rest.is_empty() {
                    RemoteTaskResponse::err(RemoteErrorCode::MalformedRequest, "trailing bytes")
                } else {
                    match req.frame {
                        RequestFrame::Task(RemoteTaskRequest { policy_hash, .. }) => {
                            RemoteTaskResponse::ok(b"legacy-ok".to_vec(), policy_hash)
                        }
                        RequestFrame::Control(_) => {
                            RemoteTaskResponse::err(RemoteErrorCode::Internal, "unexpected")
                        }
                    }
                };
                encode_response(&resp).unwrap()
            }
        },
    ));

    // A pre-extension peer predates capability tokens too: it issued none.
    let dispatcher = dispatcher_with(&a, &legacy, false);
    let plugin: PluginId = "0123456789abcdef0123456789abcdef/legacy@1.0.0"
        .parse()
        .unwrap();
    for round in 0..2 {
        let result = deadline(
            "dispatch",
            dispatcher
                .dispatch_one_shot(task_for(plugin.clone(), b"hi"))
                .instrument(tracing::info_span!(target: "entangle_test", "test.legacy", round)),
        )
        .await
        .expect("a pre-extension peer must still run the task");
        assert_eq!(result.output, b"legacy-ok");
    }
    assert_eq!(
        *seen.lock(),
        [true, false, false],
        "first try carries the extension and is refused; the resend and the next \
         dispatch go without it"
    );
}
