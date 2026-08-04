//! Cross-node dispatch, end to end over real QUIC on loopback.
//!
//! Every test here builds **two independent nodes in one process** — each with
//! its own identity, its own `Kernel`, and its own `mesh.iroh` endpoint bound
//! to `127.0.0.1:0` with relays disabled — and moves real packets between
//! them. Nothing is mocked and nothing touches the network beyond loopback.
//!
//! The load-bearing trick that makes "it really ran over there" provable:
//! **the plugin is loaded only on node B.** Node A's kernel has never seen it.
//! So when A's dispatcher returns `Hello, world!`, that output cannot have
//! come from A — a silent local fallback would fail with `NotLoaded`, not
//! succeed. The test asserts that emptiness explicitly rather than relying on
//! it implicitly.
//!
//! The suite covers, in order:
//!
//! 1. the happy path (a task really executes on another machine);
//! 2. **authorization** — an unlisted or revoked peer cannot make this node
//!    execute anything. This is the test that matters most: without it the
//!    feature is a remote-code-execution hole;
//! 3. size limits, on both sides, against a hostile counterparty;
//! 4. failure modes — every one a typed error under a deadline, never a hang
//!    and never a panic;
//! 5. the no-transport case, which must behave exactly as it did before this
//!    feature existed.

use std::sync::Arc;
use std::time::Duration;

use entangle_mesh_iroh::{
    IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_SCHEDULER, MAX_FRAME_BYTES,
};
use entangle_runtime::{Kernel, KernelConfig, LifecyclePhase};
use entangle_scheduler::wire::{
    decode_response, encode_request, RemoteErrorCode, RemoteOutcome, RemoteTaskRequest,
    WIRE_VERSION,
};
use entangle_scheduler::{
    DispatchError, Dispatcher, PeerDirectory, RemoteDispatch, RemoteTaskServer, StaticAllowlist,
    WorkerInfo, WorkerPool, MAX_REMOTE_TASK_TIMEOUT_MS,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::resource::ResourceSpec;
use entangle_types::task::{IntegrityPolicy, OneShotTask};

/// Ceiling on any single await in this file. A regression that hangs shows up
/// as a named failure rather than as a CI timeout with no explanation.
const TEST_DEADLINE: Duration = Duration::from_secs(30);

async fn deadline<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(TEST_DEADLINE, fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {TEST_DEADLINE:?}"),
    }
}

// ── fixtures ─────────────────────────────────────────────────────────────────

/// The committed hello-pong component: its `run` export echoes `Hello, <input>!`.
const HELLO_PONG_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../entangle-host/tests/fixtures/hello-pong.wasm"
);

fn hello_pong_wasm() -> Vec<u8> {
    std::fs::read(HELLO_PONG_WASM)
        .expect("hello-pong.wasm fixture not found — run fixtures-src/hello-pong/build.sh")
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

/// Write a signed plugin package (manifest + wasm + detached signature).
///
/// Mirrors how `entangle-runtime`'s own tests build one: the signature covers
/// `(artifact_bytes, manifest_bytes)` and the id is fully qualified as
/// `<publisher>/<name>@<version>`.
fn write_plugin_package(dir: &std::path::Path, keypair: &IdentityKeyPair, wasm: &[u8]) -> PluginId {
    let publisher = keypair.fingerprint_hex();
    let plugin_id_str = format!("{publisher}/remote-demo@0.1.0");

    let manifest_toml = format!(
        r#"[plugin]
id = "{plugin_id_str}"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "cross-node dispatch integration test plugin"
"#
    );

    std::fs::write(dir.join("entangle.toml"), manifest_toml.as_bytes()).expect("write manifest");
    std::fs::write(dir.join("plugin.wasm"), wasm).expect("write wasm");
    let bundle = sign_artifact(wasm, manifest_toml.as_bytes(), keypair);
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&bundle)
            .expect("serialize bundle")
            .as_bytes(),
    )
    .expect("write sig");

    plugin_id_str.parse().expect("fixture plugin id must parse")
}

// ── two-node harness ─────────────────────────────────────────────────────────

fn loopback_config() -> MeshIrohConfig {
    MeshIrohConfig {
        // The scheduler ALPN, not the control one: a node serving the wrong
        // sub-protocol must not accidentally accept work.
        alpn: ALPN_SCHEDULER.to_vec(),
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(10),
        ..MeshIrohConfig::loopback()
    }
}

/// One node: an identity, a kernel, and a QUIC endpoint.
struct Node {
    peer_id: PeerId,
    kernel: Arc<Kernel>,
    transport: Arc<MeshIroh>,
    /// Kept alive so the tempdir holding the plugin package is not deleted.
    _package: Option<tempfile::TempDir>,
}

impl Node {
    /// Start a node whose kernel trusts `publisher` but has nothing loaded.
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
            _package: None,
        }
    }

    /// Load the hello-pong fixture into this node's kernel.
    async fn load_hello_pong(&mut self, publisher: &IdentityKeyPair) -> PluginId {
        let dir = tempfile::tempdir().expect("tempdir");
        let plugin_id = write_plugin_package(dir.path(), publisher, &hello_pong_wasm());
        self.kernel
            .load_plugin_from_dir(dir.path())
            .await
            .expect("plugin must load");
        self._package = Some(dir);
        plugin_id
    }

    /// A dialable descriptor for this node, as a peer learns it from pairing.
    fn address(&self) -> IrohPeer {
        let addr = self
            .transport
            .local_addrs()
            .into_iter()
            .find(|a| a.ip().is_loopback())
            .expect("a loopback-bound endpoint must report a loopback socket");
        IrohPeer::new(self.transport.local_public_key(), addr)
    }

    /// Start serving scheduler work for exactly the peers in `allowlist`.
    fn serve(&self, allowlist: StaticAllowlist) -> Arc<RemoteTaskServer> {
        self.serve_with(RemoteTaskServer::new(
            Arc::clone(&self.kernel),
            Arc::new(allowlist),
            self.peer_id,
        ))
    }

    /// Start serving with a pre-configured server (custom ceilings, etc).
    fn serve_with(&self, server: RemoteTaskServer) -> Arc<RemoteTaskServer> {
        let server = Arc::new(server);
        tokio::spawn(entangle_scheduler::serve_tasks(
            Arc::clone(&self.transport),
            Arc::clone(&server),
        ));
        server
    }
}

/// A `WorkerInfo` advertising `peer` as a big, fast, idle machine — so
/// placement prefers it over anything else in the pool.
fn worker_for(peer: PeerId) -> WorkerInfo {
    WorkerInfo {
        peer_id: peer,
        display_name: "node-b".into(),
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

/// Build node A's dispatcher: a pool containing only `remote`, a transport,
/// and an address book that can reach it.
fn dispatcher_for(local: &Node, remote: &Node) -> Dispatcher {
    let pool = WorkerPool::new();
    pool.upsert(worker_for(remote.peer_id));

    let directory = PeerDirectory::new();
    directory.insert(remote.address());

    let client = RemoteDispatch::new(
        Arc::clone(&local.transport) as Arc<dyn MeshTransport>,
        Arc::new(directory),
    );

    Dispatcher::new(pool, Arc::clone(&local.kernel), local.peer_id)
        .with_strict_remote(true)
        .with_remote(Arc::new(client))
}

fn task_for(plugin: PluginId, input: &[u8]) -> OneShotTask {
    OneShotTask {
        id: uuid::Uuid::new_v4(),
        plugin,
        input: input.to_vec(),
        max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
        max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        // Zero resources: placement still prefers the one worker in the pool.
        resources: ResourceSpec::default(),
        integrity: IntegrityPolicy::None,
        timeout_ms: 10_000,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. THE PRODUCT: a task submitted here executes over there.
// ═════════════════════════════════════════════════════════════════════════════

/// Node A dispatches a task; placement routes it to node B; **B** executes the
/// hello-pong fixture; A receives `Hello, world!`.
///
/// The proof that it genuinely ran on B, not on A:
///
/// * A's kernel has **no plugins loaded at all** (asserted). A local fallback
///   would have failed with `NotLoaded` instead of returning output.
/// * B's lifecycle bus emits `Activated` for the plugin (asserted) — B really
///   instantiated and ran the component.
/// * the placement decision A returns names B's peer id (asserted).
#[tokio::test(flavor = "multi_thread")]
async fn task_executes_on_the_other_node_and_output_comes_back() {
    let publisher = IdentityKeyPair::generate();

    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;

    // B trusts A, and only A.
    node_b.serve(StaticAllowlist::new().allow(node_a.peer_id));

    // Watch B's kernel so we can prove *B* is what executed.
    let mut b_events = node_b.kernel.bus().subscribe();

    // A has never seen this plugin. This is the whole proof.
    assert!(
        node_a.kernel.list_plugins().is_empty(),
        "node A must have no plugins loaded — otherwise a local fallback \
         could masquerade as remote execution"
    );
    assert!(
        node_b.kernel.list_plugins().contains(&plugin_id),
        "node B must have the plugin loaded"
    );

    let dispatcher = dispatcher_for(&node_a, &node_b);
    let result = deadline(
        "remote dispatch",
        dispatcher.dispatch_one_shot(task_for(plugin_id.clone(), b"world")),
    )
    .await
    .expect("the task must execute on node B and return its output");

    assert_eq!(
        result.output, b"Hello, world!",
        "A must receive the bytes B's plugin produced"
    );
    assert_eq!(
        result.chosen.peer_id, node_b.peer_id,
        "the placement decision must name node B"
    );
    assert_ne!(
        node_a.peer_id, node_b.peer_id,
        "the two nodes must have distinct identities"
    );

    // B really instantiated and ran the component.
    let activated = deadline("node B lifecycle event", async {
        loop {
            let env = b_events.recv().await.expect("B's bus must stay open");
            if env.payload.phase == LifecyclePhase::Activated {
                return env.payload.plugin;
            }
        }
    })
    .await;
    assert_eq!(
        activated, plugin_id,
        "node B must have activated the dispatched plugin"
    );

    // And A still has nothing loaded: it never ran anything.
    assert!(
        node_a.kernel.list_plugins().is_empty(),
        "node A must still have no plugins loaded after the round trip"
    );
}

/// The same round trip twice on the same pair of nodes, with different inputs.
/// Guards against a handler that works only for the first request, or that
/// leaks state between invocations.
#[tokio::test(flavor = "multi_thread")]
async fn repeated_remote_dispatches_stay_independent() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;
    node_b.serve(StaticAllowlist::new().allow(node_a.peer_id));

    let dispatcher = dispatcher_for(&node_a, &node_b);

    for name in ["world", "again", "entanglement"] {
        let result = deadline(
            "remote dispatch",
            dispatcher.dispatch_one_shot(task_for(plugin_id.clone(), name.as_bytes())),
        )
        .await
        .unwrap_or_else(|e| panic!("dispatch for {name:?} must succeed: {e}"));
        assert_eq!(result.output, format!("Hello, {name}!").into_bytes());
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. AUTHORIZATION — the test that matters most.
// ═════════════════════════════════════════════════════════════════════════════

/// A peer that is **not** in the executor's allowlist cannot make it run
/// anything.
///
/// Without this gate the scheduler ALPN is an unauthenticated remote-code-
/// execution endpoint: anyone who can reach the UDP port could name a loaded
/// plugin and have it run. So the assertion is not merely "an error came
/// back" — it is also that **no execution happened**, proved by watching B's
/// lifecycle bus stay silent.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_outside_the_allowlist_cannot_make_this_node_execute_anything() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;

    // B's allowlist names somebody else entirely. A is a stranger.
    let a_stranger = PeerId::from_public_key_bytes(&[0x5a; 32]);
    assert_ne!(a_stranger, node_a.peer_id);
    node_b.serve(StaticAllowlist::new().allow(a_stranger));

    let mut b_events = node_b.kernel.bus().subscribe();

    let dispatcher = dispatcher_for(&node_a, &node_b);
    let err = deadline(
        "unauthorized dispatch",
        dispatcher.dispatch_one_shot(task_for(plugin_id, b"world")),
    )
    .await
    .expect_err("an unlisted peer must be refused");

    match err {
        DispatchError::RemoteRejected { peer, code, .. } => {
            assert_eq!(
                peer, node_b.peer_id,
                "the error must name the refusing peer"
            );
            assert_eq!(
                code,
                RemoteErrorCode::NotAuthorized,
                "refusal must be the authorization refusal, not an incidental failure"
            );
        }
        other => panic!("expected RemoteRejected(NotAuthorized), got {other:?}"),
    }

    // Nothing ran. B's kernel emits `Activated` on every invocation, so a
    // silent window here means the plugin was never invoked.
    match tokio::time::timeout(Duration::from_millis(500), b_events.recv()).await {
        Err(_) => {} // silence: nothing executed. This is the pass condition.
        Ok(Ok(env)) => panic!(
            "node B emitted {:?} for {} — an unauthorized peer caused execution",
            env.payload.phase, env.payload.plugin
        ),
        Ok(Err(e)) => panic!("node B's bus closed unexpectedly: {e}"),
    }
}

/// An executor with an empty allowlist authorizes nobody — the safe default
/// for a node that has not paired with anyone.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_allowlist_refuses_every_peer() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;
    node_b.serve(StaticAllowlist::new());

    let dispatcher = dispatcher_for(&node_a, &node_b);
    let err = deadline(
        "dispatch to an empty allowlist",
        dispatcher.dispatch_one_shot(task_for(plugin_id, b"world")),
    )
    .await
    .expect_err("an empty allowlist must refuse everyone");

    assert!(
        matches!(
            err,
            DispatchError::RemoteRejected {
                code: RemoteErrorCode::NotAuthorized,
                ..
            }
        ),
        "got {err:?}"
    );
    assert!(err.to_string().contains("ENTANGLE-E0403"));
}

/// Authorization is keyed on the identity QUIC authenticated, so a stranger
/// cannot borrow an authorized peer's id by asserting it: it would have to
/// possess that peer's Ed25519 secret key to complete the handshake as them.
///
/// Here node C is allowlisted and node A is not; A dials B directly with a
/// well-formed frame and is still refused.
#[tokio::test(flavor = "multi_thread")]
async fn authorization_follows_the_authenticated_identity_not_the_payload() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let node_c = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;

    // Only C may submit work.
    node_b.serve(StaticAllowlist::new().allow(node_c.peer_id));

    // A sends a perfectly well-formed request anyway.
    let request = RemoteTaskRequest::for_task(&task_for(plugin_id, b"world"));
    let frame = encode_request(&request).expect("encode");
    let raw = deadline(
        "raw request from an unauthorized peer",
        node_a.transport.request(&node_b.address(), &frame),
    )
    .await
    .expect("the transport round trip itself succeeds");

    let response = decode_response(&raw, u64::MAX).expect("B must answer with a valid envelope");
    match response.outcome {
        RemoteOutcome::Err { code, .. } => assert_eq!(
            code,
            RemoteErrorCode::NotAuthorized,
            "identity, not payload, decides authorization"
        ),
        RemoteOutcome::Ok { .. } => {
            panic!("node B executed work for a peer outside its allowlist")
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SIZE LIMITS — enforced on both sides, against a hostile counterparty.
// ═════════════════════════════════════════════════════════════════════════════

/// An input over the executor's own ceiling is refused by the executor, no
/// matter what the caller declared. The caller cannot raise this limit.
#[tokio::test(flavor = "multi_thread")]
async fn oversize_input_is_refused_by_the_executor() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;

    // B accepts at most 8 bytes of input, whatever a caller says.
    let server = RemoteTaskServer::new(
        Arc::clone(&node_b.kernel),
        Arc::new(StaticAllowlist::new().allow(node_a.peer_id)),
        node_b.peer_id,
    )
    .with_max_bytes(8, OneShotTask::DEFAULT_MAX_OUTPUT_BYTES);
    assert_eq!(server.input_ceiling(), 8);
    node_b.serve_with(server);

    // A declares the full 16 MiB ceiling and sends 4 KiB — legal by its own
    // lights, over B's limit.
    let mut task = task_for(plugin_id, &vec![b'x'; 4096]);
    task.max_input_bytes = OneShotTask::DEFAULT_MAX_INPUT_BYTES;

    let dispatcher = dispatcher_for(&node_a, &node_b);
    let err = deadline(
        "oversize input dispatch",
        dispatcher.dispatch_one_shot(task),
    )
    .await
    .expect_err("B must refuse an input over its own ceiling");

    assert!(
        matches!(
            err,
            DispatchError::RemoteRejected {
                code: RemoteErrorCode::InputTooLarge,
                ..
            }
        ),
        "got {err:?}"
    );
}

/// An output over the caller's declared `max_output_bytes` is refused. The
/// executor catches it first (it knows the caller's limit), so the oversized
/// payload is never even put on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn oversize_output_is_refused() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;
    node_b.serve(StaticAllowlist::new().allow(node_a.peer_id));

    // hello-pong answers with 13 bytes; A will accept only 4.
    let mut task = task_for(plugin_id, b"world");
    task.max_output_bytes = 4;

    let dispatcher = dispatcher_for(&node_a, &node_b);
    let err = deadline(
        "oversize output dispatch",
        dispatcher.dispatch_one_shot(task),
    )
    .await
    .expect_err("an output over the caller's limit must be refused");

    assert!(
        matches!(
            err,
            DispatchError::RemoteRejected {
                code: RemoteErrorCode::OutputTooLarge,
                ..
            }
        ),
        "got {err:?}"
    );
}

/// The caller's own ingress guard still fires *before* placement, so an
/// oversized input never reaches the wire at all — attaching a transport did
/// not weaken the existing `ENTANGLE-E0401` check.
#[tokio::test(flavor = "multi_thread")]
async fn oversize_input_never_leaves_the_caller() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;
    node_b.serve(StaticAllowlist::new().allow(node_a.peer_id));

    let mut b_events = node_b.kernel.bus().subscribe();

    let mut task = task_for(plugin_id, &vec![b'x'; 1024]);
    task.max_input_bytes = 16; // smaller than the input we are handing it

    let dispatcher = dispatcher_for(&node_a, &node_b);
    let err = deadline("self-inconsistent task", dispatcher.dispatch_one_shot(task))
        .await
        .expect_err("an input over its own declared limit must be refused locally");

    match err {
        DispatchError::InputSizeExceeded { declared, actual } => {
            assert_eq!(declared, 16);
            assert_eq!(actual, 1024);
        }
        other => panic!("expected InputSizeExceeded, got {other:?}"),
    }
    assert!(err.to_string().contains("ENTANGLE-E0401"));

    // B was never contacted.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), b_events.recv())
            .await
            .is_err(),
        "node B must not have been contacted at all"
    );
}

/// A hostile caller whose frame is internally inconsistent — more input than
/// the `max_input_bytes` it declared — is rejected by the executor's decoder,
/// before any execution.
#[tokio::test(flavor = "multi_thread")]
async fn a_self_inconsistent_frame_is_rejected_by_the_executor() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;
    node_b.serve(StaticAllowlist::new().allow(node_a.peer_id));

    let mut request = RemoteTaskRequest::for_task(&task_for(plugin_id, b"world"));
    request.input = vec![0u8; 4096];
    request.max_input_bytes = 8; // a lie the decoder catches

    let frame = encode_request(&request).expect("encode");
    let raw = deadline(
        "inconsistent frame",
        node_a.transport.request(&node_b.address(), &frame),
    )
    .await
    .expect("transport round trip");

    let response = decode_response(&raw, u64::MAX).expect("valid envelope");
    match response.outcome {
        RemoteOutcome::Err { code, .. } => {
            assert_eq!(code, RemoteErrorCode::InputTooLarge)
        }
        RemoteOutcome::Ok { .. } => panic!("executor accepted a self-inconsistent frame"),
    }
}

/// The transport's own frame cap sits below anything the wire layer would
/// encode, so an over-cap payload cannot be constructed and sent.
#[test]
fn the_wire_refuses_to_encode_a_frame_over_the_transport_cap() {
    let plugin: PluginId = "0123456789abcdef0123456789abcdef/demo@1.0.0"
        .parse()
        .expect("plugin id");
    let mut task = OneShotTask::with_defaults(plugin, vec![0u8; MAX_FRAME_BYTES + 1]);
    task.max_input_bytes = u64::MAX;

    let err = encode_request(&RemoteTaskRequest::for_task(&task))
        .expect_err("a frame over the transport cap must not encode");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. FAILURE MODES — typed errors under a deadline. Never a hang, never a panic.
// ═════════════════════════════════════════════════════════════════════════════

/// The plugin is loaded on A but not on B. Placement sends the task to B, B
/// says so, and A gets a typed error naming the peer — not a hang, not a
/// panic, and *not* a silent local fallback that would hide the misplacement.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_missing_on_the_executor_surfaces_as_a_typed_error() {
    let publisher = IdentityKeyPair::generate();
    let mut node_a = Node::start(&publisher).await;
    let node_b = Node::start(&publisher).await;

    // Loaded here, deliberately not there.
    let plugin_id = node_a.load_hello_pong(&publisher).await;
    node_b.serve(StaticAllowlist::new().allow(node_a.peer_id));
    assert!(node_b.kernel.list_plugins().is_empty());

    let dispatcher = dispatcher_for(&node_a, &node_b);
    let err = deadline(
        "dispatch of a plugin B lacks",
        dispatcher.dispatch_one_shot(task_for(plugin_id.clone(), b"world")),
    )
    .await
    .expect_err("B cannot run a plugin it does not have");

    match err {
        DispatchError::RemoteRejected {
            peer,
            code,
            message,
        } => {
            assert_eq!(peer, node_b.peer_id);
            assert_eq!(code, RemoteErrorCode::PluginNotLoaded);
            assert!(
                message.contains(&plugin_id.to_string()),
                "the message should name the missing plugin: {message}"
            );
        }
        other => panic!("expected RemoteRejected(PluginNotLoaded), got {other:?}"),
    }
}

/// A peer that cannot be dialled fails with a typed error well inside the
/// deadline. The `deadline` wrapper is the anti-hang assertion.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_peer_fails_with_a_typed_error_under_a_deadline() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;

    // A syntactically valid identity nobody holds, at a port nobody serves.
    let ghost = IdentityKeyPair::generate();
    let ghost_peer = IrohPeer::new(
        *ghost.public().as_bytes(),
        "127.0.0.1:1".parse().expect("addr"),
    );

    let pool = WorkerPool::new();
    pool.upsert(worker_for(ghost_peer.peer_id));
    let directory = PeerDirectory::new();
    directory.insert(ghost_peer.clone());

    let dispatcher = Dispatcher::new(pool, Arc::clone(&node_a.kernel), node_a.peer_id)
        .with_strict_remote(true)
        .with_remote(Arc::new(RemoteDispatch::new(
            Arc::clone(&node_a.transport) as Arc<dyn MeshTransport>,
            Arc::new(directory),
        )));

    let plugin: PluginId = "0123456789abcdef0123456789abcdef/demo@1.0.0"
        .parse()
        .expect("plugin id");
    let mut task = task_for(plugin, b"world");
    task.timeout_ms = 1_000;

    let started = std::time::Instant::now();
    let err = deadline("dispatch to nowhere", dispatcher.dispatch_one_shot(task))
        .await
        .expect_err("dialling nowhere must fail");

    match err {
        DispatchError::RemoteTransport { peer, reason } => {
            assert_eq!(peer, ghost_peer.peer_id, "the error must name the peer");
            assert!(!reason.is_empty());
        }
        other => panic!("expected RemoteTransport, got {other:?}"),
    }
    assert!(
        started.elapsed() < TEST_DEADLINE,
        "must fail fast, took {:?}",
        started.elapsed()
    );
}

/// Placement picks a peer this node has no address for. That is a typed
/// error, not a panic and not an accidental local execution.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_with_no_known_address_is_a_typed_error() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;

    let unknown = PeerId::from_public_key_bytes(&[0x77; 32]);
    let pool = WorkerPool::new();
    pool.upsert(worker_for(unknown));

    let dispatcher = Dispatcher::new(pool, Arc::clone(&node_a.kernel), node_a.peer_id).with_remote(
        Arc::new(RemoteDispatch::new(
            Arc::clone(&node_a.transport) as Arc<dyn MeshTransport>,
            // An empty address book: placement knows the peer, routing doesn't.
            Arc::new(PeerDirectory::new()),
        )),
    );

    let plugin: PluginId = "0123456789abcdef0123456789abcdef/demo@1.0.0"
        .parse()
        .expect("plugin id");
    let err = deadline(
        "dispatch to an unaddressed peer",
        dispatcher.dispatch_one_shot(task_for(plugin, b"world")),
    )
    .await
    .expect_err("an unaddressed peer must not silently run locally");

    assert!(err.to_string().contains("ENTANGLE-E0402"), "{err}");
    match err {
        DispatchError::RemoteTransport { peer, reason } => {
            assert_eq!(peer, unknown);
            assert!(reason.contains("address"), "{reason}");
        }
        other => panic!("expected RemoteTransport, got {other:?}"),
    }
}

/// A peer speaking a future envelope version is told so, rather than having
/// its bytes misparsed into a plausible-looking task.
#[tokio::test(flavor = "multi_thread")]
async fn a_future_wire_version_is_refused_not_misparsed() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;
    node_b.serve(StaticAllowlist::new().allow(node_a.peer_id));

    let mut request = RemoteTaskRequest::for_task(&task_for(plugin_id, b"world"));
    request.v = WIRE_VERSION + 1;
    let frame = encode_request(&request).expect("encode");

    let raw = deadline(
        "future-version frame",
        node_a.transport.request(&node_b.address(), &frame),
    )
    .await
    .expect("transport round trip");

    let response = decode_response(&raw, u64::MAX).expect("valid envelope");
    match response.outcome {
        RemoteOutcome::Err { code, .. } => {
            assert_eq!(code, RemoteErrorCode::UnsupportedVersion)
        }
        RemoteOutcome::Ok { .. } => panic!("executor ran a task from an unknown envelope version"),
    }
}

/// Pure garbage from an authorized peer is answered, not crashed on. An
/// authorized-but-buggy peer must not be able to kill the accept loop.
#[tokio::test(flavor = "multi_thread")]
async fn garbage_from_an_authorized_peer_is_answered_not_fatal() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;
    node_b.serve(StaticAllowlist::new().allow(node_a.peer_id));

    let junk: Vec<u8> = (0u8..=200).collect();
    let raw = deadline(
        "garbage frame",
        node_a.transport.request(&node_b.address(), &junk),
    )
    .await
    .expect("transport round trip");
    let response = decode_response(&raw, u64::MAX).expect("valid envelope");
    assert!(
        matches!(response.outcome, RemoteOutcome::Err { .. }),
        "garbage must produce a structured error"
    );

    // The node is still healthy: a real task still works afterwards.
    let dispatcher = dispatcher_for(&node_a, &node_b);
    let result = deadline(
        "dispatch after garbage",
        dispatcher.dispatch_one_shot(task_for(plugin_id, b"world")),
    )
    .await
    .expect("the executor must survive a garbage frame");
    assert_eq!(result.output, b"Hello, world!");
}

/// A remote caller must not be able to pin a worker indefinitely: whatever
/// timeout it asks for, the executor clamps it to its own ceiling.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_cannot_raise_the_executors_timeout_ceiling() {
    let publisher = IdentityKeyPair::generate();
    let node_b = Node::start(&publisher).await;

    let server = RemoteTaskServer::new(
        Arc::clone(&node_b.kernel),
        Arc::new(StaticAllowlist::new()),
        node_b.peer_id,
    );

    // Whatever a peer asks for, the ceiling wins.
    assert_eq!(
        server.effective_timeout_ms(u64::MAX),
        MAX_REMOTE_TASK_TIMEOUT_MS
    );
    assert_eq!(
        server.effective_timeout_ms(MAX_REMOTE_TASK_TIMEOUT_MS + 1),
        MAX_REMOTE_TASK_TIMEOUT_MS
    );
    // A shorter request is honoured as-is.
    assert_eq!(server.effective_timeout_ms(250), 250);

    // The same holds for the output ceiling.
    assert_eq!(
        server.effective_output_cap(u64::MAX),
        OneShotTask::DEFAULT_MAX_OUTPUT_BYTES
    );
    assert_eq!(server.effective_output_cap(32), 32);

    // And an operator may lower the ceiling, never raise it.
    let strict = RemoteTaskServer::new(
        Arc::clone(&node_b.kernel),
        Arc::new(StaticAllowlist::new()),
        node_b.peer_id,
    )
    .with_max_timeout_ms(1_000);
    assert_eq!(strict.effective_timeout_ms(u64::MAX), 1_000);
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. NO TRANSPORT — a node without one behaves exactly as it did before.
// ═════════════════════════════════════════════════════════════════════════════

/// With no transport configured, `strict_remote` still turns a remote
/// placement into `RemoteNotImplemented` — the pre-existing contract.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_transport_strict_mode_still_refuses_remote_placement() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;

    let pool = WorkerPool::new();
    let remote = PeerId::from_public_key_bytes(&[0x42; 32]);
    pool.upsert(worker_for(remote));

    let dispatcher =
        Dispatcher::new(pool, Arc::clone(&node_a.kernel), node_a.peer_id).with_strict_remote(true);
    assert!(!dispatcher.has_remote());

    let plugin: PluginId = "0123456789abcdef0123456789abcdef/demo@1.0.0"
        .parse()
        .expect("plugin id");
    let err = deadline(
        "strict dispatch without a transport",
        dispatcher.dispatch_one_shot(task_for(plugin, b"world")),
    )
    .await
    .expect_err("strict mode must refuse an unreachable remote placement");

    assert!(err.to_string().contains("ENTANGLE-E0400"), "{err}");
    match err {
        DispatchError::RemoteNotImplemented { peer, reason } => {
            assert_eq!(peer, remote);
            assert!(!reason.is_empty());
        }
        other => panic!("expected RemoteNotImplemented, got {other:?}"),
    }
}

/// With no transport and `strict_remote` clear, a remote placement still falls
/// back to the local kernel — unchanged, so no existing deployment breaks.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_transport_non_strict_mode_still_falls_back_to_local() {
    let publisher = IdentityKeyPair::generate();
    let mut node_a = Node::start(&publisher).await;
    let plugin_id = node_a.load_hello_pong(&publisher).await;

    let pool = WorkerPool::new();
    pool.upsert(worker_for(PeerId::from_public_key_bytes(&[0x42; 32])));

    let dispatcher = Dispatcher::new(pool, Arc::clone(&node_a.kernel), node_a.peer_id);
    assert!(!dispatcher.has_remote());

    let result = deadline(
        "non-strict fallback",
        dispatcher.dispatch_one_shot(task_for(plugin_id, b"world")),
    )
    .await
    .expect("the historical local fallback must still work");
    assert_eq!(result.output, b"Hello, world!");
}

/// A node that is not *serving* the scheduler ALPN executes nothing for
/// anyone, even a peer it would otherwise trust: the server half is opt-in.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_not_serving_the_scheduler_alpn_executes_nothing() {
    let publisher = IdentityKeyPair::generate();
    let node_a = Node::start(&publisher).await;
    let mut node_b = Node::start(&publisher).await;
    let plugin_id = node_b.load_hello_pong(&publisher).await;
    // Deliberately no `node_b.serve(..)`.

    let dispatcher = dispatcher_for(&node_a, &node_b);
    let err = deadline(
        "dispatch to a silent node",
        dispatcher.dispatch_one_shot(task_for(plugin_id, b"world")),
    )
    .await
    .expect_err("a node that serves nothing must not execute anything");

    assert!(
        matches!(err, DispatchError::RemoteTransport { .. }),
        "expected a transport-level failure, got {err:?}"
    );
}
