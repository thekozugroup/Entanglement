//! `entangle logs` and `entangle trace task`, from the daemon side: the
//! `logs/read` and `trace/get` RPC methods over the real `tracing`
//! subscriber the daemon installs (`entangle_observability::init_daemon`).
//!
//! The subscriber is global (plugin and scheduler tasks run on other
//! threads), so this test binary installs it once and every test uses its
//! own plugin ids and task ids.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use entangle_bin::{config, methods, state::DaemonState};
use entangle_mesh_iroh::{IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_SCHEDULER};
use entangle_observability::logs::{LogConfig, LogHub, LogLevel};
use entangle_observability::traces::{TraceConfig, TraceStore};
use entangle_peers::PeerStore;
use entangle_rpc::methods::{LogsReadResult, SpanWire, TraceGetResult};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::capability::{CapabilityGate, StaticTokens};
use entangle_scheduler::{
    Dispatcher, PeerDirectory, RemoteDispatch, RemoteTaskServer, StaticAllowlist, WorkerInfo,
    WorkerPool,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::resource::ResourceSpec;
use entangle_types::task::{IntegrityPolicy, OneShotTask};

// ── the global subscriber ────────────────────────────────────────────────────

fn stores() -> &'static (LogHub, TraceStore) {
    static S: OnceLock<(LogHub, TraceStore)> = OnceLock::new();
    S.get_or_init(|| {
        let hub = LogHub::new(LogConfig {
            lines_per_source: 64,
            max_plugin_sources: 64,
            capture_level: LogLevel::Info,
        });
        let store = TraceStore::new(TraceConfig::default());
        entangle_observability::init_daemon("error", None, &hub, &store).expect("subscriber");
        (hub, store)
    })
}

// ── fixtures ─────────────────────────────────────────────────────────────────

fn keyring_for(kp: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "obs-test".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

fn state_for(kernel: Arc<Kernel>, dispatcher: Dispatcher, pool: WorkerPool) -> Arc<DaemonState> {
    let (hub, store) = stores();
    let identity = IdentityKeyPair::generate();
    Arc::new(
        DaemonState::new(
            kernel,
            Arc::new(dispatcher),
            pool,
            PeerStore::new(),
            identity,
            "obs-test".into(),
        )
        .with_observability(hub.clone(), store.clone()),
    )
}

async fn rpc(
    state: &Arc<DaemonState>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let req = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    serde_json::from_str(&methods::dispatch(&req.to_string(), state).await).unwrap()
}

async fn logs(state: &Arc<DaemonState>, params: serde_json::Value) -> LogsReadResult {
    let v = rpc(state, "logs/read", params).await;
    assert!(v.get("error").is_none(), "{v}");
    serde_json::from_value(v["result"].clone()).unwrap()
}

fn plain_state() -> Arc<DaemonState> {
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap());
    let pool = WorkerPool::new();
    let local = PeerId::from_public_key_bytes(IdentityKeyPair::generate().public().as_bytes());
    let dispatcher = Dispatcher::new(pool.clone(), kernel.clone(), local);
    state_for(kernel, dispatcher, pool)
}

fn messages(r: &LogsReadResult) -> Vec<&str> {
    r.lines.iter().map(|l| l.message.as_str()).collect()
}

// ── logs ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn plugin_output_appears_for_that_plugin_only() {
    let state = plain_state();
    let one: PluginId = "0123456789abcdef0123456789abcdef/only-one@0.1.0"
        .parse()
        .unwrap();
    let two: PluginId = "0123456789abcdef0123456789abcdef/only-two@0.1.0"
        .parse()
        .unwrap();
    // Exactly what a wasm plugin's stdout / `log` import produce.
    entangle_host::output::emit_line(&one, "info", "stdout", "hello from one");
    entangle_host::output::emit_line(&two, "warn", "log", "hello from two");

    let r = logs(&state, serde_json::json!({ "source": one.to_string() })).await;
    assert_eq!(messages(&r), ["hello from one"], "{r:?}");
    assert_eq!(r.source, one.to_string());
    // The short name resolves too.
    let r = logs(&state, serde_json::json!({ "source": "only-two" })).await;
    assert_eq!(messages(&r), ["hello from two"]);
    assert_eq!(r.lines[0].level, "warn");
    // And no subsystem buffer got plugin output.
    for sys in ["daemon", "scheduler", "mesh", "gateway"] {
        let r = logs(&state, serde_json::json!({ "source": sys })).await;
        assert!(
            !messages(&r).iter().any(|m| m.starts_with("hello from")),
            "{sys}: {r:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn level_and_filter_select_lines() {
    let state = plain_state();
    let p: PluginId = "0123456789abcdef0123456789abcdef/filtered@0.1.0"
        .parse()
        .unwrap();
    for (lvl, m) in [
        ("info", "routine start"),
        ("warn", "slow call"),
        ("error", "boom happened"),
    ] {
        entangle_host::output::emit_line(&p, lvl, "log", m);
    }
    let src = p.to_string();
    let r = logs(
        &state,
        serde_json::json!({ "source": src, "level": "warn" }),
    )
    .await;
    assert_eq!(messages(&r), ["slow call", "boom happened"]);
    let r = logs(
        &state,
        serde_json::json!({ "source": src, "filter": "BOOM" }),
    )
    .await;
    assert_eq!(messages(&r), ["boom happened"]);
    let r = logs(
        &state,
        serde_json::json!({ "source": src, "level": "error", "filter": "slow" }),
    )
    .await;
    assert!(r.lines.is_empty());

    // The spec's example: `entangle logs scheduler --filter StalledEvent`.
    tracing::warn!(
        target: "entangle::scheduler::stream",
        event = "StalledEvent",
        task = "obs-test-stall",
        "stream stalled: no credit from the submitter"
    );
    tracing::info!(target: "entangle::scheduler::stream", "obs-test unrelated scheduler line");
    let r = logs(
        &state,
        serde_json::json!({ "source": "scheduler", "filter": "StalledEvent" }),
    )
    .await;
    assert!(
        r.lines
            .iter()
            .any(|l| l.event.as_deref() == Some("StalledEvent")
                && l.fields
                    .iter()
                    .any(|(k, v)| k == "task" && v == "obs-test-stall")),
        "{r:?}"
    );
    assert!(
        r.lines
            .iter()
            .all(|l| l.event.as_deref() == Some("StalledEvent")),
        "{r:?}"
    );

    // A bad level is a parameter error with a stable code.
    let v = rpc(
        &state,
        "logs/read",
        serde_json::json!({ "source": "daemon", "level": "loud" }),
    )
    .await;
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ENTANGLE-E0922"),
        "{v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn follow_receives_a_line_logged_after_the_call_started() {
    let state = plain_state();
    let p: PluginId = "0123456789abcdef0123456789abcdef/follow-me@0.1.0"
        .parse()
        .unwrap();
    entangle_host::output::emit_line(&p, "info", "log", "before");
    let first = logs(&state, serde_json::json!({ "source": p.to_string() })).await;
    assert_eq!(messages(&first), ["before"]);

    let started = Instant::now();
    let poll = {
        let state = state.clone();
        let params = serde_json::json!({
            "source": p.to_string(), "after": first.next_cursor, "wait_ms": 10_000
        });
        tokio::spawn(async move { logs(&state, params).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !poll.is_finished(),
        "nothing new yet: the call must be held open"
    );
    entangle_host::output::emit_line(&p, "info", "log", "after the call began");
    let r = tokio::time::timeout(Duration::from_secs(5), poll)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(messages(&r), ["after the call began"]);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "returned promptly, not at the 10 s deadline"
    );
    assert!(r.next_cursor > first.next_cursor);

    // With no new line the long-poll ends at its deadline with an empty page.
    let t = Instant::now();
    let r = logs(
        &state,
        serde_json::json!({ "source": p.to_string(), "after": r.next_cursor, "wait_ms": 400 }),
    )
    .await;
    assert!(r.lines.is_empty());
    assert!(t.elapsed() >= Duration::from_millis(350) && t.elapsed() < Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ring_buffer_bound_holds() {
    let state = plain_state();
    let p: PluginId = "0123456789abcdef0123456789abcdef/flood@0.1.0"
        .parse()
        .unwrap();
    for i in 0..500 {
        entangle_host::output::emit_line(&p, "info", "log", &format!("flood {i}"));
    }
    let r = logs(
        &state,
        serde_json::json!({ "source": p.to_string(), "limit": 1000 }),
    )
    .await;
    assert_eq!(
        r.lines.len(),
        64,
        "the configured lines_per_source of this test daemon"
    );
    assert_eq!(r.lines.last().unwrap().message, "flood 499");
    assert_eq!(r.lines[0].message, "flood 436");
    // A reader that fell behind is told lines were lost.
    let r = logs(
        &state,
        serde_json::json!({ "source": p.to_string(), "after": 1 }),
    )
    .await;
    assert!(r.truncated);
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_secret_is_in_the_buffer() {
    let state = plain_state();
    let p: PluginId = "0123456789abcdef0123456789abcdef/leaky@0.1.0"
        .parse()
        .unwrap();
    let biscuit =
        "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBqS1x3wB9pQ-mVf2Zr7nLo4uYtHkDeP8sXcAaNbQ0zWyI=";
    // A daemon event with a token-shaped field and a secret in the message...
    tracing::info!(
        target: "entangle_bin::obs_test",
        plugin = %p,
        capability_token = biscuit,
        bearer = "abc.def.ghi",
        "presented token {biscuit} with passphrase=hunter2"
    );
    // ...and a plugin that printed its own credentials.
    entangle_host::output::emit_line(
        &p,
        "info",
        "stdout",
        "Authorization: Bearer sekrit-value-123",
    );
    entangle_host::output::emit_line(&p, "info", "stdout", &format!("capability {biscuit}"));
    for source in [p.to_string(), "daemon".to_owned()] {
        let r = logs(&state, serde_json::json!({ "source": source })).await;
        let dump = format!("{r:?}");
        for leak in ["En0KEwoE", "abc.def.ghi", "hunter2", "sekrit-value"] {
            assert!(!dump.contains(leak), "{leak} leaked via {source}: {dump}");
        }
        assert!(dump.contains("[REDACTED]"), "{dump}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_plugin_is_a_clear_error() {
    let state = plain_state();
    let v = rpc(
        &state,
        "logs/read",
        serde_json::json!({ "source": "no-such-plugin" }),
    )
    .await;
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.starts_with("ENTANGLE-E0920"), "{msg}");
    assert!(
        msg.contains("no-such-plugin") && msg.contains("scheduler, mesh, gateway, daemon"),
        "{msg}"
    );
    assert_eq!(v["error"]["code"], -32602);
}

// ── native plugin stderr end to end ──────────────────────────────────────────

#[cfg(target_os = "linux")]
fn build_native_echo() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf();
    let target_dir = root.join("target").join("native-examples");
    let status =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "--quiet", "--manifest-path"])
            .arg(root.join("examples/native-echo/Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .status()
            .unwrap();
    assert!(status.success(), "building examples/native-echo failed");
    target_dir.join("debug").join("entangle-native-echo")
}

/// A real daemon-side invoke of a tier-5 plugin that prints on stderr: the
/// line is in `logs/read` for that plugin, and the invocation's trace holds
/// `task.dispatch` -> ... -> `plugin.invoke` under one trace id.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_native_plugins_stderr_is_its_log_and_a_dispatch_leaves_a_trace() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let bin = std::fs::read(build_native_echo()).unwrap();
    let id = format!("{}/native-echo@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 5\nruntime = \"native\"\n\n\
         [capabilities]\n\"storage.local\" = {{ scope = \"plugin\" }}\n"
    );
    std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(pkg.join("plugin.bin"), &bin).unwrap();
    std::fs::write(
        pkg.join("plugin.bin.sig"),
        toml::to_string(&sign_artifact(&bin, manifest.as_bytes(), &kp)).unwrap(),
    )
    .unwrap();
    let config_dir = tmp.path().join(".entangle");
    let cfg = config::load_config(&config_dir.join("config.toml")).unwrap();
    let kernel =
        Arc::new(Kernel::new(config::kernel_config(&cfg, &config_dir), keyring_for(&kp)).unwrap());
    let pool = WorkerPool::new();
    let identity = IdentityKeyPair::generate();
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let dispatcher = Dispatcher::new(pool.clone(), kernel.clone(), local);
    let state = state_for(kernel, dispatcher, pool);

    let loaded = rpc(&state, "plugins/load", serde_json::json!({ "dir": pkg })).await;
    assert_eq!(
        loaded["result"]["plugin_id"],
        serde_json::json!(id),
        "{loaded}"
    );

    // A loaded plugin that has printed nothing is known: the kernel's own
    // load-time line is there (the sandbox it was given), its output is not.
    let silent = logs(&state, serde_json::json!({ "source": "native-echo" })).await;
    assert!(
        silent.lines.iter().all(|l| l.target != "entangle::native"),
        "{silent:?}"
    );

    let out = rpc(
        &state,
        "compute/dispatch",
        serde_json::json!({
            "plugin_id": id, "input": b"trace me".to_vec(), "timeout_ms": 10_000,
            "cpu_cores": 0.0, "memory_bytes": 0, "gpu_required": false,
            "gpu_vram_min_bytes": 0, "integrity": { "kind": "none" }
        }),
    )
    .await;
    assert!(out.get("error").is_none(), "{out}");
    let task_id = out["result"]["task_id"]
        .as_str()
        .expect("the daemon returns the task id")
        .to_owned();

    // The plugin's stderr line ("native-echo: request #1") is its log.
    let r = logs(&state, serde_json::json!({ "source": "native-echo" })).await;
    assert!(
        messages(&r)
            .iter()
            .any(|m| m.contains("native-echo: request #")),
        "{r:?}"
    );

    // The trace: one trace id; task.dispatch is an ancestor of plugin.invoke.
    let v = rpc(&state, "trace/get", serde_json::json!({ "id": task_id })).await;
    assert!(v.get("error").is_none(), "{v}");
    let t: TraceGetResult = serde_json::from_value(v["result"].clone()).unwrap();
    assert_eq!(t.traces.len(), 1, "{t:?}");
    let spans = &t.traces[0].spans;
    let by_name = |n: &str| spans.iter().filter(|s| s.name == n).collect::<Vec<_>>();
    let dispatch = by_name("task.dispatch");
    assert_eq!(dispatch.len(), 1, "{spans:?}");
    assert_attr(dispatch[0], "task_id", &task_id);
    let invoke = by_name("plugin.invoke");
    assert_eq!(invoke.len(), 1, "{spans:?}");
    assert!(
        is_descendant(spans, invoke[0], dispatch[0]),
        "plugin.invoke under task.dispatch: {spans:?}"
    );
    assert_eq!(invoke[0].status, "unset");
    assert!(dispatch[0].duration_us >= invoke[0].duration_us);

    // The same trace by trace id; an unknown id is a clear error.
    let by_trace = rpc(
        &state,
        "trace/get",
        serde_json::json!({ "id": t.traces[0].trace_id }),
    )
    .await;
    assert_eq!(
        by_trace["result"]["traces"][0]["spans"]
            .as_array()
            .unwrap()
            .len(),
        spans.len()
    );
    let none = rpc(
        &state,
        "trace/get",
        serde_json::json!({ "id": uuid::Uuid::new_v4().to_string() }),
    )
    .await;
    assert!(
        none["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("ENTANGLE-E0923"),
        "{none}"
    );
    let bad = rpc(
        &state,
        "trace/get",
        serde_json::json!({ "id": "not-an-id" }),
    )
    .await;
    assert!(
        bad["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("ENTANGLE-E0924"),
        "{bad}"
    );
}

fn assert_attr(s: &SpanWire, key: &str, want: &str) {
    assert!(
        s.attributes.iter().any(|(k, v)| k == key && v == want),
        "{key}={want} missing on {} {:?}",
        s.name,
        s.attributes
    );
}

fn is_descendant(spans: &[SpanWire], child: &SpanWire, ancestor: &SpanWire) -> bool {
    let mut cur = child;
    while let Some(p) = &cur.parent_span_id {
        if *p == ancestor.span_id {
            return true;
        }
        match spans.iter().find(|s| s.span_id == *p) {
            Some(parent) => cur = parent,
            None => return false,
        }
    }
    false
}

// ── a remote dispatch: dispatch -> transport -> plugin.invoke ────────────────

fn hello_pong_wasm() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong.wasm fixture")
}

fn write_wasm_package(dir: &Path, kp: &IdentityKeyPair) -> PluginId {
    let id = format!("{}/trace-remote@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\ndescription = \"trace\"\n"
    );
    let wasm = hello_pong_wasm();
    std::fs::write(dir.join("entangle.toml"), manifest.as_bytes()).unwrap();
    std::fs::write(dir.join("plugin.wasm"), &wasm).unwrap();
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(&wasm, manifest.as_bytes(), kp))
            .unwrap()
            .as_bytes(),
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

/// Two nodes in one process share this process's span store, so the whole
/// tree is visible: `task.dispatch` -> `remote.dispatch` (the transport leg,
/// carrying the peer and transport) -> `remote.task.execute` on the worker
/// (joined through the `traceparent` on the wire) -> `plugin.invoke`.
#[tokio::test(flavor = "multi_thread")]
async fn a_remote_dispatch_trace_has_dispatch_transport_and_invoke_in_one_tree() {
    let publisher = IdentityKeyPair::generate();
    let a_id = IdentityKeyPair::generate();
    let b_id = IdentityKeyPair::generate();
    let kernel_a = Arc::new(Kernel::new(KernelConfig::default(), keyring_for(&publisher)).unwrap());
    let kernel_b = Arc::new(Kernel::new(KernelConfig::default(), keyring_for(&publisher)).unwrap());
    let ta = Arc::new(MeshIroh::start(loopback_config(), &a_id).await.unwrap());
    let tb = Arc::new(MeshIroh::start(loopback_config(), &b_id).await.unwrap());
    let (a_peer, b_peer) = (ta.local_peer_id(), tb.local_peer_id());

    let dir = tempfile::tempdir().unwrap();
    let plugin = write_wasm_package(dir.path(), &publisher);
    kernel_b.load_plugin_from_dir(dir.path()).await.unwrap();
    let server = Arc::new(RemoteTaskServer::new(
        kernel_b.clone(),
        Arc::new(StaticAllowlist::new().allow(a_peer)),
        Arc::new(CapabilityGate::for_identity(&b_id).unwrap()),
    ));
    tokio::spawn(entangle_scheduler::serve_tasks(tb.clone(), server));

    let pool = WorkerPool::new();
    pool.upsert(WorkerInfo {
        peer_id: b_peer,
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
    let addr = tb
        .local_addrs()
        .into_iter()
        .find(|a| a.ip().is_loopback())
        .unwrap();
    directory.insert(IrohPeer::new(tb.local_public_key(), addr));
    let tokens = StaticTokens::new();
    tokens.paired_with(&b_id, a_peer).unwrap();
    let dispatcher = Dispatcher::new(pool.clone(), kernel_a.clone(), a_peer)
        .with_strict_remote(true)
        .with_remote(Arc::new(
            RemoteDispatch::new(ta.clone() as Arc<dyn MeshTransport>, Arc::new(directory))
                .with_capability_tokens(Arc::new(tokens)),
        ));
    let dispatcher = Arc::new(dispatcher);
    let state = state_for(kernel_a, Dispatcher::clone(&dispatcher), pool);

    let task = OneShotTask {
        id: uuid::Uuid::new_v4(),
        plugin: plugin.clone(),
        input: b"trace".to_vec(),
        max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
        max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        resources: ResourceSpec::default(),
        integrity: IntegrityPolicy::None,
        timeout_ms: 10_000,
    };
    let task_id = task.id.to_string();
    let result = tokio::time::timeout(Duration::from_secs(30), dispatcher.dispatch_one_shot(task))
        .await
        .expect("dispatch finished")
        .expect("remote dispatch");
    assert_eq!(result.output, b"Hello, trace!");

    // Uppercase / dashless spellings find the same trace.
    for spelling in [
        task_id.clone(),
        task_id.to_uppercase(),
        task_id.replace('-', ""),
    ] {
        let v = rpc(&state, "trace/get", serde_json::json!({ "id": spelling })).await;
        assert!(v.get("error").is_none(), "{spelling}: {v}");
    }
    let v = rpc(&state, "trace/get", serde_json::json!({ "id": task_id })).await;
    let t: TraceGetResult = serde_json::from_value(v["result"].clone()).unwrap();
    assert_eq!(t.traces.len(), 1, "{t:?}");
    let trace = &t.traces[0];
    let spans = &trace.spans;
    let one = |n: &str| {
        let m: Vec<&SpanWire> = spans.iter().filter(|s| s.name == n).collect();
        assert_eq!(m.len(), 1, "{n}: {spans:?}");
        m[0]
    };
    let (dispatch, transport, worker, invoke) = (
        one("task.dispatch"),
        one("remote.dispatch"),
        one("remote.task.execute"),
        one("plugin.invoke"),
    );
    // The tree: dispatch > transport > worker execution > plugin.invoke.
    assert_eq!(
        transport.parent_span_id.as_deref(),
        Some(dispatch.span_id.as_str())
    );
    assert_eq!(
        worker.parent_span_id.as_deref(),
        Some(transport.span_id.as_str()),
        "joined via traceparent"
    );
    assert_eq!(
        invoke.parent_span_id.as_deref(),
        Some(worker.span_id.as_str())
    );
    // Kinds, attributes and the worker's own id for the task.
    assert_eq!(
        (transport.kind.as_str(), worker.kind.as_str()),
        ("client", "server")
    );
    assert_attr(transport, "transport", "iroh");
    assert_attr(transport, "peer", &b_peer.to_string());
    assert_attr(worker, "task_id", &task_id);
    assert!(
        dispatch.duration_us >= transport.duration_us
            && transport.duration_us >= worker.duration_us
    );
    // Everything is in this node's store, so no part of the trace is elsewhere.
    assert!(trace.remote_hints.is_empty(), "{:?}", trace.remote_hints);
}

/// The store's cap is configurable and holds under a daemon-sized load.
#[tokio::test(flavor = "multi_thread")]
async fn the_trace_store_cap_comes_from_config_and_holds() {
    let cfg: config::Config = toml::from_str("[telemetry.trace_store]\nmax_spans = 128\n").unwrap();
    let store = TraceStore::new(cfg.telemetry.trace_store.trace_config());
    // Feed it through the real subscriber path: a private subscriber over a
    // thread-local default, spans closed on this thread.
    use tracing_subscriber::prelude::*;
    let sink: Arc<dyn entangle_observability::context::SpanSink> = Arc::new(store.clone());
    let sub =
        tracing_subscriber::registry().with(entangle_observability::context::SpanLayer::new(sink));
    tracing::subscriber::with_default(sub, || {
        for i in 0..400u32 {
            let s = tracing::info_span!(target: "entangle_test", "task.dispatch", task_id = %format!("{i:032x}"));
            let _g = s.enter();
            let _c = tracing::info_span!(target: "entangle_test", "plugin.invoke").entered();
        }
    });
    assert!(store.span_count() <= 128, "{}", store.span_count());
    assert!(store.evicted_traces() > 0);
    assert!(
        store.by_task(&format!("{:032x}", 399)).len() == 1,
        "the newest is kept"
    );
    assert!(
        store.by_task(&format!("{:032x}", 0)).is_empty(),
        "the oldest is gone"
    );
}

/// Every RPC call the daemon answers is a one-span `rpc.request` trace in the
/// store, and `entangle logs --follow` on a chatty source makes thousands of
/// them. They must not push task traces out: after more `logs/read` calls
/// than the store holds traces, the task's trace is still there.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_calls_do_not_evict_task_traces() {
    let state = plain_state();
    let task = uuid::Uuid::new_v4().to_string();
    {
        let root = tracing::info_span!(target: "entangle_test", "task.dispatch", task_id = %task);
        let _g = root.enter();
        let _c = tracing::info_span!(target: "entangle_test", "plugin.invoke").entered();
    }
    for _ in 0..(TraceConfig::DEFAULT_TRACES + 200) {
        logs(
            &state,
            serde_json::json!({ "source": "daemon", "limit": 1 }),
        )
        .await;
    }
    let v = rpc(&state, "trace/get", serde_json::json!({ "id": task })).await;
    assert!(v.get("error").is_none(), "the task trace was evicted: {v}");
    let t: TraceGetResult = serde_json::from_value(v["result"].clone()).unwrap();
    assert_eq!(t.traces.len(), 1, "{t:?}");
    let names: Vec<&str> = t.traces[0].spans.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains(&"task.dispatch") && names.contains(&"plugin.invoke"),
        "{names:?}"
    );
}

/// `max_traces` comes from `[telemetry.trace_store]` and holds.
#[tokio::test(flavor = "multi_thread")]
async fn the_trace_count_cap_comes_from_config_and_holds() {
    let cfg: config::Config = toml::from_str("[telemetry.trace_store]\nmax_traces = 10\n").unwrap();
    let store = TraceStore::new(cfg.telemetry.trace_store.trace_config());
    use tracing_subscriber::prelude::*;
    let sink: Arc<dyn entangle_observability::context::SpanSink> = Arc::new(store.clone());
    let sub =
        tracing_subscriber::registry().with(entangle_observability::context::SpanLayer::new(sink));
    tracing::subscriber::with_default(sub, || {
        for i in 0..50u32 {
            let _s = tracing::info_span!(target: "entangle_test", "task.dispatch", task_id = %format!("{i:032x}")).entered();
        }
    });
    assert_eq!(store.trace_count(), 10);
    assert_eq!(store.by_task(&format!("{:032x}", 49)).len(), 1);
    assert!(store.by_task(&format!("{:032x}", 39)).is_empty());
}

// ── a failed task: the spans that failed say so ──────────────────────────────

fn stress_wasm() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/stress.wasm"
    ))
    .expect("stress.wasm fixture")
}

/// A signed tier-1 wasm package named `name` in `dir`.
fn write_named_package(dir: &Path, kp: &IdentityKeyPair, name: &str, wasm: &[u8]) -> PluginId {
    let id = format!("{}/{name}@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\ndescription = \"trace\"\n"
    );
    std::fs::write(dir.join("entangle.toml"), manifest.as_bytes()).unwrap();
    std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(wasm, manifest.as_bytes(), kp))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    id.parse().unwrap()
}

/// `stress.wasm` answers `spin:<not a number>` with `invalid-input`.
fn failing_task(plugin: &PluginId) -> OneShotTask {
    OneShotTask {
        id: uuid::Uuid::new_v4(),
        plugin: plugin.clone(),
        input: b"spin:not-a-number".to_vec(),
        max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
        max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        resources: ResourceSpec::default(),
        integrity: IntegrityPolicy::None,
        timeout_ms: 10_000,
    }
}

async fn trace_of(state: &Arc<DaemonState>, task_id: &str) -> Vec<SpanWire> {
    let v = rpc(state, "trace/get", serde_json::json!({ "id": task_id })).await;
    assert!(v.get("error").is_none(), "{v}");
    let t: TraceGetResult = serde_json::from_value(v["result"].clone()).unwrap();
    assert_eq!(t.traces.len(), 1, "{t:?}");
    t.traces.into_iter().next().unwrap().spans
}

fn the_span<'a>(spans: &'a [SpanWire], name: &str) -> &'a SpanWire {
    let m: Vec<&SpanWire> = spans.iter().filter(|s| s.name == name).collect();
    assert_eq!(m.len(), 1, "{name}: {spans:?}");
    m[0]
}

fn assert_failed(s: &SpanWire) {
    assert_eq!(s.status, "error", "{} should be failed: {s:?}", s.name);
    assert!(
        s.status_message.as_deref().is_some_and(|m| !m.is_empty()),
        "{} says why it failed: {s:?}",
        s.name
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_local_task_shows_error_on_its_dispatch_and_invoke_spans() {
    let publisher = IdentityKeyPair::generate();
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring_for(&publisher)).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let plugin = write_named_package(dir.path(), &publisher, "trace-fails-local", &stress_wasm());
    kernel.load_plugin_from_dir(dir.path()).await.unwrap();
    let pool = WorkerPool::new();
    let local = PeerId::from_public_key_bytes(IdentityKeyPair::generate().public().as_bytes());
    let dispatcher = Arc::new(Dispatcher::new(pool.clone(), kernel.clone(), local));
    let state = state_for(kernel, Dispatcher::clone(&dispatcher), pool);

    let task = failing_task(&plugin);
    let task_id = task.id.to_string();
    let err = dispatcher
        .dispatch_one_shot(task)
        .await
        .expect_err("the plugin rejects its input");
    let spans = trace_of(&state, &task_id).await;
    let (dispatch, invoke) = (
        the_span(&spans, "task.dispatch"),
        the_span(&spans, "plugin.invoke"),
    );
    assert_failed(invoke);
    assert_failed(dispatch);
    assert!(
        dispatch
            .status_message
            .as_deref()
            .is_some_and(|m| m.contains(&err.to_string()[..12])),
        "the dispatch error is {err}: {dispatch:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_remote_task_shows_error_on_each_span_of_its_tree() {
    let publisher = IdentityKeyPair::generate();
    let a_id = IdentityKeyPair::generate();
    let b_id = IdentityKeyPair::generate();
    let kernel_a = Arc::new(Kernel::new(KernelConfig::default(), keyring_for(&publisher)).unwrap());
    let kernel_b = Arc::new(Kernel::new(KernelConfig::default(), keyring_for(&publisher)).unwrap());
    let ta = Arc::new(MeshIroh::start(loopback_config(), &a_id).await.unwrap());
    let tb = Arc::new(MeshIroh::start(loopback_config(), &b_id).await.unwrap());
    let (a_peer, b_peer) = (ta.local_peer_id(), tb.local_peer_id());

    let dir = tempfile::tempdir().unwrap();
    let plugin = write_named_package(dir.path(), &publisher, "trace-fails-remote", &stress_wasm());
    kernel_b.load_plugin_from_dir(dir.path()).await.unwrap();
    let server = Arc::new(RemoteTaskServer::new(
        kernel_b.clone(),
        Arc::new(StaticAllowlist::new().allow(a_peer)),
        Arc::new(CapabilityGate::for_identity(&b_id).unwrap()),
    ));
    tokio::spawn(entangle_scheduler::serve_tasks(tb.clone(), server));
    let pool = WorkerPool::new();
    pool.upsert(WorkerInfo {
        peer_id: b_peer,
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
    let addr = tb
        .local_addrs()
        .into_iter()
        .find(|a| a.ip().is_loopback())
        .unwrap();
    directory.insert(IrohPeer::new(tb.local_public_key(), addr));
    let tokens = StaticTokens::new();
    tokens.paired_with(&b_id, a_peer).unwrap();
    let dispatcher = Arc::new(
        Dispatcher::new(pool.clone(), kernel_a.clone(), a_peer)
            .with_strict_remote(true)
            .with_remote(Arc::new(
                RemoteDispatch::new(ta.clone() as Arc<dyn MeshTransport>, Arc::new(directory))
                    .with_capability_tokens(Arc::new(tokens)),
            )),
    );
    let state = state_for(kernel_a, Dispatcher::clone(&dispatcher), pool);

    let task = failing_task(&plugin);
    let task_id = task.id.to_string();
    tokio::time::timeout(Duration::from_secs(30), dispatcher.dispatch_one_shot(task))
        .await
        .expect("dispatch finished")
        .expect_err("the worker's plugin rejects its input");
    let spans = trace_of(&state, &task_id).await;
    for name in [
        "task.dispatch",
        "remote.dispatch",
        "remote.task.execute",
        "plugin.invoke",
    ] {
        assert_failed(the_span(&spans, name));
    }
}
