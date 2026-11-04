//! The daemon's observability surface, end to end: the Prometheus endpoint
//! after real activity, its hardening, the tailnet-state gauge, the
//! `metrics/export` RPC and the `diag/mesh` triage report over loopback iroh.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use entangle_bin::config::MetricsSection;
use entangle_bin::metrics_server::{MetricsServer, CONTENT_TYPE_PROMETHEUS, MAX_CONNECTIONS};
use entangle_bin::state::{DaemonState, MeshDiagSources, TailscaleDiag};
use entangle_bin::{diag, server};
use entangle_mesh_iroh::{IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_SCHEDULER};
use entangle_mesh_tailscale::{
    AclMode, AddressPolicy, LivenessSnapshot, MeshTailscale, MeshTailscaleConfig, TailnetState,
};
use entangle_observability::Registry;
use entangle_peers::{PeerStore, TrustedPeer};
use entangle_rpc::methods::{ComputeDispatchParams, ComputeIntegrity, DiagMeshParams};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::{
    Dispatcher, PeerDirectory, RemoteDispatch, RemoteTaskServer, StaticAllowlist, WorkerPool,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::capability::CapabilityKind;
use entangle_types::peer_id::PeerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

// ── fixtures ─────────────────────────────────────────────────────────────────

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

fn hello_pong_wasm() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong.wasm fixture")
}

fn write_plugin_package(dir: &Path, keypair: &IdentityKeyPair) -> String {
    let wasm = hello_pong_wasm();
    let id = format!("{}/obs-plugin@0.1.0", keypair.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\ndescription = \"observability test\"\n"
    );
    std::fs::write(dir.join("entangle.toml"), manifest.as_bytes()).unwrap();
    std::fs::write(dir.join("plugin.wasm"), &wasm).unwrap();
    let bundle = sign_artifact(&wasm, manifest.as_bytes(), keypair);
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap().as_bytes(),
    )
    .unwrap();
    id
}

/// A daemon state wired the way `main` wires it: one registry shared by the
/// kernel, dispatcher and state.
fn make_state(keyring: Keyring, registry: &Registry, peers: PeerStore) -> Arc<DaemonState> {
    let kernel = Arc::new(
        Kernel::new(KernelConfig::default(), keyring)
            .unwrap()
            .with_metrics(registry.clone()),
    );
    let pool = WorkerPool::new();
    let identity = IdentityKeyPair::generate();
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let dispatcher = Arc::new(
        Dispatcher::new(pool.clone(), kernel.clone(), local).with_metrics(registry.clone()),
    );
    let state = DaemonState::new(kernel, dispatcher, pool, peers, identity, "obs-node".into())
        .with_metrics(registry.clone());
    state.register_collectors();
    Arc::new(state)
}

async fn spawn_rpc(sock: PathBuf, state: Arc<DaemonState>) -> entangle_rpc::Client {
    let s = sock.clone();
    tokio::spawn(async move {
        let _ = server::serve(s, state).await;
    });
    let client = entangle_rpc::Client::new(sock);
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if client.version().await.is_ok() {
            return client;
        }
    }
    panic!("RPC server did not start");
}

fn section(listen: &str, allow: bool) -> MetricsSection {
    MetricsSection {
        enabled: true,
        listen: listen.into(),
        allow_non_loopback: allow,
    }
}

// ── a tiny HTTP/1.1 client and exposition parser ─────────────────────────────

struct Http {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

async fn http(addr: SocketAddr, request: &str) -> Http {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut raw))
        .await
        .expect("server closes the connection")
        .unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Http {
        status,
        headers,
        body: body.to_owned(),
    }
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
}

#[derive(Debug)]
struct Sample {
    name: String,
    labels: BTreeMap<String, String>,
    value: f64,
}

/// Parse Prometheus text format 0.0.4, failing the test on anything malformed:
/// every sample must belong to a family announced by `# TYPE`, with a valid
/// metric name, well-formed quoted labels and a float value.
fn parse_exposition(text: &str) -> (HashMap<String, String>, Vec<Sample>) {
    let mut types = HashMap::new();
    let mut samples = Vec::new();
    let valid_name = |n: &str| {
        !n.is_empty()
            && n.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == ':')
            && n.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    };
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').expect("# TYPE <name> <kind>");
            assert!(valid_name(name), "bad family name {name:?}");
            assert!(
                ["counter", "gauge", "histogram"].contains(&kind),
                "unknown type {kind:?}"
            );
            types.insert(name.to_owned(), kind.to_owned());
            continue;
        }
        if line.starts_with("# HELP ") {
            continue;
        }
        assert!(!line.starts_with('#'), "unexpected comment {line:?}");
        let (series, value) = line.rsplit_once(' ').expect("sample has a value");
        let (name, labels) = match series.split_once('{') {
            Some((name, rest)) => {
                let body = rest.strip_suffix('}').expect("closing brace");
                (name, parse_labels(body))
            }
            None => (series, BTreeMap::new()),
        };
        assert!(valid_name(name), "bad metric name {name:?}");
        let family = ["_bucket", "_sum", "_count"]
            .iter()
            .find_map(|suffix| {
                name.strip_suffix(suffix)
                    .filter(|f| types.get(*f).map(String::as_str) == Some("histogram"))
            })
            .unwrap_or(name);
        assert!(
            types.contains_key(family),
            "sample {name:?} has no preceding # TYPE"
        );
        samples.push(Sample {
            name: name.to_owned(),
            labels,
            value: value.parse().unwrap_or_else(|_| panic!("float {value:?}")),
        });
    }
    (types, samples)
}

fn parse_labels(body: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut chars = body.chars().peekable();
    while chars.peek().is_some() {
        let key: String = chars.by_ref().take_while(|c| *c != '=').collect();
        assert_eq!(chars.next(), Some('"'), "label value must be quoted");
        let mut value = String::new();
        loop {
            match chars.next().expect("unterminated label value") {
                '\\' => value.push(match chars.next().unwrap() {
                    'n' => '\n',
                    c => c,
                }),
                '"' => break,
                c => value.push(c),
            }
        }
        out.insert(key, value);
        if chars.peek() == Some(&',') {
            chars.next();
        }
    }
    out
}

fn find<'a>(samples: &'a [Sample], name: &str, labels: &[(&str, &str)]) -> Option<&'a Sample> {
    samples.iter().find(|s| {
        s.name == name
            && labels
                .iter()
                .all(|(k, v)| s.labels.get(*k).map(String::as_str) == Some(*v))
    })
}

// ═════════════════════════════════════════════════════════════════════════════
// the scrape endpoint
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
async fn scrape_after_real_activity_has_the_expected_families() {
    let publisher = IdentityKeyPair::generate();
    let registry = Registry::new();
    let state = make_state(keyring_for(&publisher), &registry, PeerStore::new());
    let dir = tempfile::tempdir().unwrap();
    let plugin_dir = dir.path().join("plugin");
    std::fs::create_dir(&plugin_dir).unwrap();
    let plugin = write_plugin_package(&plugin_dir, &publisher);
    let client = spawn_rpc(dir.path().join("sock"), state.clone()).await;

    // Real activity: load, invoke, fail an invoke, dispatch through the
    // scheduler, and have the broker deny an undeclared capability.
    client.plugins_load(&plugin_dir).await.expect("load");
    let out = client
        .plugins_invoke(&plugin, b"metrics".to_vec(), 10_000)
        .await
        .expect("invoke");
    assert_eq!(out.output, b"Hello, metrics!");
    client
        .plugins_invoke(
            "0123456789abcdef0123456789abcdef/absent@1.0.0",
            b"x".to_vec(),
            1_000,
        )
        .await
        .expect_err("an unloaded plugin fails");
    client
        .compute_dispatch(ComputeDispatchParams {
            plugin_id: plugin.clone(),
            input: b"dispatch".to_vec(),
            timeout_ms: 10_000,
            cpu_cores: 0.0,
            memory_bytes: 0,
            gpu_required: false,
            gpu_vram_min_bytes: 0,
            integrity: ComputeIntegrity::None,
        })
        .await
        .expect("dispatch");
    let plugin_id = plugin.parse().unwrap();
    // The runtime capability path (HostState::fetch) is still a deny-all stub
    // that never reaches the broker, so a plugin call cannot produce a denial
    // yet. Drive the broker directly to check the daemon's registry is the
    // one attached to it; when `fetch` is wired, replace this with a plugin call.
    state
        .kernel
        .broker()
        .grant(&plugin_id, &CapabilityKind::ComputeCpu)
        .expect_err("the manifest declares no capability");

    let metrics = MetricsServer::start(&section("127.0.0.1:0", false), registry.clone())
        .await
        .expect("start")
        .expect("enabled");
    let resp = http(metrics.local_addr(), &get("/metrics")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers.get("content-type").map(String::as_str),
        Some(CONTENT_TYPE_PROMETHEUS)
    );
    assert_eq!(
        CONTENT_TYPE_PROMETHEUS,
        "text/plain; version=0.0.4; charset=utf-8"
    );

    let (types, samples) = parse_exposition(&resp.body);
    for (family, kind) in [
        ("entangle_plugin_invocations_total", "counter"),
        ("entangle_plugin_invocation_duration_seconds", "histogram"),
        ("entangle_plugin_errors_total", "counter"),
        ("entangle_plugins_loaded", "gauge"),
        ("entangle_plugin_uptime_seconds", "gauge"),
        ("entangle_capability_denials_total", "counter"),
        ("entangle_rpc_requests_total", "counter"),
        ("entangle_rpc_request_duration_seconds", "histogram"),
        ("entangle_integrity_verdicts_total", "counter"),
        ("entangle_scheduler_inflight_tasks", "gauge"),
        ("entangle_scheduler_workers", "gauge"),
        ("entangle_mesh_peers", "gauge"),
        ("entangle_build_info", "gauge"),
        ("entangle_daemon_uptime_seconds", "gauge"),
    ] {
        assert_eq!(
            types.get(family).map(String::as_str),
            Some(kind),
            "family {family}\n{}",
            resp.body
        );
    }

    // Values, not just names.
    let ok = |name, extra: &[(&str, &str)]| {
        let mut labels = vec![("plugin", plugin.as_str())];
        labels.extend_from_slice(extra);
        find(&samples, name, &labels).map(|s| s.value)
    };
    // plugins/invoke + compute/dispatch each ran the plugin once.
    assert_eq!(
        ok("entangle_plugin_invocations_total", &[("outcome", "ok")]),
        Some(2.0)
    );
    assert_eq!(
        find(
            &samples,
            "entangle_plugin_invocations_total",
            &[("plugin", "unknown"), ("outcome", "error")]
        )
        .map(|s| s.value),
        Some(1.0),
        "a call for an unloaded plugin must not mint a plugin label"
    );
    assert_eq!(
        ok("entangle_plugin_invocation_duration_seconds_count", &[]),
        Some(2.0)
    );
    assert!(ok("entangle_plugin_invocation_duration_seconds_sum", &[]).unwrap() > 0.0);
    assert!(find(
        &samples,
        "entangle_plugin_invocation_duration_seconds_bucket",
        &[("plugin", &plugin), ("le", "+Inf")]
    )
    .is_some());
    assert_eq!(
        find(&samples, "entangle_plugins_loaded", &[]).map(|s| s.value),
        Some(1.0)
    );
    assert!(ok("entangle_plugin_uptime_seconds", &[]).unwrap() >= 0.0);
    assert_eq!(
        find(
            &samples,
            "entangle_capability_denials_total",
            &[("capability", "compute.cpu"), ("reason", "not_declared")]
        )
        .map(|s| s.value),
        Some(1.0)
    );
    assert_eq!(
        find(
            &samples,
            "entangle_integrity_verdicts_total",
            &[("policy", "none"), ("outcome", "accepted")]
        )
        .map(|s| s.value),
        Some(1.0)
    );
    assert_eq!(
        find(
            &samples,
            "entangle_rpc_requests_total",
            &[("method", "plugins/invoke"), ("outcome", "ok")]
        )
        .map(|s| s.value),
        Some(1.0)
    );
    assert_eq!(
        find(
            &samples,
            "entangle_rpc_requests_total",
            &[("method", "plugins/invoke"), ("outcome", "error")]
        )
        .map(|s| s.value),
        Some(1.0)
    );
    assert_eq!(
        find(&samples, "entangle_scheduler_inflight_tasks", &[]).map(|s| s.value),
        Some(0.0)
    );
    assert!(find(&samples, "entangle_mesh_peers", &[("state", "trusted")]).is_some());
    // The tailnet gauge exists only while the transport does.
    assert!(!resp.body.contains("entangle_mesh_tailscale_state"));
    // No label anywhere carries a peer id (32 hex chars).
    for s in &samples {
        for (k, v) in &s.labels {
            assert!(
                !(v.len() == 32 && v.chars().all(|c| c.is_ascii_hexdigit())),
                "label {k}={v} looks like a peer id"
            );
        }
    }

    // The same text over RPC (this is what `entangle metrics` prints).
    let via_rpc = client.metrics_export().await.expect("metrics/export");
    let (rpc_types, _) = parse_exposition(&via_rpc.text);
    assert!(rpc_types.contains_key("entangle_plugin_invocations_total"));
    // ...and that call is itself counted by the next export.
    let again = client.metrics_export().await.expect("metrics/export");
    let (_, again_samples) = parse_exposition(&again.text);
    assert!(
        find(
            &again_samples,
            "entangle_rpc_requests_total",
            &[("method", "metrics/export"), ("outcome", "ok")]
        )
        .is_some_and(|s| s.value >= 1.0),
        "{}",
        again.text
    );

    metrics.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_loopback_address_is_refused_unless_opted_in() {
    let registry = Registry::new();
    let err = MetricsServer::start(&section("0.0.0.0:0", false), registry.clone())
        .await
        .err()
        .expect("must refuse");
    assert!(err.to_string().contains("ENTANGLE-E0656"), "{err}");

    // With the explicit opt-in it binds (all interfaces) and serves.
    let server = MetricsServer::start(&section("0.0.0.0:0", true), registry.clone())
        .await
        .expect("opted in")
        .expect("enabled");
    let port = server.local_addr().port();
    let resp = http(SocketAddr::from(([127, 0, 0, 1], port)), &get("/metrics")).await;
    assert_eq!(resp.status, 200);
    server.shutdown().await;

    // A malformed address is E0655 and a disabled section is never validated.
    let err = MetricsServer::start(&section("localhost:9464", false), registry.clone())
        .await
        .err()
        .expect("must refuse");
    assert!(err.to_string().contains("ENTANGLE-E0655"), "{err}");
    let off = MetricsSection {
        enabled: false,
        listen: "garbage".into(),
        allow_non_loopback: false,
    };
    assert!(MetricsServer::start(&off, registry)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn routes_and_methods() {
    let registry = Registry::new();
    registry.inc_counter("probe_total", "probe", &[], 3.0);
    let server = MetricsServer::start(&section("127.0.0.1:0", false), registry)
        .await
        .unwrap()
        .unwrap();
    let addr = server.local_addr();

    // 404 elsewhere, including near-misses.
    for path in ["/", "/metric", "/metrics/", "/healthz", "/%6Detrics"] {
        let r = http(addr, &get(path)).await;
        assert_eq!(r.status, 404, "{path}");
    }
    // A query string does not change the route.
    let r = http(addr, &get("/metrics?name=probe")).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("probe_total 3"));

    // HEAD: same headers (with the body's length), no body.
    let head = http(
        addr,
        "HEAD /metrics HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert!(head.headers["content-length"].parse::<usize>().unwrap() > 0);

    // Everything else on /metrics is 405 with an Allow header.
    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let r = http(
            addr,
            &format!("{method} /metrics HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(r.status, 405, "{method}");
        assert_eq!(
            r.headers.get("allow").map(String::as_str),
            Some("GET, HEAD")
        );
    }
    server.shutdown().await;
}

/// Every method the daemon routes is counted under its own `method` label,
/// not folded into `unknown` (the label set is a separate list in the
/// observability catalogue, so a newly routed method must be added there).
/// The routed set is `method::ALL`, checked below against every method
/// constant `entangle-rpc` defines, so `perms/*`, `security/*` and any later
/// method cannot be left out of the catalogue unnoticed.
#[tokio::test(flavor = "multi_thread")]
async fn every_routed_rpc_method_has_its_own_metric_label() {
    use entangle_observability::catalog::RPC_METHODS;
    use entangle_rpc::methods::method;
    let registry = Registry::new();
    let state = make_state(Keyring::new(), &registry, PeerStore::new());
    let routed = method::ALL;
    for m in [method::PERMS_LIST, method::PERMS_REVOKE] {
        assert!(routed.contains(&m), "{m} is not in method::ALL");
    }
    let mut catalogued: Vec<&str> = RPC_METHODS.to_vec();
    let mut all: Vec<&str> = routed.to_vec();
    catalogued.sort_unstable();
    all.sort_unstable();
    assert_eq!(
        catalogued, all,
        "observability's RPC_METHODS must list exactly the routed methods"
    );
    for (i, m) in routed.iter().enumerate() {
        // Parameters do not matter: an invalid-params error is still counted
        // under the method's own label.
        let line = format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"{m}"}}"#);
        let resp = entangle_bin::methods::dispatch(&line, &state).await;
        assert!(
            !resp.contains("method not found"),
            "{m} is not routed: {resp}"
        );
        let counted = ["ok", "error"].iter().any(|outcome| {
            registry
                .value(
                    "entangle_rpc_requests_total",
                    &[("method", m), ("outcome", outcome)],
                )
                .is_some()
        });
        assert!(counted, "{m} was not counted under its own method label");
    }
    assert_eq!(
        registry.value(
            "entangle_rpc_requests_total",
            &[("method", "unknown"), ("outcome", "error")]
        ),
        None
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_are_capped_and_stalled_clients_are_reaped() {
    let header_timeout = Duration::from_secs(1);
    let server = MetricsServer::start_with_timeouts(
        &section("127.0.0.1:0", false),
        Registry::new(),
        header_timeout,
        Duration::from_secs(15),
    )
    .await
    .unwrap()
    .unwrap();
    let addr = server.local_addr();

    // Fill every slot with a client that connects and says nothing.
    let mut idle = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // One more is closed immediately instead of queueing.
    let mut extra = TcpStream::connect(addr).await.unwrap();
    let _ = extra.write_all(get("/metrics").as_bytes()).await;
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(2), extra.read_to_end(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(_)) | Ok(Err(_))) && !String::from_utf8_lossy(&buf).contains("200 OK"),
        "an over-cap connection must not be served: {:?}",
        String::from_utf8_lossy(&buf)
    );

    // The stalled clients are reaped once the header timeout passes, freeing
    // the slots: a real scrape then works.
    tokio::time::sleep(header_timeout + Duration::from_secs(1)).await;
    let ok = http(addr, &get("/metrics")).await;
    assert_eq!(ok.status, 200);
    for mut s in idle {
        let mut b = Vec::new();
        let r = tokio::time::timeout(Duration::from_secs(1), s.read_to_end(&mut b)).await;
        assert!(
            r.is_ok(),
            "an idle connection must have been closed by the server"
        );
    }
    server.shutdown().await;
}

// ═════════════════════════════════════════════════════════════════════════════
// the tailnet state gauge
// ═════════════════════════════════════════════════════════════════════════════

fn snapshot(state: Option<TailnetState>, n: u64) -> LivenessSnapshot {
    LivenessSnapshot {
        state,
        since: None,
        transitions: n,
    }
}

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tailscale_gauge_follows_the_liveness_watch_channel() {
    let registry = Registry::new();
    let (tx, rx) = watch::channel(snapshot(None, 0));
    let task = entangle_bin::tailscale::spawn_state_metrics(registry.clone(), rx);

    let state = |s: &str| registry.value("entangle_mesh_tailscale_state", &[("state", s)]);
    // Before the first poll: unknown.
    assert!(eventually(|| state("unknown") == Some(1.0)).await);

    tx.send(snapshot(Some(TailnetState::Active), 1)).unwrap();
    assert!(eventually(|| state("active") == Some(1.0)).await);
    tx.send(snapshot(
        Some(TailnetState::Stopped {
            reason: "NeedsLogin".into(),
        }),
        2,
    ))
    .unwrap();
    assert!(eventually(|| state("stopped") == Some(1.0)).await);
    tx.send(snapshot(Some(TailnetState::Uninstalled), 3))
        .unwrap();
    assert!(eventually(|| state("uninstalled") == Some(1.0)).await);

    // One-hot: exactly one state is 1 at any time.
    let sum: f64 = ["active", "stopped", "uninstalled", "unknown"]
        .iter()
        .map(|s| state(s).unwrap())
        .sum();
    assert_eq!(sum, 1.0);

    drop(tx);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("the watcher ends when the poller goes away")
        .unwrap();
}

// ═════════════════════════════════════════════════════════════════════════════
// diag/mesh over loopback iroh
// ═════════════════════════════════════════════════════════════════════════════

fn loopback_scheduler_config() -> MeshIrohConfig {
    MeshIrohConfig {
        alpn: ALPN_SCHEDULER.to_vec(),
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(10),
        ..MeshIrohConfig::loopback()
    }
}

fn loopback_peer(t: &MeshIroh) -> IrohPeer {
    let addr = t
        .local_addrs()
        .into_iter()
        .find(|a| a.ip().is_loopback())
        .unwrap();
    IrohPeer::new(t.local_public_key(), addr)
}

fn trusted(id: PeerId, key: [u8; 32], name: &str) -> TrustedPeer {
    TrustedPeer::new(id, hex::encode(key), name.into())
}

#[tokio::test(flavor = "multi_thread")]
async fn diag_mesh_reports_paths_and_probes_round_trips() {
    // Two real endpoints: A is "us", B serves tasks and trusts A, C trusts
    // nobody (reachable but refuses us), and G is a trusted peer with an
    // address that nothing listens on.
    let (id_a, id_b, id_c) = (
        IdentityKeyPair::generate(),
        IdentityKeyPair::generate(),
        IdentityKeyPair::generate(),
    );
    let a = Arc::new(
        MeshIroh::start(loopback_scheduler_config(), &id_a)
            .await
            .unwrap(),
    );
    let b = Arc::new(
        MeshIroh::start(loopback_scheduler_config(), &id_b)
            .await
            .unwrap(),
    );
    let c = Arc::new(
        MeshIroh::start(loopback_scheduler_config(), &id_c)
            .await
            .unwrap(),
    );
    let kernel = || Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap());
    for (node, allow) in [
        (&b, StaticAllowlist::new().allow(a.local_peer_id())),
        (&c, StaticAllowlist::new()),
    ] {
        let server = Arc::new(RemoteTaskServer::new(
            kernel(),
            Arc::new(allow),
            node.local_peer_id(),
        ));
        tokio::spawn(entangle_scheduler::serve_tasks(Arc::clone(node), server));
    }

    let ghost_key = IdentityKeyPair::generate();
    let ghost_id = PeerId::from_public_key_bytes(ghost_key.public().as_bytes());
    // Keep the socket bound (and unread) for the whole test, so no other
    // process can take the port and answer the probe.
    let dead_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_port = dead_socket.local_addr().unwrap().port();
    let ghost = IrohPeer::new(
        *ghost_key.public().as_bytes(),
        SocketAddr::from(([127, 0, 0, 1], dead_port)),
    );
    let stranger = PeerId::from_public_key_bytes(IdentityKeyPair::generate().public().as_bytes());

    let peers = PeerStore::new();
    for (id, key, name) in [
        (b.local_peer_id(), b.local_public_key(), "node-b"),
        (c.local_peer_id(), c.local_public_key(), "node-c"),
        (ghost_id, *ghost_key.public().as_bytes(), "ghost"),
    ] {
        peers.add(trusted(id, key, name)).unwrap();
    }
    // A trusted peer no transport knows an address for.
    let lost_key = IdentityKeyPair::generate();
    let lost_id = PeerId::from_public_key_bytes(lost_key.public().as_bytes());
    peers
        .add(trusted(lost_id, *lost_key.public().as_bytes(), "lost"))
        .unwrap();
    let _ = stranger;

    let directory = PeerDirectory::new();
    for p in [loopback_peer(&b), loopback_peer(&c), ghost] {
        directory.insert(p);
    }
    let registry = Registry::new();
    let kernel_a = Arc::new(
        Kernel::new(KernelConfig::default(), Keyring::new())
            .unwrap()
            .with_metrics(registry.clone()),
    );
    let pool = WorkerPool::new();
    let dispatcher = Arc::new(
        Dispatcher::new(pool.clone(), kernel_a.clone(), a.local_peer_id()).with_remote(Arc::new(
            RemoteDispatch::new(
                Arc::clone(&a) as Arc<dyn MeshTransport>,
                Arc::new(directory.clone()),
            ),
        )),
    );
    // A tailscale transport on loopback, "stopped" per the liveness channel.
    let ts = MeshTailscale::start(
        &IdentityKeyPair::generate(),
        MeshTailscaleConfig {
            acl_mode: AclMode::TrustTailnet,
            bind_ip: [127, 0, 0, 1].into(),
            port: 0,
            address_policy: AddressPolicy::Any,
            ..MeshTailscaleConfig::default()
        },
    )
    .await
    .unwrap();
    let (_live_tx, live_rx) = watch::channel(snapshot(
        Some(TailnetState::Stopped {
            reason: "NeedsLogin".into(),
        }),
        2,
    ));
    let state = Arc::new(
        DaemonState::new(
            kernel_a,
            dispatcher,
            pool,
            peers,
            IdentityKeyPair::generate(),
            "node-a".into(),
        )
        .with_metrics(registry)
        .with_diag(MeshDiagSources {
            configured_transports: vec!["iroh".into(), "tailscale".into(), "local".into()],
            iroh: Some(Arc::clone(&a)),
            iroh_directory: Some(directory),
            tailscale: Some(TailscaleDiag {
                transport: ts.clone(),
                liveness: live_rx,
            }),
            metrics_listen: Some(SocketAddr::from(([127, 0, 0, 1], 9464))),
        }),
    );

    // ── without --probe: structure only, no round trips ────────────────────
    let plain = diag::mesh_report(&state, false, Duration::ZERO).await;
    assert!(!plain.probed);
    assert_eq!(plain.local_display_name, "node-a");
    assert_eq!(plain.transports_configured, ["iroh", "tailscale", "local"]);
    assert_eq!(
        plain.transports_active,
        ["iroh", "tailscale"],
        "local has no discovery handle"
    );
    let transports: Vec<_> = plain
        .endpoints
        .iter()
        .map(|e| e.transport.as_str())
        .collect();
    assert!(transports.contains(&"iroh") && transports.contains(&"tailscale"));
    assert!(plain
        .endpoints
        .iter()
        .any(|e| e.transport == "metrics" && e.address == "127.0.0.1:9464"));
    let tail = plain.tailscale.as_ref().expect("tailscale section");
    assert_eq!(
        (tail.state.as_str(), tail.reason.as_deref()),
        ("stopped", Some("NeedsLogin"))
    );
    assert_eq!(plain.peers.len(), 4);
    let by_name = |name: &str| plain.peers.iter().find(|p| p.display_name == name).unwrap();
    assert!(by_name("node-b").paths.iter().any(|p| p.transport == "iroh"
        && p.address.as_deref() == Some(&loopback_peer(&b).addr.to_string())));
    assert!(
        by_name("lost").paths.is_empty(),
        "no transport knows this peer"
    );
    assert!(plain
        .peers
        .iter()
        .flat_map(|p| &p.paths)
        .all(|p| p.rtt_ms.is_none() && p.probe_error.is_none()));

    // ── with --probe ───────────────────────────────────────────────────────
    let probed = diag::mesh_report(&state, true, Duration::from_secs(4)).await;
    assert!(probed.probed);
    let iroh_path = |name: &str| {
        probed
            .peers
            .iter()
            .find(|p| p.display_name == name)
            .and_then(|p| p.paths.iter().find(|x| x.transport == "iroh"))
            .cloned()
            .unwrap()
    };
    let b_path = iroh_path("node-b");
    assert!(b_path.rtt_ms.is_some_and(|ms| ms > 0.0), "{b_path:?}");
    assert_eq!(
        b_path.probe_error, None,
        "an authorized peer answers cleanly"
    );
    let c_path = iroh_path("node-c");
    assert!(
        c_path.rtt_ms.is_some(),
        "the refusing peer was still reached: {c_path:?}"
    );
    assert!(
        c_path
            .probe_error
            .as_deref()
            .is_some_and(|e| e.contains("NotAuthorized")),
        "{c_path:?}"
    );
    let ghost_path = iroh_path("ghost");
    assert_eq!(ghost_path.rtt_ms, None);
    assert!(ghost_path.probe_error.is_some(), "{ghost_path:?}");
    assert!(probed
        .peers
        .iter()
        .find(|p| p.display_name == "lost")
        .unwrap()
        .paths
        .is_empty());

    // ── through the RPC socket, as the CLI calls it ────────────────────────
    let dir = tempfile::tempdir().unwrap();
    let client = spawn_rpc(dir.path().join("sock"), state.clone()).await;
    let via_rpc = client
        .diag_mesh(DiagMeshParams {
            probe: false,
            probe_timeout_ms: 0,
        })
        .await
        .unwrap();
    assert_eq!(via_rpc.peers.len(), 4);
    assert_eq!(via_rpc.transports_active, plain.transports_active);

    ts.shutdown().await;
    drop(dead_socket);
}

/// `entangle_mesh_peers` counts every trust level separately: an Observer is
/// not a Trusted peer (it cannot push tasks), and `diag mesh` agrees.
#[tokio::test(flavor = "multi_thread")]
async fn mesh_peer_gauge_separates_trusted_observer_and_revoked() {
    let store = PeerStore::new();
    for (seed, name) in [(1u8, "a"), (2, "b"), (3, "c")] {
        let key = [seed; 32];
        let id = PeerId::from_public_key_bytes(&key);
        store
            .add(TrustedPeer::new(id, hex::encode(key), name.into()))
            .unwrap();
    }
    let id_of = |seed: u8| PeerId::from_public_key_bytes(&[seed; 32]);
    store.revoke(&id_of(3)).unwrap();
    // No public setter for Observer: rewrite the entry through the store.
    let mut observer = store.get(&id_of(2)).unwrap();
    observer.trust = entangle_peers::TrustLevel::Observer;
    store.remove(&id_of(2)).unwrap();
    store.add(observer).unwrap();

    let registry = Registry::new();
    let _state = make_state(Keyring::new(), &registry, store);
    let (_, samples) = parse_exposition(&registry.render());
    let n =
        |state: &str| find(&samples, "entangle_mesh_peers", &[("state", state)]).map(|s| s.value);
    assert_eq!(n("trusted"), Some(1.0));
    assert_eq!(n("observer"), Some(1.0));
    assert_eq!(n("revoked"), Some(1.0));
}

/// The overall connection timeout reaps a client that the header timeout
/// does not: here the header timeout is effectively disabled and a client
/// that starts a request line but never finishes the headers must still be
/// closed once the total budget is spent.
#[tokio::test(flavor = "multi_thread")]
async fn the_total_connection_timeout_reaps_a_stalled_client() {
    let server = MetricsServer::start_with_timeouts(
        &section("127.0.0.1:0", false),
        Registry::new(),
        Duration::from_secs(3600),
        Duration::from_millis(500),
    )
    .await
    .unwrap()
    .unwrap();
    let mut s = TcpStream::connect(server.local_addr()).await.unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut b = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut b)).await;
    assert!(
        r.is_ok(),
        "the server must close the connection at the total timeout"
    );
    assert!(b.is_empty(), "no response is owed to an unfinished request");
    server.shutdown().await;
}

/// `method::ALL` lists every method constant `entangle-rpc` defines (a
/// scan of its source), so a new method cannot be routed without also
/// being in the set the label test above walks.
#[test]
fn method_all_lists_every_method_constant() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-rpc/src/methods.rs"
    ))
    .expect("read entangle-rpc/src/methods.rs");
    let module = src
        .split("pub mod method {")
        .nth(1)
        .expect("the `method` module");
    let defined: Vec<&str> = module
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub const "))
        .filter(|l| l.contains(": &str = \""))
        .filter_map(|l| l.split('"').nth(1))
        .collect();
    assert!(defined.len() >= 16, "{defined:?}");
    let all = entangle_rpc::methods::method::ALL;
    for m in &defined {
        assert!(all.contains(m), "{m} is missing from method::ALL");
    }
    assert_eq!(all.len(), defined.len(), "{all:?} vs {defined:?}");
}

/// `diag/mesh` over the tailnet: the daemon's own wiring (`mesh::
/// scheduler_servers` served with `serve_tailscale`, `mesh::build_router`)
/// on loopback. A trusted peer known on the tailnet shows its route (the
/// order dispatch would try, what it skips), the transport the last request
/// used, and a probe that speaks the scheduler protocol over the tailnet.
#[tokio::test(flavor = "multi_thread")]
async fn diag_mesh_shows_the_chosen_transport_and_probes_the_tailnet_path() {
    use entangle_bin::mesh::{build_router, scheduler_servers, RouterInputs};
    use entangle_mesh_tailscale::TailscaleStatus;
    use entangle_scheduler::{ControlAction, ControlFrame, RemoteErrorCode};

    let loopback_tailnet = |acl| MeshTailscaleConfig {
        acl_mode: acl,
        bind_ip: [127, 0, 0, 1].into(),
        port: 0,
        address_policy: AddressPolicy::Any,
        ..MeshTailscaleConfig::default()
    };
    let (id_a, id_b) = (IdentityKeyPair::generate(), IdentityKeyPair::generate());
    let peer = |k: &IdentityKeyPair| PeerId::from_public_key_bytes(k.public().as_bytes());

    // B: the daemon's servers on its tailnet listener; B trusts A.
    let b_store = PeerStore::new();
    b_store
        .add(trusted(peer(&id_a), *id_a.public().as_bytes(), "node-a"))
        .unwrap();
    let b_ts = MeshTailscale::start(&id_b, loopback_tailnet(AclMode::TrustTailnet))
        .await
        .unwrap();
    let b_served = Registry::new();
    let servers = scheduler_servers(
        Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap()),
        b_store,
        id_b.clone(),
        Some(b_served.clone()),
    );
    tokio::spawn(entangle_scheduler::serve_tailscale(
        b_ts.clone(),
        Some(servers.tasks.clone()),
        Some(servers.streams.clone()),
    ));

    // A: tailnet only, B discovered on loopback, tailnet active.
    let a_ts = MeshTailscale::start(&id_a, loopback_tailnet(AclMode::EntangleOnTop))
        .await
        .unwrap();
    let status = TailscaleStatus::parse(
        r#"{"BackendState":"Running","Self":{"Online":true},
           "Peer":{"b":{"Online":true,"DNSName":"b.t.ts.net.","TailscaleIPs":["127.0.0.1"]}}}"#,
    )
    .unwrap();
    assert_eq!(
        a_ts.discover_on_port(&status, b_ts.local_addr().port())
            .await
            .len(),
        1
    );
    let (_live_tx, live_rx) = watch::channel(snapshot(Some(TailnetState::Active), 1));
    let router = build_router(
        peer(&id_a),
        RouterInputs {
            tailscale: Some((a_ts.clone(), live_rx.clone())),
            ..RouterInputs::default()
        },
    )
    .expect("a running transport gives a router");
    let remote = Arc::new(RemoteDispatch::with_router(Arc::new(router)));
    let kernel_a = Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap());
    let pool = WorkerPool::new();
    let peers = PeerStore::new();
    peers
        .add(trusted(peer(&id_b), *id_b.public().as_bytes(), "node-b"))
        .unwrap();
    let state = DaemonState::new(
        kernel_a.clone(),
        Arc::new(Dispatcher::new(pool.clone(), kernel_a, peer(&id_a)).with_remote(remote.clone())),
        pool,
        peers,
        id_a.clone(),
        "node-a".into(),
    )
    .with_diag(MeshDiagSources {
        configured_transports: vec!["tailscale".into()],
        iroh: None,
        iroh_directory: None,
        tailscale: Some(TailscaleDiag {
            transport: a_ts.clone(),
            liveness: live_rx,
        }),
        metrics_listen: None,
    });

    // Before any traffic: the route is planned, nothing used yet.
    let report = diag::mesh_report(&state, false, Duration::ZERO).await;
    let b = &report.peers[0];
    let route = b.route.as_ref().expect("a route section");
    assert_eq!(route.order, ["tailscale"]);
    assert!(route
        .skipped
        .iter()
        .any(|s| s.starts_with("iroh: not running")));
    assert_eq!(route.last_used, None);

    // One routed request (a control frame naming no task: executes nothing).
    let frame = ControlFrame {
        task_id: [1; 16],
        action: ControlAction::SetPolicy {
            policy: Vec::new(),
            policy_hash: entangle_scheduler::work_unit::hash_canonical(&[]),
        },
    };
    let answer = remote
        .send_control(peer(&id_b), frame, Duration::from_secs(10))
        .await;
    assert!(
        matches!(
            answer,
            Err(entangle_scheduler::DispatchError::RemoteRejected {
                code: RemoteErrorCode::UnknownTask,
                ..
            })
        ),
        "{answer:?}"
    );

    let probed = diag::mesh_report(&state, true, Duration::from_secs(10)).await;
    let b = &probed.peers[0];
    assert_eq!(
        b.route.as_ref().and_then(|r| r.last_used.as_deref()),
        Some("tailscale"),
        "the chosen transport is on the peer record"
    );
    let path = b.paths.iter().find(|p| p.transport == "tailscale").unwrap();
    assert!(path.rtt_ms.is_some(), "{path:?}");
    assert_eq!(path.probe_error, None, "{path:?}");
    assert_eq!(
        b_served.value(
            entangle_observability::catalog::names::REMOTE_SERVE,
            &[("outcome", "unknown-task"), ("transport", "tailscale")]
        ),
        Some(2.0),
        "the request and the probe both arrived over the tailnet"
    );
    a_ts.shutdown().await;
    b_ts.shutdown().await;
}
