//! Integration tests for the `entangled` UDS JSON-RPC 2.0 server.
//!
//! Each test spins up `entangle_bin::server::serve` against a temporary socket
//! file, connects with `UnixStream`, sends one request line, reads one
//! response line, and asserts on the JSON-RPC 2.0 response envelope.

use entangle_bin::{server, state::DaemonState};
use entangle_peers::PeerStore;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_state() -> Arc<DaemonState> {
    make_state_with_keyring(Keyring::new())
}

/// Build a `DaemonState` whose kernel trusts the publishers in `keyring`.
fn make_state_with_keyring(keyring: Keyring) -> Arc<DaemonState> {
    let kernel = Arc::new(
        Kernel::new(KernelConfig::default(), keyring)
            .expect("kernel construction must not fail in tests"),
    );
    let worker_pool = WorkerPool::new();
    let identity = IdentityKeyPair::generate();
    let local_peer_id = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let dispatcher = Arc::new(Dispatcher::new(
        worker_pool.clone(),
        kernel.clone(),
        local_peer_id,
    ));
    Arc::new(DaemonState::new(
        kernel,
        dispatcher,
        worker_pool,
        PeerStore::new(),
        identity,
        "test-node".to_owned(),
    ))
}

/// Build a trusted [`Keyring`] containing `keypair`'s public key. Mirrors the
/// `keyring_for` helper in `entangle-runtime`'s test suite.
fn keyring_for(keypair: &IdentityKeyPair) -> Keyring {
    let pub_key = keypair.public();
    let entry = TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "test-publisher".to_owned(),
        added_at: 0,
        note: String::new(),
    };
    let mut kr = Keyring::new();
    kr.add(entry);
    kr
}

/// The committed hello-pong fixture: a real, instantiable component whose
/// `run` export echoes `"Hello, {input}!"` (and `"pong"` on empty input).
fn hello_pong_wasm() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong.wasm fixture not found — run fixtures-src/hello-pong/build.sh")
}

/// Write a complete signed plugin package (manifest + wasm + `.sig`) to `dir`
/// and return the plugin id string. Mirrors `write_plugin_package` in
/// `entangle-runtime`'s test suite: the signature bundle covers both the
/// artifact and the manifest bytes.
fn write_plugin_package(dir: &Path, keypair: &IdentityKeyPair, wasm_bytes: &[u8]) -> String {
    let publisher = keypair.fingerprint_hex();
    let plugin_id_str = format!("{publisher}/test-plugin@0.1.0");
    let manifest_toml = format!(
        r#"[plugin]
id = "{plugin_id_str}"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "rpc integration test plugin"
"#
    );

    std::fs::write(dir.join("entangle.toml"), manifest_toml.as_bytes()).expect("write manifest");
    std::fs::write(dir.join("plugin.wasm"), wasm_bytes).expect("write wasm");

    let bundle = sign_artifact(wasm_bytes, manifest_toml.as_bytes(), keypair);
    let sig_toml = toml::to_string(&bundle).expect("serialize bundle");
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).expect("write sig");

    plugin_id_str
}

/// Spawn `server::serve` on `sock` and return a typed client once the socket
/// is accepting connections.
async fn spawn_and_connect(sock: PathBuf, state: Arc<DaemonState>) -> entangle_rpc::Client {
    let serve_sock = sock.clone();
    tokio::spawn(async move {
        let _ = server::serve(serve_sock, state).await;
    });
    // The client's socket-exists precheck needs the server to have bound; poll
    // `version()` until it round-trips.
    let client = entangle_rpc::Client::new(sock);
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if client.version().await.is_ok() {
            return client;
        }
    }
    panic!("RPC server did not become ready within 1s");
}

/// Spawn the RPC server task, connect, send `request` (LF appended), return
/// the trimmed response line.
async fn send_recv(socket_path: PathBuf, state: Arc<DaemonState>, request: &str) -> String {
    let sp = socket_path.clone();
    let s = state.clone();
    tokio::spawn(async move {
        let _ = server::serve(sp, s).await;
    });

    // Retry connect — the server task may not have bound yet.
    let mut stream = None;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        if let Ok(s) = UnixStream::connect(&socket_path).await {
            stream = Some(s);
            break;
        }
    }
    let mut stream = stream.expect("failed to connect to test RPC server within 300 ms");

    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
    stream.flush().await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    line.trim_end_matches('\n').to_owned()
}

fn tmp_sock(label: &str) -> PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{label}.sock"));
    // Leak TempDir so the directory survives for the duration of the test.
    std::mem::forget(dir);
    path
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn version_rpc_returns_versions() {
    let resp = send_recv(
        tmp_sock("version"),
        make_state(),
        r#"{"jsonrpc":"2.0","id":1,"method":"version","params":{}}"#,
    )
    .await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("response must be valid JSON");
    assert_eq!(v["jsonrpc"], "2.0", "wrong jsonrpc version");
    assert_eq!(v["id"], 1, "wrong id");
    assert!(
        v["result"]["entangled"].is_string(),
        "missing result.entangled"
    );
    assert!(v["result"]["runtime"].is_string(), "missing result.runtime");
    assert!(v["result"]["types"].is_string(), "missing result.types");
    assert!(v.get("error").is_none(), "unexpected error field: {v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn time_rpc_returns_unix_millis() {
    let resp = send_recv(
        tmp_sock("time"),
        make_state(),
        r#"{"jsonrpc":"2.0","id":7,"method":"time","params":{}}"#,
    )
    .await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("response must be valid JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 7);
    let ms = v["result"]["unix_millis"]
        .as_u64()
        .expect("unix_millis must be u64");
    // Wall-clock millis since UNIX epoch should be >= year-2000 timestamp.
    assert!(
        ms > 946_684_800_000,
        "unix_millis looks too small to be wall-clock: {ms}"
    );
    assert!(v.get("error").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_method_returns_minus_32601() {
    let resp = send_recv(
        tmp_sock("badmethod"),
        make_state(),
        r#"{"jsonrpc":"2.0","id":2,"method":"definitely/not/a/real/method","params":{}}"#,
    )
    .await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("response must be valid JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 2);
    assert_eq!(
        v["error"]["code"], -32601,
        "expected -32601 method-not-found"
    );
    assert!(v.get("result").is_none(), "unexpected result field: {v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_json_returns_minus_32700() {
    let resp = send_recv(
        tmp_sock("malformed"),
        make_state(),
        "{ this is not valid json }",
    )
    .await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("response must be valid JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["error"]["code"], -32700, "expected -32700 parse error");
}

#[tokio::test(flavor = "multi_thread")]
async fn plugins_list_returns_empty_list_initially() {
    let resp = send_recv(
        tmp_sock("plugins_list"),
        make_state(),
        r#"{"jsonrpc":"2.0","id":3,"method":"plugins/list","params":{}}"#,
    )
    .await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("response must be valid JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 3);
    // Wire contract: an object `{ "plugins": [] }` (PluginsListResult), not a
    // bare array — this is exactly the shape the typed client decodes.
    assert_eq!(
        v["result"],
        serde_json::json!({ "plugins": [] }),
        "expected empty plugin list object"
    );
    assert!(v.get("error").is_none(), "unexpected error field: {v}");
}

/// End-to-end safety net: drive the real typed [`entangle_rpc::Client`] against
/// a live `server::serve`, exercising `plugins/load` → `plugins/invoke` →
/// `plugins/list` → `plugins/unload` over the wire.
///
/// This is the cross-boundary test that catches wire-contract drift: it fails
/// to *decode* — not merely to assert — if any of these handlers stop speaking
/// the shared result/param types. Loading over RPC requires a trusted keyring
/// and a signed package, so we seed the kernel's keyring with the fixture's
/// signing key and write a signed hello-pong package to a tempdir.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_load_invoke_round_trip_via_typed_client() {
    // 1. Signing keypair + keyring that trusts it.
    let keypair = IdentityKeyPair::generate();
    let keyring = keyring_for(&keypair);
    let state = make_state_with_keyring(keyring);

    // 2. Signed hello-pong package in a tempdir (survives for the test).
    let dir = tempfile::tempdir().expect("tempdir");
    let expected_id = write_plugin_package(dir.path(), &keypair, &hello_pong_wasm());

    // 3. Live server + typed client.
    let client = spawn_and_connect(tmp_sock("round_trip"), state).await;

    // 4. load → the typed client decodes PluginsLoadResult (object, not string).
    let loaded = client
        .plugins_load(dir.path())
        .await
        .expect("plugins/load must round-trip through the typed client");
    assert_eq!(loaded.plugin_id, expected_id, "unexpected loaded plugin id");

    // 5. list → decodes PluginsListResult (object, not bare array) and includes it.
    let listed = client
        .plugins_list()
        .await
        .expect("plugins/list must round-trip through the typed client");
    assert!(
        listed.plugins.contains(&expected_id),
        "loaded plugin should appear in list: {:?}",
        listed.plugins
    );

    // 6. invoke → hello-pong maps "world" to "Hello, world!".
    let out = client
        .plugins_invoke(&loaded.plugin_id, b"world".to_vec(), 30_000)
        .await
        .expect("plugins/invoke must round-trip through the typed client");
    assert_eq!(
        out.output, b"Hello, world!",
        "hello-pong should greet the input"
    );

    // 7. unload → succeeds and empties the list.
    client
        .plugins_unload(&loaded.plugin_id)
        .await
        .expect("plugins/unload must round-trip through the typed client");
    let after = client.plugins_list().await.expect("list after unload");
    assert!(
        after.plugins.is_empty(),
        "list should be empty after unload: {:?}",
        after.plugins
    );
}

/// Negative wire cases over the typed client: an unknown-but-well-formed plugin
/// id yields the application error (-32000); a malformed id yields invalid
/// params (-32602).
#[tokio::test(flavor = "multi_thread")]
async fn plugins_invoke_negative_cases_via_typed_client() {
    let client = spawn_and_connect(tmp_sock("negatives"), make_state()).await;

    // Unknown but well-formed id → the kernel reports "not loaded" → -32000.
    let unknown = "aabbccddeeff00112233445566778899/ghost@0.1.0";
    match client
        .plugins_invoke(unknown, b"world".to_vec(), 30_000)
        .await
    {
        Err(entangle_rpc::RpcError::Rpc { code, .. }) => {
            assert_eq!(code, -32000, "unknown plugin id should be the app error");
        }
        other => panic!("expected -32000 Rpc error, got: {other:?}"),
    }

    // Malformed id (no '/', no '@') → parse failure → -32602 invalid params.
    match client
        .plugins_invoke("not-a-valid-id", b"world".to_vec(), 30_000)
        .await
    {
        Err(entangle_rpc::RpcError::Rpc { code, .. }) => {
            assert_eq!(code, -32602, "malformed id should be invalid params");
        }
        other => panic!("expected -32602 Rpc error, got: {other:?}"),
    }
}
