//! Integration tests for the `entangled` UDS JSON-RPC 2.0 server.
//!
//! Each test spins up `entangle_bin::server::serve` against a temporary socket
//! file, connects with `UnixStream`, sends one request line, reads one
//! response line, and asserts on the JSON-RPC 2.0 response envelope.

use entangle_bin::server;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_signing::Keyring;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_kernel() -> Arc<Kernel> {
    Arc::new(
        Kernel::new(KernelConfig::default(), Keyring::new())
            .expect("kernel construction must not fail in tests"),
    )
}

/// Spawn the RPC server task, connect, send `request` (LF appended), return
/// the trimmed response line.
async fn send_recv(socket_path: PathBuf, kernel: Arc<Kernel>, request: &str) -> String {
    let sp = socket_path.clone();
    let k = kernel.clone();
    tokio::spawn(async move {
        let _ = server::serve(sp, k).await;
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
        make_kernel(),
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
async fn invalid_method_returns_minus_32601() {
    let resp = send_recv(
        tmp_sock("badmethod"),
        make_kernel(),
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
        make_kernel(),
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
        make_kernel(),
        r#"{"jsonrpc":"2.0","id":3,"method":"plugins/list","params":{}}"#,
    )
    .await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("response must be valid JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 3);
    assert_eq!(
        v["result"],
        serde_json::json!([]),
        "expected empty plugin list"
    );
    assert!(v.get("error").is_none(), "unexpected error field: {v}");
}
