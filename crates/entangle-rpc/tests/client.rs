use entangle_rpc::{Client, RpcError};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Spin up a fake UDS server that accepts one connection, reads one line,
/// and replies with `reply_json`, then shuts down.
async fn fake_server(sock_path: PathBuf, reply_json: &'static str) {
    let listener = UnixListener::bind(&sock_path).expect("bind");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (rd, mut wr) = stream.into_split();
        let mut lines = BufReader::new(rd).lines();
        // consume the request line
        let _ = lines.next_line().await;
        wr.write_all(reply_json.as_bytes()).await.expect("write");
        wr.write_all(b"\n").await.expect("write newline");
        wr.flush().await.expect("flush");
    });
}

#[tokio::test]
async fn test_version_happy_path() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"entangled":"0.1.0","runtime":"wasmtime-43","types":"0.1.0"}}"#,
    )
    .await;

    // give the listener a moment to be ready
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let v = client.version().await.expect("version call");
    assert_eq!(v.entangled, "0.1.0");
    assert_eq!(v.runtime, "wasmtime-43");
    assert_eq!(v.types, "0.1.0");
}

#[tokio::test]
async fn test_plugins_load_returns_plugin_id() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"plugin_id":"my-plugin-abc123"}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let res = client
        .plugins_load("/opt/plugins/my-plugin")
        .await
        .expect("plugins_load");
    assert_eq!(res.plugin_id, "my-plugin-abc123");
}

#[tokio::test]
async fn test_rpc_error_method_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let err = client.version().await.expect_err("should be rpc error");

    match err {
        RpcError::Rpc { code, message } => {
            assert_eq!(code, -32601);
            assert_eq!(message, "method not found");
        }
        other => panic!("expected RpcError::Rpc, got {other:?}"),
    }
}

#[tokio::test]
async fn test_daemon_not_running() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    // socket file is never created — simulates daemon not running

    let client = Client::new(&sock);
    let err = client.version().await.expect_err("should be not running");

    assert!(
        matches!(err, RpcError::DaemonNotRunning(_)),
        "expected DaemonNotRunning, got {err:?}"
    );
}

#[tokio::test]
async fn test_malformed_response() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    // Server sends garbage instead of valid JSON-RPC
    fake_server(sock.clone(), "this is not json at all!!!").await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let err = client.version().await.expect_err("should be malformed");

    assert!(
        matches!(err, RpcError::Json(_)),
        "expected RpcError::Json for garbage, got {err:?}"
    );
}

#[tokio::test]
async fn test_malformed_missing_result_field() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    // Valid JSON but neither `result` nor `error` field
    fake_server(sock.clone(), r#"{"jsonrpc":"2.0","id":1}"#).await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let err = client.version().await.expect_err("should be malformed");

    assert!(
        matches!(err, RpcError::Malformed(_)),
        "expected RpcError::Malformed, got {err:?}"
    );
}
