//! Tests for the `compute/dispatch` RPC method types and client.

use entangle_rpc::{
    methods::{ComputeDispatchParams, ComputeDispatchResult, ComputeIntegrity},
    Client, RpcError,
};
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
async fn compute_dispatch_returns_typed_result_from_fake_server() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("compute_test.sock");

    // The fake server returns a structured ComputeDispatchResult JSON.
    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"chosen_peer":"aabbccdd","score":0.87,"reason":"fit ok, rtt=1ms, bw=1000000000 bps, load=0.10, cost=1.00","output":[104,101,108,108,111]}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let params = ComputeDispatchParams {
        plugin_id: "pub/myplugin@0.1.0".into(),
        input: b"test-input".to_vec(),
        timeout_ms: 5_000,
        cpu_cores: 0.0,
        memory_bytes: 0,
        gpu_required: false,
        gpu_vram_min_bytes: 0,
        integrity: ComputeIntegrity::None,
    };
    let result: ComputeDispatchResult = client
        .compute_dispatch(params)
        .await
        .expect("compute_dispatch should succeed");

    assert_eq!(result.chosen_peer, "aabbccdd");
    assert!((result.score - 0.87).abs() < 0.01, "score mismatch");
    assert!(
        result.reason.contains("fit ok"),
        "reason should mention 'fit ok', got: {}",
        result.reason
    );
    assert_eq!(result.output, b"hello", "output bytes mismatch");
}

#[tokio::test]
async fn compute_dispatch_deterministic_integrity_serialises() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("compute_det.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"chosen_peer":"aabb","score":1.0,"reason":"ok","output":[]}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let params = ComputeDispatchParams {
        plugin_id: "pub/plugin@0.1.0".into(),
        input: vec![],
        timeout_ms: 1_000,
        cpu_cores: 0.0,
        memory_bytes: 0,
        gpu_required: false,
        gpu_vram_min_bytes: 0,
        integrity: ComputeIntegrity::Deterministic { replicas: 3 },
    };
    let result = client
        .compute_dispatch(params)
        .await
        .expect("should succeed");
    assert_eq!(result.chosen_peer, "aabb");
}

#[tokio::test]
async fn compute_dispatch_trusted_executor_integrity_serialises() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("compute_te.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"chosen_peer":"ccdd","score":0.5,"reason":"trusted","output":[1,2,3]}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let params = ComputeDispatchParams {
        plugin_id: "pub/plugin@0.1.0".into(),
        input: vec![],
        timeout_ms: 1_000,
        cpu_cores: 0.0,
        memory_bytes: 0,
        gpu_required: false,
        gpu_vram_min_bytes: 0,
        integrity: ComputeIntegrity::TrustedExecutor {
            allowlist: vec!["deadbeef".into(), "cafebabe".into()],
        },
    };
    let result = client
        .compute_dispatch(params)
        .await
        .expect("should succeed");
    assert_eq!(result.output, vec![1u8, 2, 3]);
}

#[tokio::test]
async fn compute_dispatch_no_daemon_returns_not_running() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("no_daemon.sock");
    // Never create the socket file.

    let client = Client::new(&sock);
    let params = ComputeDispatchParams {
        plugin_id: "pub/plugin@0.1.0".into(),
        input: vec![],
        timeout_ms: 1_000,
        cpu_cores: 0.0,
        memory_bytes: 0,
        gpu_required: false,
        gpu_vram_min_bytes: 0,
        integrity: ComputeIntegrity::None,
    };
    let err = client
        .compute_dispatch(params)
        .await
        .expect_err("should fail with DaemonNotRunning");

    assert!(
        matches!(err, RpcError::DaemonNotRunning(_)),
        "expected DaemonNotRunning, got {err:?}"
    );
}
