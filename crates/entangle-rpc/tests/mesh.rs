//! RPC client tests for `mesh/peers` and `mesh/status`.
//!
//! Uses a fake UDS server (same pattern as `tests/client.rs`) to verify the
//! client correctly serialises requests and deserialises structured responses.

use entangle_rpc::{Client, RpcError};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Spin up a one-shot fake UDS server that reads one request line and replies.
async fn fake_server(sock_path: PathBuf, reply_json: &'static str) {
    let listener = UnixListener::bind(&sock_path).expect("bind fake server");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (rd, mut wr) = stream.into_split();
        let mut lines = BufReader::new(rd).lines();
        let _ = lines.next_line().await; // consume request
        wr.write_all(reply_json.as_bytes()).await.expect("write");
        wr.write_all(b"\n").await.expect("write newline");
        wr.flush().await.expect("flush");
    });
}

#[tokio::test]
async fn mesh_peers_returns_empty_on_fresh_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"peers":[]}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let res = client.mesh_peers().await.expect("mesh_peers");
    assert_eq!(res.peers.len(), 0, "expected empty peers list");
}

#[tokio::test]
async fn mesh_peers_parses_peer_fields() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"peers":[{"peer_id":"abc123","display_name":"laptop","addresses":["192.168.1.42:7001"],"port":7001,"version":"0.1.0","last_seen_secs_ago":5,"trusted":true}]}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let res = client.mesh_peers().await.expect("mesh_peers");
    assert_eq!(res.peers.len(), 1);

    let peer = &res.peers[0];
    assert_eq!(peer.peer_id, "abc123");
    assert_eq!(peer.display_name, "laptop");
    assert_eq!(peer.addresses, vec!["192.168.1.42:7001"]);
    assert_eq!(peer.port, 7001);
    assert_eq!(peer.version, "0.1.0");
    assert_eq!(peer.last_seen_secs_ago, 5);
    assert!(peer.trusted);
}

#[tokio::test]
async fn mesh_status_includes_local_peer_id() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"local_peer_id":"deadbeef01234567","local_display_name":"my-node","transports_active":["mesh.local"],"seen_peer_count":3,"trusted_peer_count":1}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let res = client.mesh_status().await.expect("mesh_status");
    assert_eq!(res.local_peer_id, "deadbeef01234567");
    assert_eq!(res.local_display_name, "my-node");
    assert_eq!(res.transports_active, vec!["mesh.local"]);
    assert_eq!(res.seen_peer_count, 3);
    assert_eq!(res.trusted_peer_count, 1);
}

#[tokio::test]
async fn mesh_status_zero_counts_on_fresh_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"local_peer_id":"","local_display_name":"","transports_active":[],"seen_peer_count":0,"trusted_peer_count":0}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let res = client.mesh_status().await.expect("mesh_status");
    assert_eq!(res.seen_peer_count, 0);
    assert_eq!(res.trusted_peer_count, 0);
    assert!(res.transports_active.is_empty());
}

#[tokio::test]
async fn mesh_peers_propagates_rpc_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    fake_server(
        sock.clone(),
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#,
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let client = Client::new(&sock);
    let err = client.mesh_peers().await.expect_err("should fail");
    match err {
        RpcError::Rpc { code, message } => {
            assert_eq!(code, -32601);
            assert_eq!(message, "method not found");
        }
        other => panic!("expected RpcError::Rpc, got {other:?}"),
    }
}
