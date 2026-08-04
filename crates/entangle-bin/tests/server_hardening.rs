//! Integration tests for the hardened UDS server transport:
//! request-size cap, socket permissions, stale-socket handling, and
//! accept-loop permit recycling.
//!
//! Hermetic: every test binds its own socket under a fresh temp dir; no
//! running daemon is required.

use entangle_bin::{server, state::DaemonState};
use entangle_peers::PeerStore;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::peer_id::PeerId;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_state() -> Arc<DaemonState> {
    let kernel = Arc::new(
        Kernel::new(KernelConfig::default(), Keyring::new())
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

fn tmp_sock(label: &str) -> PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{label}.sock"));
    // Leak TempDir so the directory survives for the duration of the test.
    std::mem::forget(dir);
    path
}

/// Spawn the RPC server task and connect to it, retrying until the socket
/// is bound.
async fn start_and_connect(socket_path: &PathBuf, state: Arc<DaemonState>) -> UnixStream {
    let sp = socket_path.clone();
    tokio::spawn(async move {
        let _ = server::serve(sp, state).await;
    });
    connect_with_retry(socket_path).await
}

async fn connect_with_retry(socket_path: &PathBuf) -> UnixStream {
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        if let Ok(s) = UnixStream::connect(socket_path).await {
            return s;
        }
    }
    panic!("failed to connect to test RPC server within 500 ms");
}

/// A `version` request padded (via an ignored string param) to exactly
/// `total_len` bytes, excluding the trailing `\n`.
fn padded_version_request(id: u64, total_len: usize) -> String {
    let prefix = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"version","params":{{"pad":""#);
    let suffix = r#""}}"#;
    let pad_len = total_len
        .checked_sub(prefix.len() + suffix.len())
        .expect("total_len too small for envelope");
    let mut req = String::with_capacity(total_len);
    req.push_str(&prefix);
    req.extend(std::iter::repeat_n('x', pad_len));
    req.push_str(suffix);
    assert_eq!(req.len(), total_len);
    req
}

// ── request-size cap ──────────────────────────────────────────────────────────

/// A request line of exactly `MAX_REQUEST_BYTES` (plus its `\n` delimiter)
/// must be served normally — no off-by-one at the cap.
#[tokio::test(flavor = "multi_thread")]
async fn request_at_exactly_the_cap_succeeds() {
    let sock = tmp_sock("cap_exact");
    let mut stream = start_and_connect(&sock, make_state()).await;

    let req = padded_version_request(42, server::MAX_REQUEST_BYTES);
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
    stream.flush().await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let v: serde_json::Value = serde_json::from_str(&line).expect("response must be valid JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 42);
    assert!(
        v["result"]["entangled"].is_string(),
        "at-cap request must be dispatched normally: {v}"
    );
    assert!(v.get("error").is_none(), "unexpected error field: {v}");
}

/// One byte over the cap gets a JSON-RPC `-32600` error and the connection
/// is closed — the server never buffers past the cap.
#[tokio::test(flavor = "multi_thread")]
async fn over_cap_request_returns_minus_32600_and_closes() {
    let sock = tmp_sock("cap_over");
    let mut stream = start_and_connect(&sock, make_state()).await;

    // No delimiter needed: the server detects the overrun as soon as the
    // cap is exhausted without a `\n` having arrived.
    let payload = vec![b'x'; server::MAX_REQUEST_BYTES + 1];
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let v: serde_json::Value = serde_json::from_str(&line).expect("response must be valid JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], serde_json::Value::Null);
    assert_eq!(
        v["error"]["code"], -32600,
        "expected -32600 invalid request"
    );

    // The server must close the connection after rejecting.
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "connection must be closed after -32600");
}

// ── socket permissions and stale-socket handling ──────────────────────────────

/// The bound socket must be mode 0600 and a freshly created parent
/// directory must be mode 0700.
#[tokio::test(flavor = "multi_thread")]
async fn socket_is_0600_and_created_parent_dir_is_0700() {
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().join("sub");
    let sock = parent.join("perm.sock");
    std::mem::forget(dir);

    // Connecting proves the server is up; only then inspect modes.
    let _stream = start_and_connect(&sock, make_state()).await;

    let sock_mode = std::fs::metadata(&sock).unwrap().permissions().mode();
    assert_eq!(sock_mode & 0o7777, 0o600, "socket must be owner-only");

    let dir_mode = std::fs::metadata(&parent).unwrap().permissions().mode();
    assert_eq!(dir_mode & 0o7777, 0o700, "socket dir must be owner-only");
}

/// A non-socket file squatting on the socket path must not be unlinked;
/// the server refuses to start instead.
#[tokio::test(flavor = "multi_thread")]
async fn refuses_to_replace_non_socket_file() {
    let sock = tmp_sock("squatter");
    std::fs::write(&sock, b"not a socket").unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        server::serve(sock.clone(), make_state()),
    )
    .await
    .expect("serve must return promptly when the path is not a socket");

    assert!(result.is_err(), "must refuse to replace a non-socket file");
    assert_eq!(
        std::fs::read(&sock).unwrap(),
        b"not a socket",
        "squatting file must be left untouched"
    );
}

/// A genuinely stale socket (left behind by a crashed daemon) is unlinked
/// and rebound.
#[tokio::test(flavor = "multi_thread")]
async fn stale_socket_is_replaced_and_served() {
    let sock = tmp_sock("stale");
    // Simulate a crash: bind, then drop the listener without unlinking.
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
    assert!(sock.exists(), "stale socket file must remain for the test");

    let mut stream = start_and_connect(&sock, make_state()).await;
    stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"version\",\"params\":{}}\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let v: serde_json::Value = serde_json::from_str(&line).expect("response must be valid JSON");
    assert_eq!(v["id"], 5);
    assert!(v["result"]["entangled"].is_string(), "bad response: {v}");
}

// ── accept-loop permit recycling ──────────────────────────────────────────────

/// Sequential short-lived connections must all be served: closing a
/// connection releases its concurrency permit back to the accept loop.
#[tokio::test(flavor = "multi_thread")]
async fn sequential_connections_recycle_permits() {
    let sock = tmp_sock("recycle");
    let state = make_state();
    let sp = sock.clone();
    let s = state.clone();
    tokio::spawn(async move {
        let _ = server::serve(sp, s).await;
    });

    for id in 0..10u64 {
        let mut stream = connect_with_retry(&sock).await;
        let req = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"version","params":{{}}}}"#);
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&line).expect("response must be valid JSON");
        assert_eq!(v["id"], id, "connection {id} was not served");
        // Dropping the stream closes the connection and frees the permit.
    }
}
