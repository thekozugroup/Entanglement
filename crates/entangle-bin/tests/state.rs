//! Integration tests for `DaemonState` construction and mesh RPC methods.

use entangle_bin::{methods, state::DaemonState};
use entangle_peers::{PeerStore, TrustedPeer};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::peer_id::PeerId;
use std::sync::Arc;

// ── helpers ───────────────────────────────────────────────────────────────────

fn build_state_with_store(peer_store: PeerStore) -> Arc<DaemonState> {
    let keyring = Keyring::new();
    let kernel_cfg = KernelConfig {
        multi_node: false,
        bus_capacity: 64,
        ..KernelConfig::default()
    };
    let kernel = Arc::new(Kernel::new(kernel_cfg, keyring).expect("kernel init"));
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
        peer_store,
        identity,
        "test-node".to_owned(),
    ))
}

fn default_state() -> Arc<DaemonState> {
    build_state_with_store(PeerStore::new())
}

fn make_trusted_peer(seed: u8, name: &str) -> TrustedPeer {
    let key = [seed; 32];
    let peer_id = PeerId::from_public_key_bytes(&key);
    TrustedPeer::new(peer_id, hex::encode(key), name.to_owned())
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Smoke test: DaemonState can be constructed and all fields are present.
#[test]
fn daemon_state_smoke() {
    let state = default_state();

    // local_peer_id is a non-zero hash of the generated key.
    assert_ne!(state.local_peer_id.to_hex(), "0".repeat(32));
    assert_eq!(state.local_display_name, "test-node");
    // peer store starts empty
    assert!(state.peer_store.is_empty());
}

/// DaemonState::local_peer_id is deterministically derived from the identity key.
#[test]
fn daemon_state_local_peer_id_matches_identity() {
    let identity = IdentityKeyPair::generate();
    let expected_id = PeerId::from_public_key_bytes(identity.public().as_bytes());

    let keyring = Keyring::new();
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring).expect("kernel"));
    let worker_pool = WorkerPool::new();
    let dispatcher = Arc::new(Dispatcher::new(
        worker_pool.clone(),
        kernel.clone(),
        expected_id,
    ));
    let state = DaemonState::new(
        kernel,
        dispatcher,
        worker_pool,
        PeerStore::new(),
        identity,
        "host".to_owned(),
    );
    assert_eq!(state.local_peer_id, expected_id);
}

/// `mesh/peers` returns an entry per trusted peer, each with `trusted=true`.
#[tokio::test]
async fn mesh_peers_returns_trusted_from_store() {
    let store = PeerStore::new();
    store.add(make_trusted_peer(1, "alice")).unwrap();
    store.add(make_trusted_peer(2, "bob")).unwrap();

    let state = build_state_with_store(store);

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"mesh/peers","params":{}}"#;
    let resp = methods::dispatch(req, &state).await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("valid JSON");
    let peers = v["result"]["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 2, "expected 2 peers, got {}", peers.len());
    for peer in peers {
        assert_eq!(
            peer["trusted"].as_bool(),
            Some(true),
            "all PeerStore entries should be trusted=true"
        );
    }
}

/// `mesh/status` exposes the real identity-derived `local_peer_id`.
#[tokio::test]
async fn mesh_status_includes_real_local_peer_id() {
    let state = default_state();
    let expected_hex = state.local_peer_id.to_hex();
    assert_eq!(expected_hex.len(), 32, "hex should be 32 chars (16 bytes)");

    let req = r#"{"jsonrpc":"2.0","id":2,"method":"mesh/status","params":{}}"#;
    let resp = methods::dispatch(req, &state).await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("valid JSON");
    let got_id = v["result"]["local_peer_id"]
        .as_str()
        .expect("local_peer_id string");
    assert_eq!(got_id, expected_hex);
    // Should no longer be the all-zero placeholder.
    assert_ne!(got_id, "0".repeat(32));
}

/// `mesh/peers` merges sighted (mDNS) and trusted (PeerStore) peers correctly.
///
/// Two trusted peers in the store + discovery not wired (None) → both appear
/// with `trusted=true` and empty addresses (the trusted-but-not-sighted path).
///
/// The full sighted-and-trusted merge path requires a live Discovery with a
/// mutable internal peer map that is not publicly accessible, so the half that
/// exercises the sighted view is marked `#[ignore]`.
#[tokio::test]
async fn mesh_peers_merges_trusted_only_when_no_discovery() {
    let store = PeerStore::new();
    store.add(make_trusted_peer(3, "carol")).unwrap();
    store.add(make_trusted_peer(4, "dave")).unwrap();

    // state.discovery is None (default) — only trusted peers should appear.
    let state = build_state_with_store(store);
    assert!(state.discovery.is_none());

    let req = r#"{"jsonrpc":"2.0","id":10,"method":"mesh/peers","params":{}}"#;
    let resp = methods::dispatch(req, &state).await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("valid JSON");
    let peers = v["result"]["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 2, "expected carol and dave");
    for peer in peers {
        assert_eq!(
            peer["trusted"].as_bool(),
            Some(true),
            "all PeerStore entries must be trusted=true"
        );
        // No live sighting → addresses should be empty.
        assert_eq!(
            peer["addresses"].as_array().map(|a| a.len()),
            Some(0),
            "trusted-but-not-sighted peers have no addresses"
        );
    }
}

/// Full merge: sighted AND trusted peers both appear, with correct flags.
///
/// Ignored because `Discovery`'s internal peer map is not publicly mutable.
/// Run manually with: `cargo test -p entangle-bin -- --ignored mesh_peers_merges_sighted_and_trusted`
#[tokio::test]
#[ignore]
async fn mesh_peers_merges_sighted_and_trusted() {
    // This test requires a controllable Discovery mock; deferred to Phase 2
    // when the internal peer map will have a test-injection API.
}

/// `mesh/status` trusted_peer_count reflects the live store.
#[tokio::test]
async fn mesh_status_trusted_peer_count() {
    let store = PeerStore::new();
    store.add(make_trusted_peer(10, "x")).unwrap();
    store.add(make_trusted_peer(11, "y")).unwrap();

    let state = build_state_with_store(store);
    let req = r#"{"jsonrpc":"2.0","id":3,"method":"mesh/status","params":{}}"#;
    let resp = methods::dispatch(req, &state).await;

    let v: serde_json::Value = serde_json::from_str(&resp).expect("valid JSON");
    let count = v["result"]["trusted_peer_count"]
        .as_u64()
        .expect("trusted_peer_count");
    assert_eq!(count, 2);
}
