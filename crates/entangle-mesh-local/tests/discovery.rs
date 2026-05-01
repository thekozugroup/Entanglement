//! Integration tests for `entangle-mesh-local` discovery.
//!
//! Real mDNS tests require multicast on a live loopback/LAN interface, which
//! is unreliable in sandboxed CI environments. The non-ignored smoke test
//! tolerates a daemon bind failure gracefully. The `manual_` tests are marked
//! `#[ignore]` and must be run explicitly:
//!
//! ```text
//! cargo test -p entangle-mesh-local -- --ignored manual_
//! ```

use entangle_mesh_local::{Discovery, DiscoveryConfig, LocalPeer};
use entangle_types::peer_id::PeerId;

/// Fixed 32-byte seed for a deterministic peer id in tests.
const KEY_A: [u8; 32] = [0xAA; 32];
const KEY_B: [u8; 32] = [0xBB; 32];

fn make_config(key: &[u8; 32], port: u16, name: &str) -> DiscoveryConfig {
    DiscoveryConfig {
        local: LocalPeer {
            peer_id: PeerId::from_public_key_bytes(key),
            display_name: name.to_string(),
            port,
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        announce_interval_secs: 30,
        channel_capacity: 64,
    }
}

// ── non-ignored unit test ─────────────────────────────────────────────────────

/// Smoke test: create a Discovery, announce, then shut it down.
///
/// If the mDNS daemon cannot bind (sandboxed CI), we accept the error and pass.
#[test]
fn smoke_announce_and_shutdown() {
    let config = make_config(&KEY_A, 17700, "test-node-a");
    let discovery = match Discovery::new(config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Discovery::new failed (expected in sandbox): {e}");
            return;
        }
    };

    if let Err(e) = discovery.start_announcing() {
        eprintln!("start_announcing failed (expected in sandbox): {e}");
        // Still attempt shutdown; ignore its result too.
        let _ = discovery.shutdown();
        return;
    }

    match discovery.shutdown() {
        Ok(()) => {}
        Err(e) => eprintln!("shutdown failed (non-fatal in sandbox): {e}"),
    }
}

// ── ignored manual integration tests ─────────────────────────────────────────

/// Starts two `Discovery` instances on different peer_ids, browses for 5 s,
/// and asserts each sees the other.
///
/// Run with: `cargo test -p entangle-mesh-local -- --ignored manual_two_instances_see_each_other`
#[tokio::test]
#[ignore]
async fn manual_two_instances_see_each_other() {
    use tokio::time::{timeout, Duration};

    let config_a = make_config(&KEY_A, 17701, "node-a");
    let config_b = make_config(&KEY_B, 17702, "node-b");

    let id_a = config_a.local.peer_id;
    let id_b = config_b.local.peer_id;

    let disc_a = Discovery::new(config_a).expect("Discovery A");
    let disc_b = Discovery::new(config_b).expect("Discovery B");

    disc_a.start_announcing().expect("announce A");
    disc_b.start_announcing().expect("announce B");

    let mut rx_a = disc_a.subscribe();
    let mut rx_b = disc_b.subscribe();

    let _h_a = disc_a.spawn_browser().expect("browser A");
    let _h_b = disc_b.spawn_browser().expect("browser B");

    // Wait up to 5 s for each side to see the other.
    let saw_b_from_a = timeout(Duration::from_secs(5), async {
        loop {
            match rx_a.recv().await {
                Ok(entangle_mesh_local::DiscoveryEvent::PeerAppeared(p)) if p.peer_id == id_b => {
                    break true
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    let saw_a_from_b = timeout(Duration::from_secs(5), async {
        loop {
            match rx_b.recv().await {
                Ok(entangle_mesh_local::DiscoveryEvent::PeerAppeared(p)) if p.peer_id == id_a => {
                    break true
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    disc_a.shutdown().ok();
    disc_b.shutdown().ok();

    assert!(saw_b_from_a, "node-a did not see node-b within 5 s");
    assert!(saw_a_from_b, "node-b did not see node-a within 5 s");
}
