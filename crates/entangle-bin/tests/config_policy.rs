//! WP5 integration tests: config-driven tier ceiling, multi-node startup
//! policy (ENTANGLE-E0050), and CLI ↔ daemon config schema compatibility.
//!
//! These tests wire the daemon's parsed `Config` through the exact same types
//! `main.rs` uses (`KernelConfig`, `BrokerPolicy`) so the enforcement path is
//! the one the real daemon takes.

use entangle_bin::config::Config;
use entangle_broker::BrokerPolicy;
use entangle_peers::{PeerStore, TrustedPeer};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::peer_id::PeerId;
use entangle_types::tier::Tier;

/// Build a `KernelConfig` from a parsed daemon config exactly as `main.rs`
/// does.
fn kernel_config_from(cfg: &Config) -> KernelConfig {
    KernelConfig {
        max_tier_allowed: cfg.security.max_tier_allowed,
        multi_node: cfg.mesh.multi_node,
        bus_capacity: cfg.runtime.bus_capacity,
    }
}

// ---------------------------------------------------------------------------
// Tier ceiling: max_tier_allowed = 2 must reject a tier-5 load.
// ---------------------------------------------------------------------------

#[test]
fn config_tier_ceiling_rejects_tier5_load() {
    let cfg: Config = toml::from_str("[security]\nmax_tier_allowed = 2\n").unwrap();
    assert_eq!(cfg.security.max_tier_allowed, Tier::Sandboxed);

    // The ceiling reaches the kernel's broker policy (it is no longer the
    // silent Tier::Native default) ...
    let kernel = Kernel::new(kernel_config_from(&cfg), Keyring::new()).expect("kernel");
    assert_eq!(kernel.broker().policy().max_tier_allowed, Tier::Sandboxed);

    // ... and that policy refuses a tier-5 (native) plugin load with E0043.
    let err = kernel
        .broker()
        .policy()
        .check_plugin_load(Tier::Native)
        .expect_err("tier-5 load must be rejected under a tier-2 ceiling");
    assert!(
        err.to_string().contains("ENTANGLE-E0043"),
        "expected ENTANGLE-E0043, got: {err}"
    );

    // Loads at or below the ceiling stay permitted.
    kernel
        .broker()
        .policy()
        .check_plugin_load(Tier::Sandboxed)
        .expect("tier-2 load must be permitted at a tier-2 ceiling");
}

// ---------------------------------------------------------------------------
// Multi-node + empty allowlist: startup must fail with ENTANGLE-E0050.
// ---------------------------------------------------------------------------

#[test]
fn multi_node_with_empty_peer_store_errors_with_e0050() {
    let cfg: Config = toml::from_str("[mesh]\nmulti_node = true\n").unwrap();
    let store = PeerStore::new(); // empty allowlist

    let policy = BrokerPolicy::new(cfg.security.max_tier_allowed, cfg.mesh.multi_node, &store);
    let err = policy
        .check_startup()
        .expect_err("multi-node with an empty allowlist must refuse to start");
    assert!(
        err.to_string().contains("ENTANGLE-E0050"),
        "expected ENTANGLE-E0050, got: {err}"
    );
}

#[test]
fn multi_node_with_populated_peer_store_starts() {
    let cfg: Config = toml::from_str("[mesh]\nmulti_node = true\n").unwrap();

    let identity = IdentityKeyPair::generate();
    let peer_id = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let store = PeerStore::new();
    store
        .add(TrustedPeer::new(
            peer_id,
            hex::encode(identity.public().as_bytes()),
            "peer-a".into(),
        ))
        .unwrap();

    let policy = BrokerPolicy::new(cfg.security.max_tier_allowed, cfg.mesh.multi_node, &store);
    policy
        .check_startup()
        .expect("multi-node with a populated allowlist must start");
}

#[test]
fn single_node_with_empty_peer_store_starts() {
    let cfg: Config = toml::from_str("").unwrap();
    let store = PeerStore::new();

    let policy = BrokerPolicy::new(cfg.security.max_tier_allowed, cfg.mesh.multi_node, &store);
    policy
        .check_startup()
        .expect("single-node mode never requires peers");
}

// ---------------------------------------------------------------------------
// CLI-written config round-trips through the daemon with fields preserved.
// ---------------------------------------------------------------------------

/// Byte-for-byte what `entangle-cli`'s `config::save` emits
/// (`toml::to_string_pretty` of its `Config` struct). If this stops parsing,
/// the CLI and daemon schemas have drifted.
const CLI_WRITTEN_CONFIG: &str = r#"[mesh]
transports = ["local"]
multi_node = true

[security]
max_tier_allowed = 3
"#;

#[test]
fn cli_written_config_parses_in_daemon_with_all_fields_preserved() {
    let cfg: Config = toml::from_str(CLI_WRITTEN_CONFIG).expect("CLI-written config must parse");
    assert_eq!(cfg.mesh.transports, vec!["local".to_owned()]);
    assert!(cfg.mesh.multi_node);
    assert_eq!(cfg.security.max_tier_allowed, Tier::Networked);

    // Round trip: daemon serialize → daemon reparse preserves every field.
    let out = toml::to_string_pretty(&cfg).expect("serialize");
    let reparsed: Config = toml::from_str(&out).expect("reparse");
    assert_eq!(reparsed.mesh.transports, cfg.mesh.transports);
    assert_eq!(reparsed.mesh.multi_node, cfg.mesh.multi_node);
    assert_eq!(
        reparsed.security.max_tier_allowed,
        cfg.security.max_tier_allowed
    );
    assert_eq!(reparsed.runtime.bus_capacity, cfg.runtime.bus_capacity);

    // And the values that reach the kernel are the operator's, not defaults.
    let kc = kernel_config_from(&cfg);
    assert_eq!(kc.max_tier_allowed, Tier::Networked);
    assert!(kc.multi_node);
}
