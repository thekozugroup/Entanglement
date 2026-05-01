//! Acceptance tests for integrity-policy enforcement (spec §7.5).
//!
//! ATC-INT-1 through ATC-INT-6, per §16 of the Entanglement Architecture spec.
//!
//! Tests that require the hello-pong fixture (a real WASM plugin with a `run`
//! export) are gated behind `#[ignore]` if the fixture may be absent in CI.
//! Run them with:
//!
//!   cargo test -p entangle-runtime --test integrity -- --ignored
//!
//! Tests exercising pure policy logic (TrustedExecutor, NotImplemented) do NOT
//! require any plugin and always run.

use entangle_runtime::{IntegrityError, Kernel, KernelConfig, RuntimeError};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::{
    peer_id::PeerId,
    task::{IntegrityPolicy, OneShotTask},
};

// ── Fixture paths ─────────────────────────────────────────────────────────────

const HELLO_PONG_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../entangle-host/tests/fixtures/hello-pong.wasm"
);

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a trusted `Keyring` for `keypair`.
fn keyring_for(keypair: &IdentityKeyPair) -> Keyring {
    let pub_key = keypair.public();
    let entry = TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "integrity-test-publisher".to_owned(),
        added_at: 0,
        note: String::new(),
    };
    let mut kr = Keyring::new();
    kr.add(entry);
    kr
}

/// Write a complete plugin package to `dir`, return the plugin-id string.
fn write_package(dir: &std::path::Path, keypair: &IdentityKeyPair, wasm_bytes: &[u8]) -> String {
    let publisher = keypair.fingerprint_hex();
    let plugin_id_str = format!("{publisher}/integrity-test@0.1.0");

    let manifest = format!(
        r#"[plugin]
id = "{plugin_id_str}"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "integrity acceptance-test plugin"
"#
    );
    std::fs::write(dir.join("entangle.toml"), manifest.as_bytes()).unwrap();
    std::fs::write(dir.join("plugin.wasm"), wasm_bytes).unwrap();
    let bundle = sign_artifact(wasm_bytes, keypair);
    let sig_toml = toml::to_string(&bundle).unwrap();
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).unwrap();

    plugin_id_str
}

/// Generate a `PeerId` from a fixed 32-byte key (deterministic for tests).
fn peer_from_seed(seed: u8) -> PeerId {
    PeerId::from_public_key_bytes(&[seed; 32])
}

// ── §16 ATC-INT-1 ─────────────────────────────────────────────────────────────

/// §16 ATC-INT-1 — `Deterministic { replicas: 2 }` with a real plugin: both
/// replicas must agree; the canonical output is returned.
///
/// Requires hello-pong.wasm fixture. Marked `#[ignore]` so CI doesn't fail
/// when the fixture hasn't been built; run manually with `--ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires hello-pong.wasm — run: cargo test -p entangle-runtime --test integrity -- --ignored"]
async fn atc_int_1_deterministic_n2_hash_match_succeeds() {
    let wasm = std::fs::read(HELLO_PONG_WASM)
        .expect("hello-pong.wasm fixture not found — run fixtures-src/hello-pong/build.sh");

    let keypair = IdentityKeyPair::generate();
    let keyring = keyring_for(&keypair);
    let dir = tempfile::tempdir().unwrap();
    let plugin_id_str = write_package(dir.path(), &keypair, &wasm);

    let kernel = Kernel::new(KernelConfig::default(), keyring).unwrap();
    let plugin_id = kernel.load_plugin_from_dir(dir.path()).await.unwrap();

    let mut task = OneShotTask::with_defaults(plugin_id, b"world".to_vec());
    task.integrity = IntegrityPolicy::Deterministic { replicas: 2 };

    let local_peer = peer_from_seed(0x01);
    let output = kernel
        .invoke_with_integrity(&task, local_peer)
        .await
        .expect("deterministic N=2 should succeed when plugin is deterministic");

    assert_eq!(
        output, b"Hello, world!",
        "ATC-INT-1: plugin output must be b\"Hello, world!\""
    );
    let _ = plugin_id_str; // keep id in scope for diagnostics
}

// ── §16 ATC-INT-2 ─────────────────────────────────────────────────────────────

/// §16 ATC-INT-2 — `Deterministic { replicas: 0 }` and `{ replicas: 1 }` are
/// no-ops; they fall through to a single invocation without replica logic.
///
/// This test validates the no-op path using a real plugin.
/// Marked `#[ignore]` because it needs the fixture.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires hello-pong.wasm — run: cargo test -p entangle-runtime --test integrity -- --ignored"]
async fn atc_int_2_deterministic_insufficient_replicas_errors() {
    // ATC-INT-2 proposition: N=0 and N=1 are no-ops; single invoke, ok.
    let wasm = std::fs::read(HELLO_PONG_WASM)
        .expect("hello-pong.wasm fixture not found — run fixtures-src/hello-pong/build.sh");

    let keypair = IdentityKeyPair::generate();
    let keyring = keyring_for(&keypair);
    let dir = tempfile::tempdir().unwrap();
    let plugin_id_str = write_package(dir.path(), &keypair, &wasm);

    let kernel = Kernel::new(KernelConfig::default(), keyring).unwrap();
    let plugin_id = kernel.load_plugin_from_dir(dir.path()).await.unwrap();
    let local_peer = peer_from_seed(0x02);

    // N=0 is a no-op → succeeds.
    let mut task0 = OneShotTask::with_defaults(plugin_id.clone(), b"x".to_vec());
    task0.integrity = IntegrityPolicy::Deterministic { replicas: 0 };
    kernel
        .invoke_with_integrity(&task0, local_peer)
        .await
        .expect("ATC-INT-2: replicas=0 should be a no-op (single invoke, ok)");

    // N=1 is a no-op → succeeds.
    let mut task1 = OneShotTask::with_defaults(plugin_id.clone(), b"x".to_vec());
    task1.integrity = IntegrityPolicy::Deterministic { replicas: 1 };
    kernel
        .invoke_with_integrity(&task1, local_peer)
        .await
        .expect("ATC-INT-2: replicas=1 should be a no-op (single invoke, ok)");

    let _ = plugin_id_str;
}

// ── §16 ATC-INT-3 ─────────────────────────────────────────────────────────────

/// §16 ATC-INT-3 — `TrustedExecutor` allowlist passes when `local_peer` is listed.
///
/// Does NOT require a real plugin: `TrustedExecutor` checks are enforced before
/// the plugin invocation and the test operates against a no-op kernel that
/// already has no loaded plugins — we only verify the allowlist gate.
///
/// Because `invoke` would fail with `NotLoaded` after the allowlist check, we
/// exercise `check_trusted_executor` directly (the public re-export) to keep
/// the test self-contained and CI-safe.
#[test]
fn atc_int_3_trusted_executor_allowlist_passes_when_local_peer_in_list() {
    let local_peer = peer_from_seed(0x03);
    let policy = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![local_peer],
    };
    entangle_runtime::check_trusted_executor(&policy, &local_peer)
        .expect("ATC-INT-3: local peer in allowlist should pass");
}

// ── §16 ATC-INT-4 ─────────────────────────────────────────────────────────────

/// §16 ATC-INT-4 — `TrustedExecutor` rejects when `local_peer` is not in the allowlist.
#[test]
fn atc_int_4_trusted_executor_rejects_when_local_peer_not_in_list() {
    let local_peer = peer_from_seed(0x04);
    let other_peer = peer_from_seed(0xff);
    let policy = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![other_peer],
    };
    let err = entangle_runtime::check_trusted_executor(&policy, &local_peer)
        .expect_err("ATC-INT-4: local peer absent from allowlist should be refused");

    assert!(
        matches!(err, IntegrityError::TrustedExecutorRefused(_)),
        "ATC-INT-4: expected TrustedExecutorRefused, got: {err}"
    );
}

// ── §16 ATC-INT-5 ─────────────────────────────────────────────────────────────

/// §16 ATC-INT-5 — `SemanticEquivalent` returns `NotImplemented` in Phase 1.
///
/// Uses a no-op task against an empty kernel (invoke would fail with NotLoaded
/// anyway, but the integrity gate fires first and returns NotImplemented).
#[tokio::test(flavor = "multi_thread")]
async fn atc_int_5_semantic_equivalent_returns_not_implemented() {
    let keyring = Keyring::new();
    let kernel = Kernel::new(KernelConfig::default(), keyring).unwrap();
    let local_peer = peer_from_seed(0x05);

    // Use a syntactically valid but unloaded plugin id — the integrity gate
    // fires before the plugin lookup.
    let fake_id = entangle_types::plugin_id::PluginId::new(
        "a".repeat(32),
        "semantic-test",
        "0.1.0".parse().unwrap(),
    )
    .unwrap();

    let mut task = OneShotTask::with_defaults(fake_id, b"".to_vec());
    task.integrity = IntegrityPolicy::SemanticEquivalent {
        metric: "cosine".to_string(),
        threshold: 0.9,
    };

    let err = kernel
        .invoke_with_integrity(&task, local_peer)
        .await
        .expect_err("ATC-INT-5: SemanticEquivalent must return NotImplemented");

    assert!(
        matches!(
            err,
            RuntimeError::Integrity(IntegrityError::NotImplemented("SemanticEquivalent"))
        ),
        "ATC-INT-5: expected Integrity(NotImplemented(\"SemanticEquivalent\")), got: {err}"
    );
}

// ── §16 ATC-INT-6 ─────────────────────────────────────────────────────────────

/// §16 ATC-INT-6 — `Attested` returns `NotImplemented` in Phase 1.
#[tokio::test(flavor = "multi_thread")]
async fn atc_int_6_attested_returns_not_implemented() {
    let keyring = Keyring::new();
    let kernel = Kernel::new(KernelConfig::default(), keyring).unwrap();
    let local_peer = peer_from_seed(0x06);

    let fake_id = entangle_types::plugin_id::PluginId::new(
        "b".repeat(32),
        "attested-test",
        "0.1.0".parse().unwrap(),
    )
    .unwrap();

    let mut task = OneShotTask::with_defaults(fake_id, b"".to_vec());
    task.integrity = IntegrityPolicy::Attested {
        tee: "sgx".to_string(),
    };

    let err = kernel
        .invoke_with_integrity(&task, local_peer)
        .await
        .expect_err("ATC-INT-6: Attested must return NotImplemented");

    assert!(
        matches!(
            err,
            RuntimeError::Integrity(IntegrityError::NotImplemented("Attested"))
        ),
        "ATC-INT-6: expected Integrity(NotImplemented(\"Attested\")), got: {err}"
    );
}
