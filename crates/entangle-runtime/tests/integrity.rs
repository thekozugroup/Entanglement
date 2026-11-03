//! Kernel-level integrity-policy enforcement (spec §7.5).
//!
//! These cover what a bare kernel invocation enforces. The §16 ATC-INT
//! acceptance criteria for the submitter-side pipeline (verifier locality,
//! keyring check, policy immutability, output-size short-circuit) live in
//! `crates/entangle-scheduler/tests/integrity_atc.rs`.
//!
//! Tests that need a real WASM plugin with a `run` export use the committed
//! `hello-pong.wasm` fixture (`crates/entangle-host/tests/fixtures/`). The
//! fixture is checked into the repository, so these tests run by default —
//! nothing here is gated behind `#[ignore]`.
//!
//! Tests exercising pure policy logic (TrustedExecutor, NotImplemented) do NOT
//! require any plugin.

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
    let bundle = sign_artifact(wasm_bytes, manifest.as_bytes(), keypair);
    let sig_toml = toml::to_string(&bundle).unwrap();
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).unwrap();

    plugin_id_str
}

/// Generate a `PeerId` from a fixed 32-byte key (deterministic for tests).
fn peer_from_seed(seed: u8) -> PeerId {
    PeerId::from_public_key_bytes(&[seed; 32])
}

// ── Deterministic, N = 2 ─────────────────────────────────────────────────────

/// `Deterministic { replicas: 2 }` with a real plugin: both replicas must
/// agree; the canonical output is returned.
///
/// Uses the committed hello-pong.wasm fixture.
#[tokio::test(flavor = "multi_thread")]
async fn deterministic_n2_hash_match_succeeds() {
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
        "plugin output must be b\"Hello, world!\""
    );
    let _ = plugin_id_str; // keep id in scope for diagnostics
}

// ── Deterministic, N = 0 / 1 ─────────────────────────────────────────────────

/// `Deterministic { replicas: 0 }` and `{ replicas: 1 }` are no-ops; they fall
/// through to a single invocation without replica logic.
///
/// This test validates the no-op path using a real plugin (the committed
/// hello-pong.wasm fixture).
#[tokio::test(flavor = "multi_thread")]
async fn deterministic_zero_and_one_replicas_are_single_invocations() {
    // N=0 and N=1 are no-ops; single invoke, ok.
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
        .expect("replicas=0 should be a no-op (single invoke, ok)");

    // N=1 is a no-op → succeeds.
    let mut task1 = OneShotTask::with_defaults(plugin_id.clone(), b"x".to_vec());
    task1.integrity = IntegrityPolicy::Deterministic { replicas: 1 };
    kernel
        .invoke_with_integrity(&task1, local_peer)
        .await
        .expect("replicas=1 should be a no-op (single invoke, ok)");

    let _ = plugin_id_str;
}

// ── TrustedExecutor ──────────────────────────────────────────────────────────

/// `TrustedExecutor` allowlist passes when `local_peer` is listed.
///
/// Does NOT require a real plugin: `TrustedExecutor` checks are enforced before
/// the plugin invocation and the test operates against a no-op kernel that
/// already has no loaded plugins — we only verify the allowlist gate.
///
/// Because `invoke` would fail with `NotLoaded` after the allowlist check, we
/// exercise `check_trusted_executor` directly (the public re-export) to keep
/// the test self-contained and CI-safe.
#[test]
fn trusted_executor_allowlist_passes_when_local_peer_in_list() {
    let local_peer = peer_from_seed(0x03);
    let policy = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![local_peer],
    };
    entangle_runtime::check_trusted_executor(&policy, &local_peer)
        .expect("local peer in allowlist should pass");
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

// ── SemanticEquivalent through a bare kernel ─────────────────────────────────

/// A bare kernel cannot verify `SemanticEquivalent`: replicas belong on
/// several peers and the metric runs in the submitter's scheduler pipeline
/// (§7.5 verifier-locality). The kernel refuses with the stable
/// `ENTANGLE-E0306` instead of running anything.
#[tokio::test(flavor = "multi_thread")]
async fn semantic_equivalent_through_a_bare_kernel_requires_the_scheduler_verifier() {
    let keyring = Keyring::new();
    let kernel = Kernel::new(KernelConfig::default(), keyring).unwrap();
    let local_peer = peer_from_seed(0x05);

    // A syntactically valid but unloaded plugin id — the integrity gate fires
    // before the plugin lookup.
    let fake_id = entangle_types::plugin_id::PluginId::new(
        "a".repeat(32),
        "semantic-test",
        "0.1.0".parse().unwrap(),
    )
    .unwrap();

    let mut task = OneShotTask::with_defaults(fake_id.clone(), b"".to_vec());
    task.integrity = IntegrityPolicy::SemanticEquivalent {
        replicas: 3,
        quorum: 2,
        metric: entangle_types::task::MetricRef {
            plugin: fake_id,
            publisher_key: [1u8; 32],
            artifact_blake3: [2u8; 32],
        },
        threshold: 0.2,
    };

    let err = kernel
        .invoke_with_integrity(&task, local_peer)
        .await
        .expect_err("a bare kernel must refuse SemanticEquivalent");

    assert!(
        matches!(
            err,
            RuntimeError::Integrity(IntegrityError::VerifierRequired("SemanticEquivalent"))
        ),
        "expected Integrity(VerifierRequired(\"SemanticEquivalent\")), got: {err}"
    );
    assert!(
        err.to_string().contains("ENTANGLE-E0306"),
        "error message must include the stable ENTANGLE-E0306 code; got: {err}"
    );
}

/// `Attested` stays refused, with a message that says *why*: it needs TEE
/// attestation, not that the code is merely missing.
#[tokio::test(flavor = "multi_thread")]
async fn attested_message_names_tee_attestation() {
    let kernel = Kernel::new(KernelConfig::default(), Keyring::new()).unwrap();
    let fake_id = entangle_types::plugin_id::PluginId::new(
        "c".repeat(32),
        "attested-msg",
        "0.1.0".parse().unwrap(),
    )
    .unwrap();
    let mut task = OneShotTask::with_defaults(fake_id, b"".to_vec());
    task.integrity = IntegrityPolicy::Attested { tee: "sev".into() };
    let msg = kernel
        .invoke_with_integrity(&task, peer_from_seed(0x07))
        .await
        .expect_err("Attested must be refused")
        .to_string();
    assert!(msg.contains("ENTANGLE-E0304"), "{msg}");
    assert!(msg.contains("unsupported"), "{msg}");
    assert!(msg.contains("TEE attestation"), "{msg}");
    assert!(!msg.contains("Phase 1"), "stale scaffold wording: {msg}");
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

    assert!(
        err.to_string().contains("ENTANGLE-E0304"),
        "ATC-INT-6: error message must include stable ENTANGLE-E0304 code; got: {err}"
    );
}
