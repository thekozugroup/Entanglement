//! Integration tests for the entangle-runtime kernel.
//!
//! Each test constructs everything in-process, writes a fixture plugin package
//! to a tempdir, and exercises the kernel end-to-end.

use std::time::Duration;

use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::tier::Tier;

use crate::{Kernel, KernelConfig, LifecyclePhase};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Minimal valid WebAssembly component bytes.
///
/// Uses `(component)` — the smallest valid component-model binary.
/// Falls back to an empty vec if the `wat` crate does not support the
/// component text format (same approach as entangle-host tests).
fn minimal_wasm() -> Vec<u8> {
    match wat::parse_str("(component)") {
        Ok(b) => b,
        Err(_) => {
            // If wat doesn't support component text, use the raw binary encoding
            // of an empty component (magic + version + layer bytes).
            // Component magic: \0asm, version 0x0a000100 (component-model)
            vec![
                0x00, 0x61, 0x73, 0x6d, // \0asm
                0x0a, 0x00, 0x01, 0x00, // component-model version
            ]
        }
    }
}

/// Build a trusted [`Keyring`] containing `keypair`'s public key.
fn keyring_for(keypair: &IdentityKeyPair) -> Keyring {
    let pub_key = keypair.public();
    let entry = TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "test-publisher".to_owned(),
        added_at: 0,
        note: String::new(),
    };
    let mut kr = Keyring::new();
    kr.add(entry);
    kr
}

/// Write a complete plugin package to `dir` and return the plugin id string.
///
/// The `publisher` is 32 lowercase hex chars (fingerprint of `keypair`).
fn write_plugin_package(
    dir: &std::path::Path,
    keypair: &IdentityKeyPair,
    wasm_bytes: &[u8],
    tier: u8,
) -> String {
    let publisher = keypair.fingerprint_hex();
    let plugin_id_str = format!("{publisher}/test-plugin@0.1.0");

    // Per spec §4.4.1 case 3: tier 1-3 require runtime=wasm, tier 4-5 require runtime=native.
    let runtime = if tier <= 3 { "wasm" } else { "native" };
    let manifest_toml = format!(
        r#"[plugin]
id = "{plugin_id_str}"
version = "0.1.0"
tier = {tier}
runtime = "{runtime}"
description = "runtime integration test plugin"
"#
    );

    // Write manifest
    std::fs::write(dir.join("entangle.toml"), manifest_toml.as_bytes()).expect("write manifest");

    // Write wasm artifact
    std::fs::write(dir.join("plugin.wasm"), wasm_bytes).expect("write wasm");

    // Sign and write signature bundle
    let bundle = sign_artifact(wasm_bytes, keypair);
    let sig_toml = toml::to_string(&bundle).expect("serialize bundle");
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).expect("write sig");

    plugin_id_str
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// 1. Full happy-path load: manifest → signature → broker → host → bus events.
#[tokio::test(flavor = "multi_thread")]
async fn load_plugin_end_to_end() {
    let keypair = IdentityKeyPair::generate();
    let keyring = keyring_for(&keypair);
    let wasm = minimal_wasm();

    let dir = tempfile::tempdir().expect("tempdir");
    write_plugin_package(dir.path(), &keypair, &wasm, 1);

    let kernel = Kernel::new(KernelConfig::default(), keyring).expect("kernel");

    // Subscribe before loading so we catch all events.
    let mut sub = kernel.bus().subscribe();

    let plugin_id = kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect("load should succeed");

    assert!(
        kernel.list_plugins().contains(&plugin_id),
        "plugin should appear in list"
    );

    // Collect the 4 lifecycle events emitted during load.
    let expected = [
        LifecyclePhase::ManifestValidated,
        LifecyclePhase::SignatureVerified,
        LifecyclePhase::Registered,
        LifecyclePhase::Loaded,
    ];
    for phase in expected {
        let env = tokio::time::timeout(Duration::from_secs(1), sub.recv())
            .await
            .expect("event should arrive within 1s")
            .expect("recv ok");
        assert_eq!(env.payload.phase, phase, "unexpected phase order");
        assert_eq!(env.payload.plugin, plugin_id);
    }
}

/// 2. Empty keyring → VerificationError::UnknownPublisher.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_publisher_blocks_load() {
    let keypair = IdentityKeyPair::generate();
    let empty_keyring = Keyring::new(); // no trusted keys
    let wasm = minimal_wasm();

    let dir = tempfile::tempdir().expect("tempdir");
    write_plugin_package(dir.path(), &keypair, &wasm, 1);

    let kernel = Kernel::new(KernelConfig::default(), empty_keyring).expect("kernel");
    let err = kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect_err("should fail with unknown publisher");

    assert!(
        matches!(
            err,
            crate::RuntimeError::Signing(entangle_signing::VerificationError::UnknownPublisher)
        ),
        "expected UnknownPublisher, got: {err}"
    );
}

/// 3. Tampered artifact bytes → ArtifactHashMismatch.
#[tokio::test(flavor = "multi_thread")]
async fn tampered_artifact_blocks_load() {
    let keypair = IdentityKeyPair::generate();
    let keyring = keyring_for(&keypair);
    let wasm_a = minimal_wasm();

    let dir = tempfile::tempdir().expect("tempdir");
    // Write package with wasm_a bytes + sign wasm_a.
    write_plugin_package(dir.path(), &keypair, &wasm_a, 1);

    // Overwrite the wasm with tampered bytes (flip one byte).
    let mut wasm_b = wasm_a.clone();
    if let Some(b) = wasm_b.last_mut() {
        *b ^= 0xff;
    } else {
        wasm_b.push(0xde);
    }
    std::fs::write(dir.path().join("plugin.wasm"), &wasm_b).expect("overwrite wasm");

    let kernel = Kernel::new(KernelConfig::default(), keyring).expect("kernel");
    let err = kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect_err("should fail with hash mismatch");

    assert!(
        matches!(
            err,
            crate::RuntimeError::Signing(
                entangle_signing::VerificationError::ArtifactHashMismatch { .. }
            )
        ),
        "expected ArtifactHashMismatch, got: {err}"
    );
}

/// 4. Plugin tier above daemon ceiling → Broker(Policy(TierAboveCeiling)).
#[tokio::test(flavor = "multi_thread")]
async fn tier_above_ceiling_blocks_load() {
    let keypair = IdentityKeyPair::generate();
    let keyring = keyring_for(&keypair);
    let wasm = minimal_wasm();

    let dir = tempfile::tempdir().expect("tempdir");
    // Plugin declares tier 5 (Native).
    write_plugin_package(dir.path(), &keypair, &wasm, 5);

    let config = KernelConfig {
        max_tier_allowed: Tier::Sandboxed, // ceiling at tier 2
        ..KernelConfig::default()
    };
    let kernel = Kernel::new(config, keyring).expect("kernel");
    let err = kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect_err("should fail with tier ceiling");

    assert!(
        matches!(
            err,
            crate::RuntimeError::Broker(entangle_broker::BrokerError::Policy(
                entangle_broker::PolicyError::TierAboveCeiling { .. }
            ))
        ),
        "expected TierAboveCeiling, got: {err}"
    );
}

/// 6. invoke emits Activated then Idled around the plugin call.
#[tokio::test(flavor = "multi_thread")]
async fn invoke_plugin_emits_activated_and_idled() {
    let keypair = IdentityKeyPair::generate();
    let keyring = keyring_for(&keypair);
    // Use the hello-pong fixture which has a real `run` export.
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong.wasm fixture not found — run fixtures-src/hello-pong/build.sh");

    let dir = tempfile::tempdir().expect("tempdir");
    let plugin_id_str = write_plugin_package(dir.path(), &keypair, &wasm, 1);

    let kernel = Kernel::new(KernelConfig::default(), keyring).expect("kernel");

    // Subscribe before load so we capture all events.
    let mut sub = kernel.bus().subscribe();

    let plugin_id = kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect("load ok");

    // Drain the 4 load events (ManifestValidated, SignatureVerified, Registered, Loaded).
    for _ in 0..4 {
        tokio::time::timeout(Duration::from_secs(1), sub.recv())
            .await
            .expect("load event timeout")
            .expect("recv ok");
    }

    // Invoke the plugin.
    let _output = kernel
        .invoke(&plugin_id, b"hi", 30_000)
        .await
        .expect("invoke ok");

    // The next two events must be Activated then Idled, in order.
    let activated = tokio::time::timeout(Duration::from_secs(2), sub.recv())
        .await
        .expect("Activated event timeout")
        .expect("recv ok");
    assert_eq!(
        activated.payload.phase,
        LifecyclePhase::Activated,
        "expected Activated, got {:?}",
        activated.payload.phase
    );
    assert_eq!(activated.payload.plugin.to_string(), plugin_id_str);

    let idled = tokio::time::timeout(Duration::from_secs(2), sub.recv())
        .await
        .expect("Idled event timeout")
        .expect("recv ok");
    assert_eq!(
        idled.payload.phase,
        LifecyclePhase::Idled,
        "expected Idled, got {:?}",
        idled.payload.phase
    );
    assert_eq!(idled.payload.plugin.to_string(), plugin_id_str);
}

/// 5. Load then unload: list is empty, Unloaded event was emitted.
#[tokio::test(flavor = "multi_thread")]
async fn unload_plugin_emits_event_and_removes_from_list() {
    let keypair = IdentityKeyPair::generate();
    let keyring = keyring_for(&keypair);
    let wasm = minimal_wasm();

    let dir = tempfile::tempdir().expect("tempdir");
    write_plugin_package(dir.path(), &keypair, &wasm, 1);

    let kernel = Kernel::new(KernelConfig::default(), keyring).expect("kernel");

    // Subscribe before load so we get all events.
    let mut sub = kernel.bus().subscribe_topic("runtime.plugin.lifecycle");

    let plugin_id = kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect("load ok");

    // Drain the 4 load events.
    for _ in 0..4 {
        tokio::time::timeout(Duration::from_secs(1), sub.recv())
            .await
            .expect("load event timeout")
            .expect("recv ok");
    }

    // Unload.
    kernel.unload(&plugin_id).await.expect("unload ok");

    assert!(
        kernel.list_plugins().is_empty(),
        "plugin list should be empty after unload"
    );

    // The next event must be Unloaded.
    let env = tokio::time::timeout(Duration::from_secs(1), sub.recv())
        .await
        .expect("unload event timeout")
        .expect("recv ok");
    assert_eq!(env.payload.phase, LifecyclePhase::Unloaded);
    assert_eq!(env.payload.plugin, plugin_id);
}
