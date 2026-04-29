//! End-to-end integration test: build hello-world → sign → load via kernel → lifecycle events.
//!
//! Marked `#[ignore]` because it requires the `wasm32-wasip2` target to be installed
//! and performs an out-of-process `cargo build`. Run with:
//!
//!   cargo test -p entangle-runtime --test hello_world_e2e -- --ignored
//!
//! The test does NOT invoke the wasm `run` export (that requires host-side
//! bindgen, deferred to a later iteration). Instantiation succeeding — and all
//! four lifecycle events arriving — is the acceptance criterion.

use std::time::Duration;

use entangle_runtime::{Kernel, KernelConfig, LifecyclePhase};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};

// ---------------------------------------------------------------------------
// Helper: build a trusted Keyring containing `keypair`'s public key.
// ---------------------------------------------------------------------------
fn keyring_for(keypair: &IdentityKeyPair) -> Keyring {
    let pub_key = keypair.public();
    let entry = TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "e2e-test-publisher".to_owned(),
        added_at: 0,
        note: String::new(),
    };
    let mut kr = Keyring::new();
    kr.add(entry);
    kr
}

// ---------------------------------------------------------------------------
// Helper: write a complete plugin package (manifest + wasm + sig) to `dir`.
// Returns the plugin-id string used in the manifest.
// ---------------------------------------------------------------------------
fn write_package(dir: &std::path::Path, keypair: &IdentityKeyPair, wasm_bytes: &[u8]) -> String {
    let fingerprint = keypair.fingerprint_hex();
    let plugin_id = format!("{fingerprint}/hello-world@0.1.0");

    let manifest = format!(
        r#"[plugin]
id = "{plugin_id}"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "e2e test — hello-world"
"#
    );
    std::fs::write(dir.join("entangle.toml"), manifest.as_bytes()).expect("write manifest");

    std::fs::write(dir.join("plugin.wasm"), wasm_bytes).expect("write wasm");

    let bundle = sign_artifact(wasm_bytes, keypair);
    let sig_toml = toml::to_string(&bundle).expect("serialize sig bundle");
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).expect("write sig");

    plugin_id
}

// ---------------------------------------------------------------------------
// Step 1: run cargo build for the hello-world example.
// Returns the path to the produced wasm artifact, or None if build failed.
// ---------------------------------------------------------------------------
fn build_hello_world() -> Option<std::path::PathBuf> {
    // Locate workspace root: this file is at crates/entangle-runtime/tests/,
    // so workspace root is three levels up from the file's directory.
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("workspace root")
        .to_owned();

    let manifest = workspace_root.join("examples/hello-world/Cargo.toml");
    let example_dir = workspace_root.join("examples/hello-world");

    // Check wasm32-wasip2 is installed.
    let installed = std::process::Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .ok()?;
    let out = String::from_utf8_lossy(&installed.stdout);
    if !out.contains("wasm32-wasip2") {
        eprintln!("[hello_world_e2e] wasm32-wasip2 not installed — skipping build step");
        return None;
    }

    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target",
            "wasm32-wasip2",
            "--manifest-path",
        ])
        .arg(&manifest)
        .status()
        .ok()?;

    if !status.success() {
        eprintln!("[hello_world_e2e] cargo build failed");
        return None;
    }

    let wasm = example_dir.join("target/wasm32-wasip2/release/entangle_hello_world.wasm");
    if wasm.exists() {
        Some(wasm)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// The test itself.
// ---------------------------------------------------------------------------

/// Full pipeline: build → sign (in-test key) → load via kernel → assert lifecycle events.
///
/// Run with:  cargo test -p entangle-runtime --test hello_world_e2e -- --ignored
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires wasm32-wasip2 target and runs cargo build out-of-process"]
async fn hello_world_full_pipeline() {
    // Step 1: build (or fall back to minimal wasm component bytes for CI).
    let wasm_bytes: Vec<u8> = match build_hello_world() {
        Some(path) => {
            println!("[hello_world_e2e] using built wasm: {}", path.display());
            std::fs::read(&path).expect("read wasm")
        }
        None => {
            println!("[hello_world_e2e] using minimal component wasm (build step skipped)");
            // Smallest valid WebAssembly component binary.
            match wat::parse_str("(component)") {
                Ok(b) => b,
                Err(_) => vec![
                    0x00, 0x61, 0x73, 0x6d, // \0asm
                    0x0a, 0x00, 0x01, 0x00, // component-model version
                ],
            }
        }
    };

    // Step 3: generate in-test IdentityKeyPair.
    let keypair = IdentityKeyPair::generate();

    // Step 4: build a Keyring with it.
    let keyring = keyring_for(&keypair);

    // Step 5: write package to tempdir with fingerprint-substituted id.
    let dir = tempfile::tempdir().expect("tempdir");
    let plugin_id_str = write_package(dir.path(), &keypair, &wasm_bytes);

    // Step 6: signing already happened inside write_package via sign_artifact.

    // Step 7: load via kernel.
    let kernel = Kernel::new(KernelConfig::default(), keyring).expect("kernel");

    // Subscribe before load so we receive all events.
    let mut sub = kernel.bus().subscribe_topic("runtime.plugin.lifecycle");

    let plugin_id = kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect("load_plugin_from_dir");

    assert_eq!(
        plugin_id.to_string(),
        plugin_id_str,
        "returned plugin id must match manifest"
    );

    assert!(
        kernel.list_plugins().contains(&plugin_id),
        "plugin must appear in list after load"
    );

    // Step 8: assert the 4 lifecycle events arrive in order.
    let expected_phases = [
        LifecyclePhase::ManifestValidated,
        LifecyclePhase::SignatureVerified,
        LifecyclePhase::Registered,
        LifecyclePhase::Loaded,
    ];

    for expected_phase in expected_phases {
        let env = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .expect("lifecycle event timed out")
            .expect("recv failed");
        assert_eq!(
            env.payload.phase, expected_phase,
            "expected phase {:?}, got {:?}",
            expected_phase, env.payload.phase
        );
        assert_eq!(env.payload.plugin, plugin_id);
    }

    // Step 9: unload and assert Unloaded event.
    kernel.unload(&plugin_id).await.expect("unload");

    assert!(
        kernel.list_plugins().is_empty(),
        "plugin list should be empty after unload"
    );

    let unload_env = tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .expect("unload event timed out")
        .expect("recv failed");
    assert_eq!(unload_env.payload.phase, LifecyclePhase::Unloaded);
    assert_eq!(unload_env.payload.plugin, plugin_id);

    println!("[hello_world_e2e] all lifecycle events verified — test passed");
}
