//! End-to-end integration test: build hello-world → sign → load via kernel → lifecycle events.
//!
//! Marked `#[ignore]` because it requires the `wasm32-wasip2` target to be installed
//! and performs an out-of-process `cargo build`. Run with:
//!
//!   cargo test -p entangle-runtime --test hello_world_e2e -- --ignored
//!
//! Checks the actual component output and the complete load, invoke and unload lifecycle.

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

    let bundle = sign_artifact(wasm_bytes, manifest.as_bytes(), keypair);
    let sig_toml = toml::to_string(&bundle).expect("serialize sig bundle");
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).expect("write sig");

    plugin_id
}

// ---------------------------------------------------------------------------
// Build the signed guest from its own locked project using a separate target
// directory so the parent workspace Cargo invocation can run concurrently.
fn build_hello_world() -> Vec<u8> {
    let example =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-world");
    let target = example.join("target");
    let status = std::process::Command::new(env!("CARGO"))
        .current_dir(&example)
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "wasm32-wasip2",
            "--target-dir",
        ])
        .arg(&target)
        .status()
        .expect("start Cargo for the WASI example");
    assert!(status.success(), "hello-world WASI build failed: {status}");
    std::fs::read(target.join("wasm32-wasip2/release/entangle_hello_world.wasm"))
        .expect("read built hello-world component")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires wasm32-wasip2 target and runs cargo build out-of-process"]
async fn hello_world_full_pipeline() {
    let wasm_bytes = build_hello_world();

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

    let result = kernel
        .invoke(&plugin_id, b"release test", 5000)
        .await
        .unwrap();
    assert_eq!(result, b"Hello, release test!");

    // Check the load and invocation lifecycle in order.
    let expected_phases = [
        LifecyclePhase::ManifestValidated,
        LifecyclePhase::SignatureVerified,
        LifecyclePhase::Registered,
        LifecyclePhase::Loaded,
        LifecyclePhase::Activated,
        LifecyclePhase::Idled,
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
