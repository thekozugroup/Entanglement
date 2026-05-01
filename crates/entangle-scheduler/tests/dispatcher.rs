//! Integration tests for the Dispatcher.

use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::{peer_id::PeerId, resource::ResourceSpec, task::OneShotTask};
use std::sync::Arc;

// ── helpers ──────────────────────────────────────────────────────────────────

fn build_keyring(keypair: &IdentityKeyPair) -> Keyring {
    let pub_key = keypair.public();
    let entry = TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "test-publisher".into(),
        added_at: 0,
        note: String::new(),
    };
    let mut kr = Keyring::new();
    kr.add(entry);
    kr
}

fn local_peer() -> PeerId {
    PeerId::from_public_key_bytes(&[0xab; 32])
}

/// Write a signed plugin package (manifest + wasm + sig) into `dir`.
///
/// Returns the plugin id string.
fn write_plugin_package(
    dir: &std::path::Path,
    keypair: &IdentityKeyPair,
    wasm_bytes: &[u8],
) -> String {
    let publisher = keypair.fingerprint_hex();
    let plugin_id_str = format!("{publisher}/test-plugin@0.1.0");

    let manifest_toml = format!(
        r#"[plugin]
id = "{plugin_id_str}"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "scheduler integration test plugin"
"#
    );

    std::fs::write(dir.join("entangle.toml"), manifest_toml.as_bytes()).expect("write manifest");
    std::fs::write(dir.join("plugin.wasm"), wasm_bytes).expect("write wasm");

    let bundle = sign_artifact(wasm_bytes, keypair);
    let sig_toml = toml::to_string(&bundle).expect("serialize bundle");
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).expect("write sig");

    plugin_id_str
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Dispatch with an empty pool and no resource requirements falls back to the
/// local kernel and returns the plugin output.
///
/// Uses the hello-pong fixture which echos "Hello, <input>!".
#[tokio::test]
#[ignore = "TODO: requires hello-pong fixture to have a run export wired to resources-zero path"]
async fn dispatch_with_empty_pool_falls_back_to_local_when_no_resources_required() {
    let wasm = match std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/entangle-host/tests/fixtures/hello-pong.wasm"
    )) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("hello-pong.wasm not found ({e}); skipping test");
            return;
        }
    };

    let keypair = IdentityKeyPair::generate();
    let keyring = build_keyring(&keypair);

    let dir = tempfile::tempdir().expect("tempdir");
    let plugin_id_str = write_plugin_package(dir.path(), &keypair, &wasm);
    let plugin_id: entangle_types::plugin_id::PluginId =
        plugin_id_str.parse().expect("parse plugin id");

    let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring).expect("kernel"));
    kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect("load ok");

    let pool = WorkerPool::new(); // empty — no workers
    let dispatcher = Dispatcher::new(pool, kernel, local_peer());

    let task = OneShotTask {
        id: uuid::Uuid::new_v4(),
        plugin: plugin_id,
        input: b"world".to_vec(),
        max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
        max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        resources: ResourceSpec::default(), // zero resources → triggers local fallback
        integrity: entangle_types::task::IntegrityPolicy::None,
        timeout_ms: 30_000,
    };

    let result = dispatcher
        .dispatch_one_shot(task)
        .await
        .expect("dispatch ok");
    assert_eq!(result.output, b"Hello, world!");
}
