//! A selector is bound to the exact signed WASI command and manifest used by this invocation.
use entangle_runtime::{Kernel, KernelConfig};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use serde_json::{json, Value};
use std::path::Path;

fn wasm(return_value: u32, start: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(component
        (core module $m {start} (func (export "run") (result i32) i32.const {return_value}))
        (core instance $i (instantiate $m))
        (func $run (result (result)) (canon lift (core func $i "run")))
        (instance $command (export "run" (func $run)))
        (export "wasi:cli/run@0.2.0" (instance $command)))"#
    ))
    .unwrap()
}

fn package(dir: &Path, signer: &IdentityKeyPair, wasm: &[u8], description: &str) -> Value {
    let manifest = format!(
        r#"[plugin]
id = "{}/checks@0.1.0"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "{description}"
[build]
wit_world = "wasi:cli/command@0.2.0"
target = "wasm32-wasip2"
"#,
        signer.fingerprint_hex()
    );
    let signature = sign_artifact(wasm, manifest.as_bytes(), signer);
    std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    std::fs::write(dir.join("entangle.toml"), manifest).unwrap();
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&signature).unwrap(),
    )
    .unwrap();
    json!({
        "artifact_blake3": hex::encode(signature.artifact_blake3),
        "manifest_blake3": hex::encode(signature.manifest_blake3),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_suite_pins_follow_the_loaded_object_across_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let signer = IdentityKeyPair::generate();
    let mut ring = Keyring::new();
    ring.add(TrustEntry {
        fingerprint: signer.fingerprint(),
        public_key: *signer.public().as_bytes(),
        added_at: 0,
        publisher_name: "fixture".into(),
        note: String::new(),
    });
    let kernel = Kernel::new(KernelConfig::default(), ring).unwrap();
    let original = package(dir.path(), &signer, &wasm(0, ""), "first");
    let id = kernel.load_plugin_from_dir(dir.path()).await.unwrap();
    for operation in [
        json!({"operation":"list"}),
        json!({"operation":"list","ignored":true,"expected_suite_identity":original}),
        json!({"operation":"test","name":"sample","expected_suite_identity":original}),
    ] {
        let bytes = kernel
            .invoke(&id, &serde_json::to_vec(&operation).unwrap(), 2000)
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["suite_identity"], original);
        assert_eq!(response["exit_code"], 0);
    }
    let mut previous = original;
    for (status, description) in [(0, "second"), (1, "second")] {
        let next = package(dir.path(), &signer, &wasm(status, ""), description);
        // Replacing files leaves the identity of the already-loaded code authoritative.
        let result = kernel
            .invoke(&id, br#"{"operation":"list"}"#, 2000)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&result).unwrap()["suite_identity"],
            previous
        );
        kernel.unload(&id).await.unwrap();
        assert_eq!(kernel.load_plugin_from_dir(dir.path()).await.unwrap(), id);
        for operation in [
            json!({"operation":"list","expected_suite_identity":previous}),
            json!({"operation":"test","name":"sample","attempt":2,"expected_suite_identity":previous}),
        ] {
            let err = kernel
                .invoke(&id, &serde_json::to_vec(&operation).unwrap(), 2000)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("libtest suite identity mismatch"),
                "{err}"
            );
        }
        let request = json!({"operation":"test","name":"sample","expected_suite_identity":next});
        let result = kernel
            .invoke(&id, &serde_json::to_vec(&request).unwrap(), 2000)
            .await
            .unwrap();
        let observed: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(observed["suite_identity"], next);
        assert_eq!(observed["exit_code"], status);
        previous = next;
    }
    // An unpinned invocation of this module traps during instantiation. The stale pin
    // must return the identity error before running even the component's start code.
    let trapped = wasm(0, "(func $start unreachable) (start $start)");
    kernel.unload(&id).await.unwrap();
    package(dir.path(), &signer, &trapped, "second");
    kernel.load_plugin_from_dir(dir.path()).await.unwrap();
    let request = json!({"operation":"test","name":"sample","expected_suite_identity":previous});
    let mismatch = kernel
        .invoke(&id, &serde_json::to_vec(&request).unwrap(), 2000)
        .await
        .unwrap_err();
    assert!(mismatch
        .to_string()
        .contains("libtest suite identity mismatch"));
    let unpinned = kernel
        .invoke(&id, br#"{"operation":"test","name":"sample"}"#, 2000)
        .await
        .unwrap_err();
    assert!(
        unpinned.to_string().contains("instantiation failed"),
        "{unpinned}"
    );
}
