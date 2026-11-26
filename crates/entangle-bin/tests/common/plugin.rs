use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use std::path::Path;

/// Build a trusted [`Keyring`] containing `keypair`'s public key. Mirrors the
/// `keyring_for` helper in `entangle-runtime`'s test suite.
pub fn keyring_for(keypair: &IdentityKeyPair) -> Keyring {
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

/// The committed hello-pong fixture: a real, instantiable component whose
/// `run` export echoes `"Hello, {input}!"` (and `"pong"` on empty input).
pub fn hello_pong_wasm() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong.wasm fixture not found — run fixtures-src/hello-pong/build.sh")
}

/// Write a complete signed plugin package (manifest + wasm + `.sig`) to `dir`
/// and return the plugin id string. Mirrors `write_plugin_package` in
/// `entangle-runtime`'s test suite: the signature bundle covers both the
/// artifact and the manifest bytes.
pub fn write_plugin_package(dir: &Path, keypair: &IdentityKeyPair, wasm_bytes: &[u8]) -> String {
    let publisher = keypair.fingerprint_hex();
    let plugin_id_str = format!("{publisher}/test-plugin@0.1.0");
    let manifest_toml = format!(
        r#"[plugin]
id = "{plugin_id_str}"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "rpc integration test plugin"
"#
    );

    std::fs::write(dir.join("entangle.toml"), manifest_toml.as_bytes()).expect("write manifest");
    std::fs::write(dir.join("plugin.wasm"), wasm_bytes).expect("write wasm");

    let bundle = sign_artifact(wasm_bytes, manifest_toml.as_bytes(), keypair);
    let sig_toml = toml::to_string(&bundle).expect("serialize bundle");
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).expect("write sig");

    plugin_id_str
}
