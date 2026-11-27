//! Exercise the signed-package loader, trust refresh, component ABI and unload path.
use entangle_runtime::{Kernel, KernelConfig, RuntimeError};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};

#[tokio::test]
async fn only_the_submitter_can_prepare_a_trusted_local_comparator() {
    let author = IdentityKeyPair::generate();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path();
    let wasm = wat::parse_str(include_str!(
        "../../entangle-host/tests/fixtures/byte-distance.wat"
    ))
    .unwrap();
    let id = format!("{}/equal@1.0.0", author.fingerprint_hex())
        .parse()
        .unwrap();
    let manifest=format!("[plugin]\nid='{id}'\nversion='1.0.0'\ntier=2\nruntime='wasm'\n[build]\nwit_world='entangle:integrity/comparator@0.1.0'\ntarget='wasm32-wasip2'\n");
    let sig = sign_artifact(&wasm, manifest.as_bytes(), &author);
    std::fs::write(path.join("entangle.toml"), manifest).unwrap();
    std::fs::write(path.join("plugin.wasm"), &wasm).unwrap();
    std::fs::write(path.join("plugin.wasm.sig"), toml::to_string(&sig).unwrap()).unwrap();
    let keyfile = path.join("trusted.toml");
    let kernel = Kernel::from_keyring_file(KernelConfig::default(), keyfile.clone()).unwrap();
    assert!(kernel.load_plugin_from_dir(path).await.is_err());
    assert!(matches!(
        kernel.prepare_metric(&id),
        Err(RuntimeError::MetricNotInKeyring(_))
    ));
    let mut ring = Keyring::new();
    ring.add(TrustEntry {
        fingerprint: author.fingerprint(),
        public_key: *author.public().as_bytes(),
        publisher_name: "operator".into(),
        added_at: 0,
        note: String::new(),
    });
    ring.save(&keyfile).unwrap();
    kernel.load_plugin_from_dir(path).await.unwrap();
    let metric = kernel.prepare_metric(&id).unwrap();
    assert_eq!(metric.cid, *blake3::hash(&wasm).as_bytes());
    assert_eq!(metric.publisher, *author.public().as_bytes());
    assert_eq!(metric.instantiations(), 0);
    assert!(matches!(
        kernel.invoke(&id, b"x", 1000).await,
        Err(RuntimeError::NotComputePlugin(_))
    ));
    assert_eq!(metric.compare(b"a", b"a", 1000).await.unwrap(), 0.0);
    assert_eq!(metric.compare(b"a", b"b", 1000).await.unwrap(), 1.0);
    assert_eq!(metric.instantiations(), 2);
    Keyring::new().save(&keyfile).unwrap();
    assert!(matches!(
        kernel.prepare_metric(&id),
        Err(RuntimeError::MetricNotInKeyring(_))
    ));
    kernel.unload(&id).await.unwrap();
    assert!(metric.compare(b"a", b"b", 1000).await.is_err());
    assert_eq!(metric.instantiations(), 2);
}
