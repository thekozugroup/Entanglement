//! Shared fixtures: signed packages and artifact seeding.
#![allow(dead_code)]

use entangle_oci::testing::MockRegistry;
use entangle_oci::*;
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};

pub fn keypair(seed: u8) -> IdentityKeyPair {
    IdentityKeyPair::from_seed(&[seed; 32])
}

pub fn trust(kp: &IdentityKeyPair, name: &str) -> TrustEntry {
    TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: name.to_owned(),
        added_at: 0,
        note: String::new(),
    }
}

pub fn keyring_with(kps: &[&IdentityKeyPair]) -> Keyring {
    let mut k = Keyring::new();
    for (i, kp) in kps.iter().enumerate() {
        k.add(trust(kp, &format!("pub{i}")));
    }
    k
}

/// A signed package whose manifest names `kp` as publisher.
pub fn signed_files(kp: &IdentityKeyPair, name: &str, wasm: &[u8]) -> PackageFiles {
    let manifest = format!(
        "[plugin]\nid = \"{}/{name}@0.1.0\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n",
        kp.fingerprint_hex()
    );
    let bundle = sign_artifact(wasm, manifest.as_bytes(), kp);
    PackageFiles {
        manifest: manifest.into_bytes(),
        wasm: wasm.to_vec(),
        signature: toml::to_string(&bundle_to_value(&bundle))
            .unwrap()
            .into_bytes(),
        provenance: None,
    }
}

fn bundle_to_value(b: &entangle_signing::SignatureBundle) -> toml::Value {
    toml::Value::try_from(b).unwrap()
}

pub fn signed_package(kp: &IdentityKeyPair, name: &str, wasm: &[u8]) -> Vec<u8> {
    pack(&signed_files(kp, name, wasm)).unwrap()
}

pub fn wasm_bytes(n: usize) -> Vec<u8> {
    let mut v = b"\0asm\x01\0\0\0".to_vec();
    // xorshift: incompressible, so package sizes track `n`.
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    v.extend((0..n).map(|_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x >> 24) as u8
    }));
    v
}

/// Store a plugin artifact directly in the mock (no client involved).
pub fn seed_artifact(mock: &MockRegistry, repo: &str, tag: &str, package: &[u8]) -> String {
    let layer = mock.put_blob(package);
    let empty = mock.put_blob(b"{}");
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: MEDIA_TYPE_MANIFEST.into(),
        artifact_type: Some(ARTIFACT_TYPE_PLUGIN.into()),
        config: Descriptor {
            media_type: MEDIA_TYPE_EMPTY.into(),
            digest: empty.parse().unwrap(),
            size: 2,
            artifact_type: None,
            annotations: None,
        },
        layers: vec![Descriptor {
            media_type: LAYER_TYPE_PLUGIN.into(),
            digest: layer.parse().unwrap(),
            size: package.len() as u64,
            artifact_type: None,
            annotations: None,
        }],
        annotations: None,
    };
    mock.put_manifest(
        repo,
        tag,
        MEDIA_TYPE_MANIFEST,
        &serde_json::to_vec(&manifest).unwrap(),
    )
}

pub fn client(mock: &MockRegistry) -> OciClient {
    client_with(mock, ClientConfig::default())
}

pub fn client_with(mock: &MockRegistry, mut cfg: ClientConfig) -> OciClient {
    cfg.retry.base_delay = std::time::Duration::from_millis(1);
    cfg.retry.max_delay = std::time::Duration::from_millis(5);
    OciClient::new(&mock.registry(), cfg).unwrap()
}

pub fn reference(mock: &MockRegistry, rest: &str) -> Reference {
    Reference::parse(&format!("oci://{}/{rest}", mock.registry())).unwrap()
}
