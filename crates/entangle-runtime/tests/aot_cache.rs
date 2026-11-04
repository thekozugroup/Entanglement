//! The kernel's AOT compilation cache (`KernelConfig::aot_cache`): a second
//! load of the same package is answered from the cache and invokes
//! correctly, also in a new kernel (a daemon restart); a damaged entry is
//! refused and the component compiled instead.

use entangle_observability::{catalog::names, Registry};
use entangle_runtime::{AotCache, AotCacheConfig, Kernel, KernelConfig};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use std::path::Path;

const HELLO: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/hello-pong.wasm");

fn keyring_for(kp: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "aot".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

fn write_package(dir: &Path, kp: &IdentityKeyPair) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let id = format!("{}/hello@0.1.0", kp.fingerprint_hex());
    let manifest =
        format!("[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n");
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join("plugin.wasm"), HELLO).unwrap();
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(HELLO, manifest.as_bytes(), kp)).unwrap(),
    )
    .unwrap();
    id
}

fn kernel(cache_dir: &Path, kp: &IdentityKeyPair, registry: &Registry) -> Kernel {
    Kernel::new(
        KernelConfig {
            aot_cache: Some(AotCacheConfig::new(cache_dir)),
            ..KernelConfig::default()
        },
        keyring_for(kp),
    )
    .unwrap()
    .with_metrics(registry.clone())
}

fn value(registry: &Registry, name: &str, labels: &[(&str, &str)]) -> f64 {
    registry.value(name, labels).unwrap_or(0.0)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_load_is_a_cache_hit_and_invokes_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    let pkg = tmp.path().join("pkg");
    let id = write_package(&pkg, &kp);
    let cache_dir = tmp.path().join("aot");
    let reg = Registry::new();
    let k = kernel(&cache_dir, &kp, &reg);

    let pid = k.load_plugin_from_dir(&pkg).await.unwrap();
    assert_eq!(pid.to_string(), id);
    assert_eq!(value(&reg, names::AOT_CACHE_MISSES, &[]), 1.0);
    assert_eq!(value(&reg, names::AOT_CACHE_HITS, &[]), 0.0);
    k.unload(&pid).await.unwrap();

    let pid = k.load_plugin_from_dir(&pkg).await.unwrap();
    assert_eq!(value(&reg, names::AOT_CACHE_HITS, &[]), 1.0);
    let out = k.invoke(&pid, b"cache", 10_000).await.unwrap();
    assert_eq!(out, b"Hello, cache!");

    // A new kernel — a restarted daemon — starts from the cache as well.
    let reg2 = Registry::new();
    let k2 = kernel(&cache_dir, &kp, &reg2);
    let pid = k2.load_plugin_from_dir(&pkg).await.unwrap();
    assert_eq!(value(&reg2, names::AOT_CACHE_HITS, &[]), 1.0);
    assert_eq!(value(&reg2, names::AOT_CACHE_MISSES, &[]), 0.0);
    assert_eq!(k2.invoke(&pid, b"", 10_000).await.unwrap(), b"pong");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_entry_is_refused_and_the_component_compiled() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    let pkg = tmp.path().join("pkg");
    write_package(&pkg, &kp);
    let cache_dir = tmp.path().join("aot");
    let reg = Registry::new();
    let k = kernel(&cache_dir, &kp, &reg);
    let pid = k.load_plugin_from_dir(&pkg).await.unwrap();
    k.unload(&pid).await.unwrap();

    // Flip one byte of the one artifact in the cache.
    let artifact = std::fs::read_dir(&cache_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "cwasm"))
        .expect("an artifact");
    let mut bytes = std::fs::read(&artifact).unwrap();
    let at = bytes.len() / 3;
    bytes[at] ^= 0x80;
    std::fs::write(&artifact, &bytes).unwrap();

    let pid = k.load_plugin_from_dir(&pkg).await.unwrap();
    assert_eq!(
        value(&reg, names::AOT_CACHE_REJECTIONS, &[("reason", "mac")]),
        1.0
    );
    assert_eq!(value(&reg, names::AOT_CACHE_HITS, &[]), 0.0);
    assert_eq!(k.invoke(&pid, b"x", 10_000).await.unwrap(), b"Hello, x!");
    // The recompiled component replaced the bad entry.
    k.unload(&pid).await.unwrap();
    k.load_plugin_from_dir(&pkg).await.unwrap();
    assert_eq!(value(&reg, names::AOT_CACHE_HITS, &[]), 1.0);
    // GC through the kernel's handle keeps a fresh entry.
    let report = k.aot_cache().expect("cache in use").gc();
    assert_eq!(report.expired + report.over_cap, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_cache_directory_leaves_the_kernel_compiling() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    let pkg = tmp.path().join("pkg");
    write_package(&pkg, &kp);
    // A directory others can read: not private, so not used.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let reg = Registry::new();
    let k = kernel(tmp.path(), &kp, &reg);
    assert!(k.aot_cache().is_none());
    let pid = k.load_plugin_from_dir(&pkg).await.unwrap();
    assert_eq!(k.invoke(&pid, b"", 10_000).await.unwrap(), b"pong");
    assert!(AotCache::open(AotCacheConfig::new(tmp.path())).is_err());
}
