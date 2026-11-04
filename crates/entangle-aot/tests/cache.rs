//! The AOT cache against real Wasmtime engines: hits, the keyed MAC, the
//! permission checks, engine-configuration keys and garbage collection.

use entangle_aot::{AotCache, AotCacheConfig, Lookup, Rejection};
use entangle_observability::{catalog::names, Registry};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};
use wasmtime::{Config, Engine};

/// A small component with real code in it.
fn component(answer: i32) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(component
             (core module $m (func (export "f") (result i32) i32.const {answer}))
             (core instance $i (instantiate $m)))"#
    ))
    .unwrap()
}

fn engine() -> Engine {
    let mut cfg = Config::new();
    cfg.wasm_component_model(true);
    Engine::new(&cfg).unwrap()
}

/// An engine whose code generation differs (epoch interruption adds checks).
fn other_engine() -> Engine {
    let mut cfg = Config::new();
    cfg.wasm_component_model(true);
    cfg.epoch_interruption(true);
    Engine::new(&cfg).unwrap()
}

fn open(dir: &Path, registry: &Registry) -> AotCache {
    AotCache::open(AotCacheConfig::new(dir))
        .unwrap()
        .with_metrics(registry.clone())
}

fn count(registry: &Registry, name: &str, labels: &[(&str, &str)]) -> f64 {
    registry.value(name, labels).unwrap_or(0.0)
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn second_load_is_a_hit_and_survives_a_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("aot");
    let reg = Registry::new();
    let engine = engine();
    let bytes = component(7);

    let cache = open(&dir, &reg);
    let (_, first) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(first, Lookup::Miss);
    let (_, second) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(second, Lookup::Hit);
    assert_eq!(count(&reg, names::AOT_CACHE_MISSES, &[]), 1.0);
    assert_eq!(count(&reg, names::AOT_CACHE_HITS, &[]), 1.0);
    assert!(count(&reg, names::AOT_CACHE_BYTES, &[]) > 0.0);

    // Private on disk: directory 0700, key and entries 0600.
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("cache.key")), 0o600);
    assert_eq!(std::fs::metadata(dir.join("cache.key")).unwrap().len(), 32);
    let key = AotCache::entry_key(&engine, &bytes);
    assert_eq!(mode(&cache.artifact_path(&key)), 0o600);
    assert_eq!(mode(&cache.meta_path(&key)), 0o600);

    // A new process (same key file) trusts what the last one wrote.
    drop(cache);
    let reg2 = Registry::new();
    let cache = open(&dir, &reg2);
    let (_, again) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(again, Lookup::Hit);
}

#[test]
fn a_flipped_byte_in_the_artifact_is_rejected_and_recompiled() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::new();
    let engine = engine();
    let bytes = component(1);
    let cache = open(&tmp.path().join("aot"), &reg);
    cache.load_or_compile(&engine, &bytes).unwrap();

    let key = AotCache::entry_key(&engine, &bytes);
    let path = cache.artifact_path(&key);
    let mut artifact = std::fs::read(&path).unwrap();
    let mid = artifact.len() / 2;
    artifact[mid] ^= 0x01;
    std::fs::write(&path, &artifact).unwrap();

    let (_, lookup) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Rejected(Rejection::Mac));
    assert_eq!(
        count(&reg, names::AOT_CACHE_REJECTIONS, &[("reason", "mac")]),
        1.0
    );
    // Recompiled and stored afresh: the next load is a hit again.
    let (_, lookup) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Hit);
}

#[test]
fn a_flipped_byte_in_the_mac_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::new();
    let engine = engine();
    let bytes = component(2);
    let cache = open(&tmp.path().join("aot"), &reg);
    cache.load_or_compile(&engine, &bytes).unwrap();

    let key = AotCache::entry_key(&engine, &bytes);
    let meta_path = cache.meta_path(&key);
    let meta = std::fs::read_to_string(&meta_path).unwrap();
    let mac_at = meta.find("\nmac ").unwrap() + 5;
    let mut meta = meta.into_bytes();
    meta[mac_at] = if meta[mac_at] == b'0' { b'1' } else { b'0' };
    std::fs::write(&meta_path, &meta).unwrap();

    let (_, lookup) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Rejected(Rejection::Mac));
    let (_, lookup) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Hit);
}

#[test]
fn an_edited_sidecar_header_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::new();
    let engine = engine();
    let bytes = component(3);
    let cache = open(&tmp.path().join("aot"), &reg);
    cache.load_or_compile(&engine, &bytes).unwrap();
    let key = AotCache::entry_key(&engine, &bytes);
    let meta_path = cache.meta_path(&key);

    // Another Wasmtime version: refused before the MAC is even checked.
    let meta = std::fs::read_to_string(&meta_path).unwrap();
    std::fs::write(
        &meta_path,
        meta.replace(entangle_aot::WASMTIME_VERSION, "1.0.0"),
    )
    .unwrap();
    let (_, lookup) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Rejected(Rejection::Version));

    // Not a sidecar at all.
    std::fs::write(&meta_path, "hello").unwrap();
    let (_, lookup) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Rejected(Rejection::Header));
    assert_eq!(
        count(&reg, names::AOT_CACHE_REJECTIONS, &[("reason", "version")]),
        1.0
    );
    assert_eq!(
        count(&reg, names::AOT_CACHE_REJECTIONS, &[("reason", "header")]),
        1.0
    );
}

#[test]
fn an_entry_written_by_another_engine_configuration_is_a_miss() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::new();
    let (a, b) = (engine(), other_engine());
    let bytes = component(4);
    let cache = open(&tmp.path().join("aot"), &reg);

    assert_ne!(
        AotCache::entry_key(&a, &bytes),
        AotCache::entry_key(&b, &bytes),
        "the engine configuration is part of the key"
    );
    cache.load_or_compile(&a, &bytes).unwrap();
    let (_, lookup) = cache.load_or_compile(&b, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Miss);
    // Each configuration now has its own entry.
    assert_eq!(cache.load_or_compile(&a, &bytes).unwrap().1, Lookup::Hit);
    assert_eq!(cache.load_or_compile(&b, &bytes).unwrap().1, Lookup::Hit);

    // An entry renamed to stand in for the other configuration's key is
    // refused: its sidecar names the entry it was written for.
    let (ka, kb) = (
        AotCache::entry_key(&a, &bytes),
        AotCache::entry_key(&b, &bytes),
    );
    std::fs::copy(cache.artifact_path(&ka), cache.artifact_path(&kb)).unwrap();
    std::fs::copy(cache.meta_path(&ka), cache.meta_path(&kb)).unwrap();
    let (_, lookup) = cache.load_or_compile(&b, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Rejected(Rejection::Header));
}

#[test]
fn entries_others_can_write_or_links_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::new();
    let engine = engine();
    let bytes = component(5);
    let cache = open(&tmp.path().join("aot"), &reg);
    cache.load_or_compile(&engine, &bytes).unwrap();
    let key = AotCache::entry_key(&engine, &bytes);

    // Group-writable artifact.
    std::fs::set_permissions(
        cache.artifact_path(&key),
        std::fs::Permissions::from_mode(0o660),
    )
    .unwrap();
    let (_, lookup) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Rejected(Rejection::Permissions));
    assert!(
        cache.meta_path(&key).exists(),
        "rewritten after the rejection"
    );

    // A sidecar that is a symbolic link to a (valid) file elsewhere.
    let elsewhere = tmp.path().join("elsewhere.meta");
    std::fs::rename(cache.meta_path(&key), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, cache.meta_path(&key)).unwrap();
    let (_, lookup) = cache.load_or_compile(&engine, &bytes).unwrap();
    assert_eq!(lookup, Lookup::Rejected(Rejection::Permissions));
    assert_eq!(
        count(
            &reg,
            names::AOT_CACHE_REJECTIONS,
            &[("reason", "permissions")]
        ),
        2.0
    );
}

#[test]
fn a_directory_others_can_reach_disables_the_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("aot");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = AotCache::open(AotCacheConfig::new(&dir)).unwrap_err();
    assert!(err.to_string().contains("ENTANGLE-E0786"), "{err}");

    // A world-readable key file too.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join("cache.key"), [0u8; 32]).unwrap();
    std::fs::set_permissions(
        dir.join("cache.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let err = AotCache::open(AotCacheConfig::new(&dir)).unwrap_err();
    assert!(err.to_string().contains("ENTANGLE-E0786"), "{err}");
}

fn age(path: &Path, by: Duration) {
    let f = std::fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - by).unwrap();
}

#[test]
fn gc_removes_unused_entries_then_the_oldest_above_the_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::new();
    let engine = engine();
    let mut cfg = AotCacheConfig::new(tmp.path().join("aot"));
    cfg.max_unused = Duration::from_secs(10 * 24 * 3600);
    let cache = AotCache::open(cfg.clone())
        .unwrap()
        .with_metrics(reg.clone());

    let (old, older, fresh) = (component(10), component(11), component(12));
    for c in [&old, &older, &fresh] {
        cache.load_or_compile(&engine, c).unwrap();
    }
    let key = |c: &[u8]| AotCache::entry_key(&engine, c);
    // Last use is the sidecar's mtime.
    age(
        &cache.meta_path(&key(&old)),
        Duration::from_secs(11 * 24 * 3600),
    );
    age(
        &cache.meta_path(&key(&older)),
        Duration::from_secs(5 * 3600),
    );
    age(&cache.meta_path(&key(&fresh)), Duration::from_secs(60));
    // A partial write from a crash.
    let partial = tmp.path().join("aot/.tmp-1-1");
    std::fs::write(&partial, b"half").unwrap();
    age(&partial, Duration::from_secs(2 * 3600));

    let report = cache.gc();
    assert_eq!((report.expired, report.over_cap, report.orphans), (1, 0, 1));
    assert!(!cache.meta_path(&key(&old)).exists());
    assert!(!cache.artifact_path(&key(&old)).exists());
    assert!(!partial.exists());
    assert_eq!(
        count(&reg, names::AOT_CACHE_EVICTIONS, &[("reason", "age")]),
        1.0
    );

    // A cap that fits only the freshest entry: the least recently used goes.
    let size = |p: std::path::PathBuf| std::fs::metadata(p).unwrap().len();
    let one = size(cache.meta_path(&key(&fresh))) + size(cache.artifact_path(&key(&fresh)));
    let capped = AotCache::open(AotCacheConfig {
        max_bytes: one,
        ..cfg
    })
    .unwrap()
    .with_metrics(reg.clone());
    let report = capped.gc();
    assert_eq!(report.over_cap, 1, "{report:?}");
    assert!(!capped.meta_path(&key(&older)).exists());
    assert!(capped.meta_path(&key(&fresh)).exists());
    assert_eq!(
        count(&reg, names::AOT_CACHE_EVICTIONS, &[("reason", "size")]),
        1.0
    );
    assert_eq!(
        count(&reg, names::AOT_CACHE_BYTES, &[]),
        report.bytes as f64
    );
    // A hit refreshes the last use, so it survives an age pass.
    assert_eq!(
        capped.load_or_compile(&engine, &fresh).unwrap().1,
        Lookup::Hit
    );
}
