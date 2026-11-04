//! Daemon-side runtime lifecycle: the `[runtime]` AOT cache settings and the
//! maintenance loop's AOT cache GC.

use entangle_bin::config::{self, Config};
use entangle_bin::maintenance::{MaintenanceConfig, MaintenanceLoop};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn the_aot_cache_is_on_by_default_and_can_be_turned_off() {
    let dir = Path::new("/home/op/.entangle");
    let cfg = Config::default();
    let aot = config::kernel_config(&cfg, dir)
        .aot_cache
        .expect("on by default");
    assert_eq!(aot.dir, dir.join("aot"));
    assert_eq!(aot.max_bytes, 512 * 1024 * 1024);
    assert_eq!(aot.max_unused, Duration::from_secs(30 * 24 * 3600));

    let cfg: Config = toml::from_str(
        "[runtime]\naot_cache = true\naot_cache_max_mb = 64\naot_cache_max_unused_days = 2\n",
    )
    .unwrap();
    let aot = config::kernel_config(&cfg, dir).aot_cache.unwrap();
    assert_eq!(aot.max_bytes, 64 * 1024 * 1024);
    assert_eq!(aot.max_unused, Duration::from_secs(2 * 24 * 3600));

    let cfg: Config = toml::from_str("[runtime]\naot_cache = false\n").unwrap();
    assert!(config::kernel_config(&cfg, dir).aot_cache.is_none());

    // A typo is a load error, as everywhere in the daemon's config.
    assert!(toml::from_str::<Config>("[runtime]\naot_cahce = false\n").is_err());
}

fn backdate(path: &Path, age: Duration) {
    let f = std::fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - age).unwrap();
}

#[tokio::test]
async fn the_maintenance_loop_garbage_collects_the_aot_cache() {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let mut aot_cfg = entangle_runtime::AotCacheConfig::new(tmp.path().join("aot"));
    aot_cfg.max_unused = Duration::from_secs(24 * 3600);
    let cache = Arc::new(entangle_runtime::AotCache::open(aot_cfg).unwrap());

    // Two entries (GC reads only sizes and the sidecar's last-use time).
    let write = |name: &str| {
        let p = tmp.path().join("aot").join(name);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        std::fs::write(&p, b"x").unwrap();
        p
    };
    write("old.cwasm");
    let old_meta = write("old.meta");
    write("new.cwasm");
    write("new.meta");
    backdate(&old_meta, Duration::from_secs(2 * 24 * 3600));

    let maint = MaintenanceLoop::new(MaintenanceConfig {
        cache_dir: tmp.path().join("cache"),
        log_dir: tmp.path().join("logs"),
        identity_path: tmp.path().join("identity.key"),
        ..MaintenanceConfig::default()
    })
    .with_aot_cache(Some(cache));
    let report = maint.gc_aot_cache().await.expect("a cache is attached");
    assert_eq!(report.expired, 1);
    assert!(!old_meta.exists());
    assert!(tmp.path().join("aot/new.meta").exists());

    let without = MaintenanceLoop::new(MaintenanceConfig::default());
    assert!(without.gc_aot_cache().await.is_none());
}
