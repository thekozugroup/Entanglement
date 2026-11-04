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

// ── plugin state across restarts (spec §2.1) ─────────────────────────────────

mod restart {
    use entangle_bin::plugin_state::{restore, PluginStateFile, PluginStateStore, STATE_FILE};
    use entangle_bin::{config, methods, state::DaemonState};
    use entangle_observability::{catalog::names, Registry};
    use entangle_peers::PeerStore;
    use entangle_runtime::Kernel;
    use entangle_scheduler::{Dispatcher, WorkerPool};
    use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
    use entangle_types::peer_id::PeerId;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const HELLO: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/hello-pong.wasm");
    const PROBE: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/caps-probe.wasm");

    /// A node's on-disk state: `~/.entangle` and the packages it loads.
    pub(super) struct Node {
        _tmp: tempfile::TempDir,
        pub(super) dir: PathBuf,
        pub(super) kp: IdentityKeyPair,
    }

    impl Node {
        pub(super) fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join(".entangle");
            std::fs::create_dir_all(&dir).unwrap();
            Self {
                dir,
                _tmp: tmp,
                kp: IdentityKeyPair::generate(),
            }
        }

        pub(super) fn package(
            &self,
            name: &str,
            version: &str,
            wasm: &[u8],
            tier: u8,
            caps: &str,
        ) -> (PathBuf, String) {
            let pkg = self.dir.parent().unwrap().join(format!("{name}-{version}"));
            std::fs::create_dir_all(&pkg).unwrap();
            let id = format!("{}/{name}@{version}", self.kp.fingerprint_hex());
            let manifest = format!(
                "[plugin]\nid = \"{id}\"\nversion = \"{version}\"\ntier = {tier}\nruntime = \"wasm\"\n\n[capabilities]\n{caps}\n"
            );
            std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
            std::fs::write(pkg.join("plugin.wasm"), wasm).unwrap();
            std::fs::write(
                pkg.join("plugin.wasm.sig"),
                toml::to_string(&sign_artifact(wasm, manifest.as_bytes(), &self.kp)).unwrap(),
            )
            .unwrap();
            (pkg, id)
        }

        pub(super) fn hello(&self) -> (PathBuf, String) {
            self.package("hello", "0.1.0", HELLO, 1, "")
        }

        pub(super) fn probe(&self) -> (PathBuf, String) {
            self.package(
                "probe",
                "0.1.0",
                PROBE,
                1,
                "\"storage.local\" = { mode = \"rw\" }",
            )
        }

        pub(super) fn state_file(&self) -> PathBuf {
            self.dir.join(STATE_FILE)
        }

        /// A daemon as `main` builds it from `config.toml`, without
        /// restoring anything yet.
        pub(super) fn daemon(&self, registry: &Registry) -> Arc<DaemonState> {
            let cfg = config::load_config(&self.dir.join("config.toml")).unwrap();
            let mut keyring = Keyring::new();
            keyring.add(TrustEntry {
                fingerprint: self.kp.fingerprint(),
                public_key: *self.kp.public().as_bytes(),
                publisher_name: "restart".into(),
                added_at: 0,
                note: String::new(),
            });
            let kernel = Arc::new(
                Kernel::new(config::kernel_config(&cfg, &self.dir), keyring)
                    .unwrap()
                    .with_metrics(registry.clone()),
            );
            let pool = WorkerPool::new();
            let identity = IdentityKeyPair::generate();
            let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
            Arc::new(
                DaemonState::new(
                    kernel.clone(),
                    Arc::new(Dispatcher::new(pool.clone(), kernel, local)),
                    pool,
                    PeerStore::new(),
                    identity,
                    "restart".into(),
                )
                .with_plugin_state(Arc::new(PluginStateStore::new(self.state_file())))
                .with_config_path(self.dir.join("config.toml")),
            )
        }

        /// Start a daemon the way `main` does: build it, restore its plugins.
        pub(super) async fn start(
            &self,
            registry: &Registry,
        ) -> (Arc<DaemonState>, entangle_bin::plugin_state::RestoreReport) {
            let d = self.daemon(registry);
            let report = restore(&d.kernel, d.plugin_state.as_ref().unwrap(), Some(registry)).await;
            (d, report)
        }
    }

    pub(super) async fn rpc(
        state: &Arc<DaemonState>,
        method: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        let req =
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        serde_json::from_str(&methods::dispatch(&req.to_string(), state).await).unwrap()
    }

    async fn list(state: &Arc<DaemonState>) -> Vec<String> {
        let r = rpc(state, "plugins/list", serde_json::Value::Null).await;
        let mut v: Vec<String> = serde_json::from_value(r["result"]["plugins"].clone()).unwrap();
        v.sort();
        v
    }

    async fn invoke(state: &Arc<DaemonState>, id: &str, input: &[u8]) -> serde_json::Value {
        rpc(
            state,
            "plugins/invoke",
            serde_json::json!({ "plugin_id": id, "input": input, "timeout_ms": 30_000 }),
        )
        .await
    }

    fn output(r: &serde_json::Value) -> String {
        let bytes: Vec<u8> =
            serde_json::from_value(r["result"]["output"].clone()).unwrap_or_else(|_| panic!("{r}"));
        String::from_utf8(bytes).unwrap()
    }

    fn restores(reg: &Registry, outcome: &str) -> f64 {
        reg.value(names::PLUGIN_RESTORES, &[("outcome", outcome)])
            .unwrap_or(0.0)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn loaded_plugins_come_back_after_a_restart() {
        let node = Node::new();
        let (hello, hello_id) = node.hello();
        let (probe, probe_id) = node.probe();
        {
            let reg = Registry::new();
            let (d, report) = node.start(&reg).await;
            assert_eq!(report, Default::default(), "nothing recorded yet");
            for pkg in [&hello, &probe] {
                let r = rpc(&d, "plugins/load", serde_json::json!({ "dir": pkg })).await;
                assert!(r["error"].is_null(), "{r}");
            }
            // A run-time revocation is part of the recorded state.
            let r = rpc(
                &d,
                "perms/revoke",
                serde_json::json!({ "plugin_id": probe_id, "capability": "storage.local" }),
            )
            .await;
            assert!(r["error"].is_null(), "{r}");
        }

        // The file: private, both plugins, in load order, with their grants.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(node.state_file())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let file = PluginStateFile::read(&node.state_file()).unwrap();
        let ids: Vec<&str> = file.plugins.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, [hello_id.as_str(), probe_id.as_str()]);
        assert_eq!(file.plugins[1].revoked, ["storage.local"]);
        assert_eq!(file.plugins[1].dir, probe);
        assert!(file.plugins.iter().all(|e| e.failed.is_none()));

        // Restart.
        let reg = Registry::new();
        let (d, report) = node.start(&reg).await;
        assert_eq!(report.restored, [hello_id.clone(), probe_id.clone()]);
        assert_eq!(restores(&reg, "restored"), 2.0);
        let mut want = vec![hello_id.clone(), probe_id.clone()];
        want.sort();
        assert_eq!(list(&d).await, want);
        assert_eq!(
            output(&invoke(&d, &hello_id, b"again").await),
            "Hello, again!"
        );
        // The revocation still holds.
        let out = output(&invoke(&d, &probe_id, b"fetch storage-local\n").await);
        assert_eq!(out, "err:revoked:\n");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_tampered_package_is_skipped_with_a_warning_and_the_other_loads() {
        let node = Node::new();
        let (hello, hello_id) = node.hello();
        let (probe, probe_id) = node.probe();
        {
            let reg = Registry::new();
            let (d, _) = node.start(&reg).await;
            for pkg in [&hello, &probe] {
                assert!(
                    rpc(&d, "plugins/load", serde_json::json!({ "dir": pkg })).await["error"]
                        .is_null()
                );
            }
        }
        // While the daemon is down, the probe's artifact is altered: its
        // signature no longer verifies.
        let mut wasm = std::fs::read(probe.join("plugin.wasm")).unwrap();
        let last = wasm.len() - 1;
        wasm[last] ^= 0x01;
        std::fs::write(probe.join("plugin.wasm"), &wasm).unwrap();

        let reg = Registry::new();
        let logs = LogCapture::global();
        let (d, report) = node.start(&reg).await;
        assert_eq!(report.restored, [hello_id.as_str()]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, probe_id);
        assert_eq!(restores(&reg, "failed"), 1.0);
        assert_eq!(list(&d).await, vec![hello_id.clone()]);
        assert_eq!(output(&invoke(&d, &hello_id, b"").await), "pong");
        // One structured warning for it.
        let warnings: Vec<String> = logs
            .lines_with("ENTANGLE-E0784")
            .into_iter()
            .filter(|l| l.contains(&probe_id))
            .collect();
        assert_eq!(warnings.len(), 1, "{:?}", logs.text());
        assert!(warnings[0].contains(&probe_id), "{}", warnings[0]);
        assert!(
            warnings[0].contains("entangle::telemetry"),
            "{}",
            warnings[0]
        );

        // It stays in the file, marked, and is retried at the next start.
        let file = PluginStateFile::read(&node.state_file()).unwrap();
        let entry = file.plugins.iter().find(|e| e.id == probe_id).unwrap();
        assert!(
            entry.failed.as_deref().is_some_and(|f| !f.is_empty()),
            "{entry:?}"
        );
        drop(d);
        let reg = Registry::new();
        let (d, report) = node.start(&reg).await;
        assert_eq!(report.failed.len(), 1, "retried");
        // `plugins unload` forgets a failed entry.
        let r = rpc(
            &d,
            "plugins/unload",
            serde_json::json!({ "plugin_id": probe_id }),
        )
        .await;
        assert!(r["error"].is_null(), "{r}");
        let file = PluginStateFile::read(&node.state_file()).unwrap();
        assert_eq!(file.plugins.len(), 1);
        assert_eq!(file.plugins[0].id, hello_id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_plugin_disabled_while_the_daemon_was_down_is_not_reloaded() {
        let node = Node::new();
        let (hello, hello_id) = node.hello();
        let (probe, probe_id) = node.probe();
        {
            let reg = Registry::new();
            let (d, _) = node.start(&reg).await;
            for pkg in [&hello, &probe] {
                assert!(
                    rpc(&d, "plugins/load", serde_json::json!({ "dir": pkg })).await["error"]
                        .is_null()
                );
            }
        }
        // `entangle plugins disable` while the daemon is stopped.
        std::fs::write(
            node.dir.join("config.toml"),
            format!("[plugins]\ndisabled = [\"{probe_id}\"]\n"),
        )
        .unwrap();
        let reg = Registry::new();
        let (d, report) = node.start(&reg).await;
        assert_eq!(report.restored, [hello_id.as_str()]);
        assert_eq!(report.disabled, [probe_id.as_str()]);
        assert_eq!(restores(&reg, "disabled"), 1.0);
        assert_eq!(list(&d).await, vec![hello_id.clone()]);
        drop(d);

        // Enabled again: the next start brings it back.
        std::fs::write(node.dir.join("config.toml"), "").unwrap();
        let reg = Registry::new();
        let (d, report) = node.start(&reg).await;
        assert_eq!(report.restored.len(), 2);
        assert!(list(&d).await.contains(&probe_id));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_package_changed_while_the_daemon_was_down_is_not_reloaded() {
        let node = Node::new();
        let (hello, hello_id) = node.hello();
        {
            let reg = Registry::new();
            let (d, _) = node.start(&reg).await;
            assert!(
                rpc(&d, "plugins/load", serde_json::json!({ "dir": hello })).await["error"]
                    .is_null()
            );
        }
        // Re-signed with a new capability, same id: it verifies, but it is not
        // what the operator loaded.
        node.package("hello", "0.1.0", HELLO, 1, "\"custom.telemetry\" = {}");
        let reg = Registry::new();
        let (d, report) = node.start(&reg).await;
        assert!(report.restored.is_empty());
        assert!(
            report.failed[0].1.contains("changed since it was recorded"),
            "{report:?}"
        );
        assert!(list(&d).await.is_empty());
        let _ = hello_id;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hot_reload_over_rpc_asks_for_consent_and_is_recorded() {
        let node = Node::new();
        let (v1, v1_id) = node.package("probe", "0.1.0", PROBE, 1, "");
        let (v2, v2_id) = node.package(
            "probe",
            "0.2.0",
            PROBE,
            3,
            "\"net.wan\" = { hosts = [\"api.example.com:443\"] }",
        );
        let reg = Registry::new();
        let (d, _) = node.start(&reg).await;
        assert!(rpc(&d, "plugins/load", serde_json::json!({ "dir": v1 })).await["error"].is_null());

        let refused = rpc(&d, "plugins/load", serde_json::json!({ "dir": v2 })).await;
        let msg = refused["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(msg.contains("ENTANGLE-E0781"), "{refused}");
        assert!(
            msg.contains("+ net.wan (hosts=api.example.com:443)"),
            "{msg}"
        );
        assert!(msg.contains("tier 1 -> 3"), "{msg}");
        assert_eq!(list(&d).await, vec![v1_id.clone()]);

        let ok = rpc(
            &d,
            "plugins/load",
            serde_json::json!({ "dir": v2, "accept_new_capabilities": true }),
        )
        .await;
        assert_eq!(ok["result"]["plugin_id"], serde_json::json!(v2_id), "{ok}");
        assert_eq!(ok["result"]["replaced"], serde_json::json!(v1_id), "{ok}");
        assert_eq!(list(&d).await, vec![v2_id.clone()]);
        // Old clients' calls to the old id reach the new version.
        assert!(output(&invoke(&d, &v1_id, b"info\n").await).contains(&v2_id));
        let file = PluginStateFile::read(&node.state_file()).unwrap();
        let ids: Vec<&str> = file.plugins.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, [v2_id.as_str()]);
    }

    /// After a hot reload, `compute/dispatch` naming the replaced version's id
    /// runs the new version, as `plugins/invoke` does, instead of answering
    /// "plugin not loaded".
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_dispatch_to_a_replaced_id_runs_the_new_version() {
        let node = Node::new();
        let (v1, v1_id) = node.package("probe", "0.1.0", PROBE, 1, "");
        let (v2, v2_id) = node.package("probe", "0.2.0", PROBE, 1, "");
        let reg = Registry::new();
        let (d, _) = node.start(&reg).await;
        for dir in [&v1, &v2] {
            let r = rpc(&d, "plugins/load", serde_json::json!({ "dir": dir })).await;
            assert!(r["error"].is_null(), "{r}");
        }
        let r = rpc(
            &d,
            "compute/dispatch",
            serde_json::json!({
                "plugin_id": v1_id,
                "input": b"info\n",
                "timeout_ms": 30_000,
                "cpu_cores": 0.0,
                "memory_bytes": 0,
                "gpu_required": false,
                "gpu_vram_min_bytes": 0,
                "integrity": { "kind": "none" },
            }),
        )
        .await;
        assert!(r["error"].is_null(), "{r}");
        assert!(output(&r).contains(&v2_id), "{r}");
    }

    /// `perms revoke` and `perms list` naming a version replaced by a hot
    /// reload act on the version that answers for that id now (and say so),
    /// the same way calls to it are routed — not "not loaded" while calls to
    /// that id still run, with the capability.
    #[tokio::test(flavor = "multi_thread")]
    async fn perms_through_a_replaced_id_reach_the_version_answering_for_it() {
        let node = Node::new();
        let caps = "\"storage.local\" = { mode = \"rw\" }";
        let (v1, v1_id) = node.package("probe", "0.1.0", PROBE, 1, caps);
        let (v2, v2_id) = node.package("probe", "0.2.0", PROBE, 1, caps);
        let reg = Registry::new();
        let (d, _) = node.start(&reg).await;
        for dir in [&v1, &v2] {
            let r = rpc(&d, "plugins/load", serde_json::json!({ "dir": dir })).await;
            assert!(r["error"].is_null(), "{r}");
        }
        // 0.1.0 had nothing running: wait for its drain to finish.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while d.kernel.broker().registered_tiers().len() != 1 {
            assert!(std::time::Instant::now() < deadline, "0.1.0 never drained");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let listed = rpc(&d, "perms/list", serde_json::json!({ "plugin_id": v1_id })).await;
        assert!(listed["error"].is_null(), "{listed}");
        assert_eq!(
            listed["result"]["plugins"][0]["plugin_id"],
            serde_json::json!(v2_id),
            "{listed}"
        );

        let r = rpc(
            &d,
            "perms/revoke",
            serde_json::json!({ "plugin_id": v1_id, "capability": "storage.local" }),
        )
        .await;
        assert!(r["error"].is_null(), "{r}");
        assert_eq!(r["result"]["plugin_id"], serde_json::json!(v2_id), "{r}");
        // Calls through the old id run on 0.2.0, which no longer has it.
        let out = output(&invoke(&d, &v1_id, b"fetch storage-local\n").await);
        assert_eq!(out, "err:revoked:\n");
        // And it is recorded against 0.2.0, so it survives a restart.
        let file = PluginStateFile::read(&node.state_file()).unwrap();
        let entry = file.plugins.iter().find(|e| e.id == v2_id).unwrap();
        assert_eq!(entry.revoked, ["storage.local"]);
    }

    /// Captures formatted log lines (JSON) for assertions.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

    impl LogCapture {
        /// The process-wide capture (this test binary owns the subscriber).
        fn global() -> &'static LogCapture {
            static LOGS: std::sync::OnceLock<LogCapture> = std::sync::OnceLock::new();
            LOGS.get_or_init(|| {
                let c = LogCapture::default();
                tracing::subscriber::set_global_default(c.subscriber())
                    .expect("this test binary owns the subscriber");
                c
            })
        }

        fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
            let sink = self.clone();
            tracing_subscriber::fmt()
                .json()
                .with_writer(move || sink.clone())
                .with_max_level(tracing::Level::INFO)
                .finish()
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        fn lines_with(&self, needle: &str) -> Vec<String> {
            self.text()
                .lines()
                .filter(|l| l.contains(needle))
                .map(str::to_owned)
                .collect()
        }
    }

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn _unused(_: &Path) {}
}
