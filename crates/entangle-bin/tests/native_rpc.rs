//! The daemon's JSON-RPC path loads and invokes a tier-5 native plugin
//! (`examples/native-echo`, built with cargo) under the real OS sandbox.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use entangle_bin::{config, methods, state::DaemonState};
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;

fn build_native_echo() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf();
    let target_dir = root.join("target").join("native-examples");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let status = std::process::Command::new(cargo)
        .args(["build", "--quiet", "--manifest-path"])
        .arg(root.join("examples/native-echo/Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .unwrap();
    assert!(status.success(), "building examples/native-echo failed");
    target_dir.join("debug").join("entangle-native-echo")
}

async fn rpc(
    state: &Arc<DaemonState>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let req = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    serde_json::from_str(&methods::dispatch(&req.to_string(), state).await).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_rpc_loads_and_invokes_a_native_plugin() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();

    // Signed native package.
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let bin = std::fs::read(build_native_echo()).unwrap();
    let id = format!("{}/native-echo@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 5\nruntime = \"native\"\n\n\
         [capabilities]\n\"storage.local\" = {{ scope = \"plugin\" }}\n"
    );
    std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(pkg.join("plugin.bin"), &bin).unwrap();
    std::fs::write(
        pkg.join("plugin.bin.sig"),
        toml::to_string(&sign_artifact(&bin, manifest.as_bytes(), &kp)).unwrap(),
    )
    .unwrap();

    // Daemon state built the way `entangled run` builds it.
    let config_dir = tmp.path().join(".entangle");
    let cfg = config::load_config(&config_dir.join("config.toml")).unwrap();
    let mut keyring = Keyring::new();
    keyring.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "native-rpc".into(),
        added_at: 0,
        note: String::new(),
    });
    let kernel = Arc::new(Kernel::new(config::kernel_config(&cfg, &config_dir), keyring).unwrap());
    let pool = WorkerPool::new();
    let identity = IdentityKeyPair::generate();
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let state = Arc::new(DaemonState::new(
        kernel.clone(),
        Arc::new(Dispatcher::new(pool.clone(), kernel, local)),
        pool,
        PeerStore::new(),
        identity,
        "native-rpc".into(),
    ));

    let loaded = rpc(&state, "plugins/load", serde_json::json!({ "dir": pkg })).await;
    assert_eq!(
        loaded["result"]["plugin_id"],
        serde_json::json!(id),
        "{loaded}"
    );

    let input: Vec<u8> = b"over json-rpc".to_vec();
    let out = rpc(
        &state,
        "plugins/invoke",
        serde_json::json!({ "plugin_id": id, "input": input, "timeout_ms": 10_000 }),
    )
    .await;
    assert_eq!(out["result"]["output"], serde_json::json!(input), "{out}");

    // Its storage scope is under the daemon's data dir, and it was used.
    let own = config_dir
        .join("data/plugins")
        .join(kp.fingerprint_hex())
        .join("native-echo");
    assert_eq!(std::fs::read_to_string(own.join("requests")).unwrap(), "1");

    let unloaded = rpc(
        &state,
        "plugins/unload",
        serde_json::json!({ "plugin_id": id }),
    )
    .await;
    assert!(unloaded.get("error").is_none(), "{unloaded}");
}

/// A run-time revocation recorded in the plugin-state file is re-applied
/// before a restored plugin can be called: a native plugin's sandbox is
/// derived without the revoked capability, so it restores usable — instead
/// of with a sandbox holding the capability and every call refused
/// (`ENTANGLE-E0125`) until an operator reloads it.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_native_plugin_runs_without_a_recorded_revocation() {
    use entangle_bin::plugin_state::{restore, PluginStateStore, STATE_FILE};

    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let bin = std::fs::read(build_native_echo()).unwrap();
    let id = format!("{}/native-echo@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 5\nruntime = \"native\"\n\n\
         [capabilities]\n\"storage.local\" = {{ scope = \"plugin\" }}\n"
    );
    std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(pkg.join("plugin.bin"), &bin).unwrap();
    std::fs::write(
        pkg.join("plugin.bin.sig"),
        toml::to_string(&sign_artifact(&bin, manifest.as_bytes(), &kp)).unwrap(),
    )
    .unwrap();
    let config_dir = tmp.path().join(".entangle");
    let daemon = || {
        let cfg = config::load_config(&config_dir.join("config.toml")).unwrap();
        let mut keyring = Keyring::new();
        keyring.add(TrustEntry {
            fingerprint: kp.fingerprint(),
            public_key: *kp.public().as_bytes(),
            publisher_name: "native-rpc".into(),
            added_at: 0,
            note: String::new(),
        });
        let kernel =
            Arc::new(Kernel::new(config::kernel_config(&cfg, &config_dir), keyring).unwrap());
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
                "native-rpc".into(),
            )
            .with_plugin_state(Arc::new(PluginStateStore::new(config_dir.join(STATE_FILE)))),
        )
    };
    {
        let state = daemon();
        let loaded = rpc(&state, "plugins/load", serde_json::json!({ "dir": pkg })).await;
        assert!(loaded["error"].is_null(), "{loaded}");
        let revoked = rpc(
            &state,
            "perms/revoke",
            serde_json::json!({ "plugin_id": id, "capability": "storage.local" }),
        )
        .await;
        assert!(revoked["error"].is_null(), "{revoked}");
    }

    let state = daemon();
    let report = restore(&state.kernel, state.plugin_state.as_ref().unwrap(), None).await;
    assert_eq!(report.restored, [id.clone()], "{report:?}");
    let input: Vec<u8> = b"after a restart".to_vec();
    let out = rpc(
        &state,
        "plugins/invoke",
        serde_json::json!({ "plugin_id": id, "input": input, "timeout_ms": 10_000 }),
    )
    .await;
    assert_eq!(out["result"]["output"], serde_json::json!(input), "{out}");
    // Without its storage: nothing counted.
    let own = config_dir
        .join("data/plugins")
        .join(kp.fingerprint_hex())
        .join("native-echo");
    assert!(!own.join("requests").exists());
}
