//! ATC-MAN-4 (spec §16.1, §9.4.1): installing a plugin whose tier exceeds
//! `[security] max_tier_allowed` is refused with the tier-ceiling error
//! (`ENTANGLE-E0043`, `PolicyError::TierAboveCeiling { plugin, ceiling }` —
//! the spec's `TierExceeded { plugin_tier, ceiling }`) and mutates no state:
//! no plugin registered, no broker grant or audit event, no file written.
//!
//! The daemon's install path is `plugins/load` over JSON-RPC; these tests
//! drive it through `methods::dispatch` with a kernel built from a parsed
//! `config.toml` exactly as `entangled run` builds it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use entangle_bin::{config, methods, state::DaemonState};
use entangle_broker::{BrokerError, PolicyError};
use entangle_peers::PeerStore;
use entangle_runtime::{Kernel, RuntimeError};
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::{peer_id::PeerId, tier::Tier};

fn keyring_for(kp: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "atc-man-4".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

fn hello_pong() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong fixture")
}

/// Write a signed package; returns the plugin id.
fn write_package(
    dir: &Path,
    kp: &IdentityKeyPair,
    tier: u8,
    runtime: &str,
    artifact: &[u8],
    artifact_name: &str,
    caps: &str,
) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let id = format!("{}/ceiling-probe@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = {tier}\nruntime = \"{runtime}\"\n\n\
         [capabilities]\n{caps}\n"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join(artifact_name), artifact).unwrap();
    let bundle = sign_artifact(artifact, manifest.as_bytes(), kp);
    std::fs::write(
        dir.join(format!("{artifact_name}.sig")),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    id
}

/// A daemon configured from `<home>/.entangle/config.toml`.
struct Daemon {
    state: Arc<DaemonState>,
}

fn daemon(home: &Path, config_toml: &str, kp: &IdentityKeyPair) -> Daemon {
    let config_dir = home.join(".entangle");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"), config_toml).unwrap();
    let cfg = config::load_config(&config_dir.join("config.toml")).unwrap();
    let kernel =
        Arc::new(Kernel::new(config::kernel_config(&cfg, &config_dir), keyring_for(kp)).unwrap());
    let pool = WorkerPool::new();
    let identity = IdentityKeyPair::generate();
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let dispatcher = Arc::new(Dispatcher::new(pool.clone(), kernel.clone(), local));
    Daemon {
        state: Arc::new(DaemonState::new(
            kernel,
            dispatcher,
            pool,
            PeerStore::new(),
            identity,
            "atc-man-4".into(),
        )),
    }
}

async fn rpc(d: &Daemon, method: &str, params: serde_json::Value) -> serde_json::Value {
    let req = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = methods::dispatch(&req.to_string(), &d.state).await;
    serde_json::from_str(&resp).unwrap()
}

/// Every file under `root` with its contents — the "no state mutated" oracle.
fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.insert(p.clone(), Vec::new());
                stack.push(p);
            } else {
                out.insert(p.clone(), std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

/// §16 ATC-MAN-4 — GIVEN an entangle.toml with `tier = 3` AND a config with
/// `[security] max_tier_allowed = 2`, WHEN it is installed, THEN the install
/// fails with the tier-ceiling error (plugin tier 3, ceiling 2) AND no plugin
/// state is mutated.
#[tokio::test(flavor = "multi_thread")]
async fn atc_man_4_install_rejects_above_ceiling() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    let pkg = tmp.path().join("pkg");
    // compute.cpu implies tier 2; the author declares tier 3.
    write_package(
        &pkg,
        &kp,
        3,
        "wasm",
        &hello_pong(),
        "plugin.wasm",
        "\"compute.cpu\" = {}",
    );
    let d = daemon(tmp.path(), "[security]\nmax_tier_allowed = 2\n", &kp);
    let before = tree(tmp.path());

    // Over the daemon's install path (JSON-RPC plugins/load).
    let resp = rpc(
        &d,
        "plugins/load",
        serde_json::json!({ "dir": pkg.display().to_string() }),
    )
    .await;
    let msg = resp["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(resp.get("result").is_none(), "load must fail: {resp}");
    assert!(msg.contains("ENTANGLE-E0043"), "{msg}");
    assert!(
        msg.contains("Networked") && msg.contains("Sandboxed"),
        "{msg}"
    );

    // The typed error, through the kernel API the RPC handler calls.
    let err = d.state.kernel.load_plugin_from_dir(&pkg).await.unwrap_err();
    match err {
        RuntimeError::Broker(BrokerError::Policy(PolicyError::TierAboveCeiling {
            plugin,
            ceiling,
        })) => {
            assert_eq!(plugin, Tier::Networked); // plugin_tier: 3
            assert_eq!(ceiling, Tier::Sandboxed); // ceiling: 2
        }
        other => panic!("expected TierAboveCeiling, got {other}"),
    }

    // No plugin state anywhere.
    let list = rpc(&d, "plugins/list", serde_json::json!({})).await;
    assert_eq!(list["result"]["plugins"], serde_json::json!([]), "{list}");
    assert!(d.state.kernel.list_plugins().is_empty());
    assert!(
        d.state.kernel.broker().audit_log().is_empty(),
        "no registration, grant, or release was audited"
    );
    assert_eq!(tree(tmp.path()), before, "no file was written or changed");
}

/// README: tier 5 "can be disabled globally with one config line" —
/// `max_tier_allowed = 4`. A native plugin is refused before any of its
/// storage scope or staged binary exists.
#[tokio::test(flavor = "multi_thread")]
async fn one_config_line_disables_tier_five_native_plugins() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    let pkg = tmp.path().join("pkg");
    let native = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    write_package(
        &pkg,
        &kp,
        5,
        "native",
        &native,
        "plugin.bin",
        "\"storage.local\" = { scope = \"plugin\" }",
    );
    let d = daemon(tmp.path(), "[security]\nmax_tier_allowed = 4\n", &kp);
    let before = tree(tmp.path());

    let resp = rpc(
        &d,
        "plugins/load",
        serde_json::json!({ "dir": pkg.display().to_string() }),
    )
    .await;
    let msg = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("ENTANGLE-E0043"), "{resp}");
    assert!(d.state.kernel.list_plugins().is_empty());
    assert!(d.state.kernel.broker().audit_log().is_empty());
    assert_eq!(tree(tmp.path()), before);
    assert!(!tmp.path().join(".entangle/native").exists());
    assert!(!tmp.path().join(".entangle/data").exists());
}

/// Control: at the ceiling the same package installs, so the refusal above
/// is the ceiling's doing.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_at_the_ceiling_installs() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    let pkg = tmp.path().join("pkg");
    let id = write_package(
        &pkg,
        &kp,
        2,
        "wasm",
        &hello_pong(),
        "plugin.wasm",
        "\"compute.cpu\" = {}",
    );
    let d = daemon(tmp.path(), "[security]\nmax_tier_allowed = 2\n", &kp);
    let resp = rpc(
        &d,
        "plugins/load",
        serde_json::json!({ "dir": pkg.display().to_string() }),
    )
    .await;
    assert_eq!(resp["result"]["plugin_id"], serde_json::json!(id), "{resp}");
}
