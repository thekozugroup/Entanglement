//! `perms/list` and `perms/revoke` over the daemon's JSON-RPC path, with the
//! operator policy taken from `config.toml` (`[security] deny_capabilities`).
//!
//! A wasm plugin (the `caps-probe` fixture) declaring a capability the
//! operator denies loads without it (spec §4.5); its grants are visible per
//! capability, and a revocation is reflected in the listing and in what the
//! next invocation can do.

use std::sync::Arc;

use entangle_bin::{config, methods, state::DaemonState};
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;

const PROBE: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/caps-probe.wasm");

async fn rpc(
    state: &Arc<DaemonState>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let req = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    serde_json::from_str(&methods::dispatch(&req.to_string(), state).await).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn perms_list_shows_grants_denials_and_revocations() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();

    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let id = format!("{}/caps-probe@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 3\nruntime = \"wasm\"\n\n\
         [capabilities]\n\
         \"storage.local\" = {{ mode = \"rw\" }}\n\
         \"net.wan\" = {{ hosts = [\"api.example.com:443\"] }}\n"
    );
    std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(pkg.join("plugin.wasm"), PROBE).unwrap();
    std::fs::write(
        pkg.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(PROBE, manifest.as_bytes(), &kp)).unwrap(),
    )
    .unwrap();

    // The operator denies WAN egress for every plugin.
    let config_dir = tmp.path().join(".entangle");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        "[security]\ndeny_capabilities = [\"net.wan\"]\n",
    )
    .unwrap();
    let cfg = config::load_config(&config_dir.join("config.toml")).unwrap();
    let mut keyring = Keyring::new();
    keyring.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "perms-rpc".into(),
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
        "perms-rpc".into(),
    ));

    let loaded = rpc(&state, "plugins/load", serde_json::json!({ "dir": pkg })).await;
    assert_eq!(
        loaded["result"]["plugin_id"],
        serde_json::json!(id),
        "{loaded}"
    );

    // No params: every plugin.
    let all = rpc(&state, "perms/list", serde_json::Value::Null).await;
    let plugins = all["result"]["plugins"].as_array().expect("plugins");
    assert_eq!(plugins.len(), 1, "{all}");
    let p = &plugins[0];
    assert_eq!(p["plugin_id"], serde_json::json!(id));
    assert_eq!(p["effective_tier"], serde_json::json!(3));
    let cap = |list: &serde_json::Value, key: &str| -> serde_json::Value {
        list["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["capability"] == key)
            .unwrap_or_else(|| panic!("{key} in {list}"))
            .clone()
    };
    let local_cap = cap(p, "storage.local");
    assert_eq!(local_cap["state"], "granted", "{local_cap}");
    assert_eq!(local_cap["params"], "scope=plugin mode=rw");
    assert_eq!(local_cap["grant_ids"].as_array().unwrap().len(), 1);
    let wan = cap(p, "net.wan");
    assert_eq!(wan["state"], "denied", "{wan}");
    assert_eq!(wan["params"], "hosts=api.example.com:443");
    assert!(
        wan["reason"].as_str().unwrap().contains("operator policy"),
        "{wan}"
    );

    // The plugin works with what it was granted, and not with the rest.
    let script = b"write /data/x.txt y\nfetch net-wan\n".to_vec();
    let out = rpc(
        &state,
        "plugins/invoke",
        serde_json::json!({ "plugin_id": id, "input": script, "timeout_ms": 30_000 }),
    )
    .await;
    let bytes: Vec<u8> = serde_json::from_value(out["result"]["output"].clone()).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        text.starts_with("ok\nerr:not-granted:ENTANGLE-E0124"),
        "{text}"
    );

    // Revoke storage.local over RPC; the listing and the next invocation see it.
    let revoked = rpc(
        &state,
        "perms/revoke",
        serde_json::json!({ "plugin_id": id, "capability": "storage.local" }),
    )
    .await;
    assert_eq!(
        revoked["result"]["withdrawn"].as_array().unwrap().len(),
        1,
        "{revoked}"
    );
    let one = rpc(&state, "perms/list", serde_json::json!({ "plugin_id": id })).await;
    assert_eq!(
        cap(&one["result"]["plugins"][0], "storage.local")["state"],
        "revoked",
        "{one}"
    );
    let out = rpc(
        &state,
        "plugins/invoke",
        serde_json::json!({ "plugin_id": id, "input": b"write /data/x.txt z\n".to_vec(), "timeout_ms": 30_000 }),
    )
    .await;
    let bytes: Vec<u8> = serde_json::from_value(out["result"]["output"].clone()).unwrap();
    assert!(String::from_utf8(bytes).unwrap().starts_with("err:"));

    // Errors: unknown capability, plugin not loaded, malformed id.
    let bad = rpc(
        &state,
        "perms/revoke",
        serde_json::json!({ "plugin_id": id, "capability": "compute.gpu" }),
    )
    .await;
    assert!(
        bad["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ENTANGLE-E0120"),
        "{bad}"
    );
    let other = format!("{}/absent@0.1.0", kp.fingerprint_hex());
    let missing = rpc(
        &state,
        "perms/list",
        serde_json::json!({ "plugin_id": other }),
    )
    .await;
    assert!(
        missing["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not loaded"),
        "{missing}"
    );
    let malformed = rpc(
        &state,
        "perms/list",
        serde_json::json!({ "plugin_id": "nope" }),
    )
    .await;
    assert_eq!(malformed["error"]["code"], -32602, "{malformed}");
}
