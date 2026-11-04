//! `entangle plugins load <dir>` with a relative directory, against a daemon
//! whose working directory is another one: the CLI resolves the directory,
//! and the daemon records the package's real, absolute path — what its
//! plugin-state file restores after a restart, from any working directory.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;

use entangle_bin::plugin_state::{PluginStateFile, PluginStateStore, STATE_FILE};
use entangle_bin::{config as dcfg, server, state::DaemonState};
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;

const HELLO: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/hello-pong.wasm");

#[tokio::test(flavor = "multi_thread")]
async fn a_relative_package_dir_is_resolved_by_the_cli_and_recorded_absolute() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    let cdir = home.join(".entangle");
    std::fs::create_dir_all(&cdir).unwrap();
    std::fs::write(cdir.join("config.toml"), "").unwrap();

    // A signed package in <work>/pkg-hello; the CLI runs in <work>.
    let kp = IdentityKeyPair::generate();
    let work = tmp.path().join("work");
    let pkg = work.join("pkg-hello");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::create_dir_all(work.join("sub")).unwrap();
    let id = format!("{}/hello@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n\n[capabilities]\n"
    );
    std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(pkg.join("plugin.wasm"), HELLO).unwrap();
    std::fs::write(
        pkg.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(HELLO, manifest.as_bytes(), &kp)).unwrap(),
    )
    .unwrap();

    // The daemon, in-process: its working directory is this test's, not
    // <work>.
    let cfg = dcfg::load_config(&cdir.join("config.toml")).unwrap();
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "load-path".into(),
        added_at: 0,
        note: String::new(),
    });
    let kernel = Arc::new(Kernel::new(dcfg::kernel_config(&cfg, &cdir), kr).unwrap());
    let pool = WorkerPool::new();
    let identity = IdentityKeyPair::generate();
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let state = Arc::new(
        DaemonState::new(
            kernel.clone(),
            Arc::new(Dispatcher::new(pool.clone(), kernel, local)),
            pool,
            PeerStore::new(),
            identity,
            "load-path".into(),
        )
        .with_plugin_state(Arc::new(PluginStateStore::new(cdir.join(STATE_FILE)))),
    );
    let sock = cdir.join("sock");
    {
        let (sock, st) = (sock.clone(), state.clone());
        tokio::spawn(async move {
            let _ = server::serve(sock, st).await;
        });
    }
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(sock.exists(), "daemon socket never appeared");

    // `..` and a relative start: nothing about it is absolute or canonical.
    let out = {
        let (home, work) = (home.clone(), work.clone());
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_entangle"))
                .args(["plugins", "load", "sub/../pkg-hello"])
                .current_dir(&work)
                .env("HOME", &home)
                .env_remove("ENTANGLE_ALLOW_LOCAL")
                .env_remove("XDG_CONFIG_HOME")
                .output()
                .unwrap()
        })
        .await
        .unwrap()
    };
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let canonical: PathBuf = std::fs::canonicalize(&pkg).unwrap();
    let loaded = state.kernel.list_plugins();
    assert_eq!(loaded.len(), 1, "{loaded:?}");
    assert_eq!(
        state.kernel.loaded_source(&loaded[0]).unwrap().dir,
        canonical
    );
    let file = PluginStateFile::read(&cdir.join(STATE_FILE)).unwrap();
    assert_eq!(file.plugins.len(), 1);
    assert_eq!(file.plugins[0].dir, canonical);
}
