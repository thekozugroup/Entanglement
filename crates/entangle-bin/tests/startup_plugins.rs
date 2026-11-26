//! Verify configured plugin startup through the real daemon and signed packages.
#![cfg(unix)]

#[path = "common/plugin.rs"]
mod plugin;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use entangle_bin::config::{Config, RuntimeConfig};
use entangle_rpc::Client;
use entangle_signing::{IdentityKeyPair, Keyring};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

fn daemon(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_entangled"));
    command
        .arg("run")
        .env("HOME", home)
        .env("TOKIO_WORKER_THREADS", "2")
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

fn signed_package(home: &Path, publisher: &IdentityKeyPair) -> (PathBuf, String) {
    let state = home.join(".entangle");
    let package = state.join("plugins/test-plugin");
    fs::create_dir_all(&package).unwrap();
    plugin::keyring_for(publisher)
        .save(&state.join("keyring.toml"))
        .unwrap();
    let plugin_id = plugin::write_plugin_package(&package, publisher, &plugin::hello_pong_wasm());
    (package, plugin_id)
}

fn configure_plugins(home: &Path, plugins: Vec<PathBuf>) {
    let config = Config {
        runtime: RuntimeConfig {
            plugins,
            ..RuntimeConfig::default()
        },
        ..Config::default()
    };
    let path = home.join(".entangle/config.toml");
    fs::write(path, toml::to_string_pretty(&config).unwrap()).unwrap();
}

async fn start(home: &Path) -> (Child, Client) {
    let mut child = daemon(home).stdout(Stdio::null()).spawn().unwrap();
    let client = Client::new(home.join(".entangle/sock"));
    timeout(STARTUP_TIMEOUT, async {
        loop {
            assert_eq!(child.try_wait().unwrap(), None, "daemon exited at startup");
            if client.version().await.is_ok() {
                break;
            }
            sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("daemon did not become ready");
    (child, client)
}

async fn assert_startup_error(home: &Path, path: &Path, reason: &str) {
    let result = timeout(STARTUP_TIMEOUT, daemon(home).output())
        .await
        .expect("daemon did not exit after invalid startup plugin")
        .unwrap();
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(!result.status.success(), "unexpected success: {stderr}");
    assert!(stderr.contains(&path.display().to_string()), "{stderr}");
    assert!(stderr.contains(reason), "{stderr}");
    assert!(!home.join(".entangle/sock").exists());
}

#[tokio::test]
async fn absent_config_does_not_load_installed_packages() {
    let home = tempfile::tempdir().unwrap();
    signed_package(home.path(), &IdentityKeyPair::generate());
    assert!(!home.path().join(".entangle/config.toml").exists());

    let (mut child, client) = start(home.path()).await;
    assert!(client.plugins_list().await.unwrap().plugins.is_empty());
    child.kill().await.unwrap();
}

#[tokio::test]
async fn signed_configured_plugin_is_invocable_after_restart() {
    let home = tempfile::tempdir().unwrap();
    let (package, id) = signed_package(home.path(), &IdentityKeyPair::generate());
    configure_plugins(home.path(), vec![package]);

    for input in ["first start", "restart"] {
        let (mut child, client) = start(home.path()).await;
        let loaded = client.plugins_list().await.unwrap();
        assert_eq!(loaded.plugins.as_slice(), std::slice::from_ref(&id));
        let response = client
            .plugins_invoke(&id, input.as_bytes().to_vec(), 30_000)
            .await
            .unwrap();
        assert_eq!(response.output, format!("Hello, {input}!").as_bytes());
        child.kill().await.unwrap();
    }
}

#[tokio::test]
async fn invalid_and_duplicate_packages_prevent_startup() {
    let home = tempfile::tempdir().unwrap();
    let publisher = IdentityKeyPair::generate();
    let (package, _) = signed_package(home.path(), &publisher);

    let relative = PathBuf::from("plugins/test-plugin");
    configure_plugins(home.path(), vec![relative.clone()]);
    assert_startup_error(home.path(), &relative, "must be absolute").await;

    let missing = home.path().join("missing-package");
    configure_plugins(home.path(), vec![missing.clone()]);
    assert_startup_error(home.path(), &missing, "loading startup plugin package").await;

    let duplicate = home.path().join("other-package");
    fs::create_dir(&duplicate).unwrap();
    plugin::write_plugin_package(&duplicate, &publisher, &plugin::hello_pong_wasm());
    configure_plugins(home.path(), vec![package.clone(), duplicate.clone()]);
    assert_startup_error(home.path(), &duplicate, "plugin already loaded").await;

    let artifact = package.join("plugin.wasm");
    let mut tampered = fs::read(&artifact).unwrap();
    tampered.push(0);
    fs::write(artifact, tampered).unwrap();
    configure_plugins(home.path(), vec![package.clone()]);
    assert_startup_error(home.path(), &package, "ENTANGLE-E0102").await;

    Keyring::new()
        .save(&home.path().join(".entangle/keyring.toml"))
        .unwrap();
    configure_plugins(home.path(), vec![duplicate.clone()]);
    assert_startup_error(home.path(), &duplicate, "ENTANGLE-E0101").await;
}
