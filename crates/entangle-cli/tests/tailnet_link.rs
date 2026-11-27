//! Operator-facing tailnet configuration through the installed CLI entry point.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use entangle_runtime::config::{load_config, TailnetPeerConfig};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use predicates::prelude::*;
use serde_json::{json, Value};
use tempfile::TempDir;

const FIRST_NODE: &str = "n12345678901";
const SECOND_NODE: &str = "n12345678902";
const PORT: &str = "7443";
const BUSY: &str = "configuration writer busy";
const CONFIG: &str = r#"# Operator configuration
[mesh]   # Keep the transport selection here
transports = ["local", "tailscale"]  # Discovery and tailnet
multi_node = true

[scheduler]
bind = "0.0.0.0:7440" # Local listener differs from the worker
relay = false

[runtime]  # Independent operator settings
bus_capacity = 256

[wrappers]
install = false  # A user choice
"#;
// A confined status-only stand-in keeps the CLI tests independent of the real
// Tailscale service and lets each case control the node IDs/address families.
const TAILSCALE: &str = r#"#!/bin/sh
test "$#" = 2 && test "$1" = status && test "$2" = --json || exit 2
exec /bin/cat "$ENTANGLE_TEST_TAILNET_STATUS"
"#;

struct Home(TempDir);

impl Home {
    fn new() -> Self {
        let home = Self(TempDir::new().unwrap());
        let tailscale = home.0.path().join("tailscale");
        fs::write(&tailscale, TAILSCALE).unwrap();
        fs::set_permissions(tailscale, fs::Permissions::from_mode(0o700)).unwrap();
        home.write_status(&Self::status());
        home.entangle()
            .args(["init", "--non-interactive"])
            .assert()
            .success();
        fs::write(home.config(), CONFIG).unwrap();
        home
    }

    fn status() -> Value {
        json!({
            "BackendState": "Running",
            "Self": {
                "ID": "n12345678900", "Online": true, "TailscaleIPs": ["100.64.0.2"],
            },
            "Peer": {
                "nodekey:fixture-a": {
                    "ID": FIRST_NODE, "Online": true, "HostName": "first-worker",
                    "DNSName": "first-worker.fixture.ts.net.",
                    "TailscaleIPs": ["100.64.0.3", "fd7a:115c:a1e0::3"],
                },
                "nodekey:fixture-b": {
                    "ID": SECOND_NODE, "Online": true, "HostName": "second-worker",
                    "TailscaleIPs": ["100.64.0.4"],
                },
            },
        })
    }

    fn status_path(&self) -> PathBuf {
        self.0.path().join("tailnet-status.json")
    }

    fn write_status(&self, status: &Value) {
        fs::write(self.status_path(), serde_json::to_vec(status).unwrap()).unwrap();
    }

    fn state(&self) -> PathBuf {
        self.0.path().join(".entangle")
    }

    fn config(&self) -> PathBuf {
        self.state().join("config.toml")
    }

    fn peers(&self) -> PathBuf {
        self.state().join("peers.toml")
    }

    fn entangle(&self) -> Command {
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("entangle");
        cmd.env("HOME", self.0.path())
            .env("PATH", self.0.path())
            .env("ENTANGLE_TEST_TAILNET_STATUS", self.status_path())
            .timeout(Duration::from_secs(10));
        cmd
    }

    fn trust(&self, peer: &Peer) {
        self.entangle()
            .args([
                "mesh",
                "trust",
                &peer.id,
                "--public-key-hex",
                &peer.key,
                "--display-name",
                "paired-worker",
            ])
            .assert()
            .success();
    }

    fn link(&self, node: &str, peer: &Peer, port: &str) -> Command {
        let mut cmd = self.entangle();
        cmd.args([
            "mesh", "tailnet", "link", node, "--peer", &peer.id, "--port", port,
        ]);
        cmd
    }

    fn link_json(&self, node: &str, peer: &Peer) -> Value {
        let assertion = self.link(node, peer, PORT).arg("--json").assert().success();
        serde_json::from_slice(&assertion.get_output().stdout).unwrap()
    }

    fn routes(&self) -> Vec<TailnetPeerConfig> {
        load_config(&self.config()).unwrap().scheduler.tailnet_peers
    }
}

struct Peer {
    id: String,
    key: String,
}

impl Peer {
    fn generate() -> Self {
        let key = IdentityKeyPair::generate().public();
        Self {
            id: PeerId::from_public_key_bytes(key.as_bytes()).to_hex(),
            key: hex::encode(key.as_bytes()),
        }
    }
}

#[test]
fn writes_the_paired_public_key_and_preserves_operator_config() {
    let home = Home::new();
    let peer = Peer::generate();
    home.trust(&peer);
    let original_peers = fs::read(home.peers()).unwrap();
    fs::set_permissions(home.config(), fs::Permissions::from_mode(0o640)).unwrap();

    let expected = json!({
        "node_id": FIRST_NODE, "peer_id": &peer.id, "public_key": &peer.key,
        "port": 7443, "changed": true, "tailscale_enabled": true,
    });
    assert_eq!(home.link_json(FIRST_NODE, &peer), expected);

    let config = load_config(&home.config()).unwrap();
    assert_eq!(config.mesh.transports, ["local", "tailscale"]);
    assert!(config.mesh.multi_node);
    assert_eq!(config.scheduler.bind, "0.0.0.0:7440");
    assert!(!config.scheduler.relay);
    assert_eq!(config.runtime.bus_capacity, 256);
    assert_eq!(config.wrappers.install, Some(false));
    assert_eq!(config.scheduler.tailnet_peers.len(), 1);
    let route = &config.scheduler.tailnet_peers[0];
    assert_eq!(route.node_id, FIRST_NODE);
    assert_eq!(route.public_key, peer.key);
    assert_eq!(route.port.get(), 7443);

    let linked = fs::read_to_string(home.config()).unwrap();
    for original_line in CONFIG.lines().filter(|line| !line.is_empty()) {
        assert!(
            linked.lines().any(|line| line == original_line),
            "lost {original_line:?}:\n{linked}"
        );
    }

    let mut expected = expected;
    expected["changed"] = json!(false);
    assert_eq!(home.link_json(FIRST_NODE, &peer), expected);
    assert_eq!(fs::read_to_string(home.config()).unwrap(), linked);
    assert_eq!(
        fs::metadata(home.config()).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(fs::read(home.peers()).unwrap(), original_peers);
}

#[test]
fn refuses_an_unknown_or_revoked_peer_without_changing_config() {
    let home = Home::new();
    let peer = Peer::generate();
    let original = fs::read(home.peers()).unwrap();

    home.link(FIRST_NODE, &peer, PORT).assert().failure();
    assert_eq!(fs::read_to_string(home.config()).unwrap(), CONFIG);
    assert_eq!(fs::read(home.peers()).unwrap(), original);

    home.trust(&peer);
    home.entangle()
        .args(["mesh", "revoke", &peer.id])
        .assert()
        .success();
    let revoked = fs::read(home.peers()).unwrap();

    home.link(FIRST_NODE, &peer, PORT)
        .assert()
        .failure()
        .stderr(predicate::str::contains("currently trusted"));
    assert_eq!(fs::read_to_string(home.config()).unwrap(), CONFIG);
    assert_eq!(fs::read(home.peers()).unwrap(), revoked);
}

#[test]
fn existing_status_and_new_link_preserve_explicit_transport_selection() {
    let home = Home::new();
    let peer = Peer::generate();
    home.trust(&peer);
    let disabled = CONFIG.replace("\"local\", \"tailscale\"", "\"local\"");
    fs::write(home.config(), &disabled).unwrap();

    let status = home
        .entangle()
        .args(["mesh", "tailnet", "--json"])
        .assert()
        .success();
    let status: Value = serde_json::from_slice(&status.get_output().stdout).unwrap();
    assert_eq!(status["backend_state"], "Running");
    let nodes = status["peers"].as_array().unwrap();
    assert!(nodes.iter().any(|node| node["node_id"] == FIRST_NODE));

    let linked = home.link_json(FIRST_NODE, &peer);
    assert_eq!(linked["tailscale_enabled"], false);
    assert_eq!(
        load_config(&home.config()).unwrap().mesh.transports,
        ["local"]
    );
    home.link(FIRST_NODE, &peer, PORT)
        .assert()
        .success()
        .stdout(predicate::str::contains("tailscale"))
        .stdout(predicate::str::contains("Restart entangled"));
}

#[test]
fn refuses_missing_ambiguous_offline_or_wrong_family_tailnet_nodes() {
    let home = Home::new();
    let peer = Peer::generate();
    home.trust(&peer);

    for node in ["first-worker", "n12345678900", "n12345678999"] {
        home.link(node, &peer, PORT).assert().failure();
        assert_eq!(fs::read_to_string(home.config()).unwrap(), CONFIG);
    }

    let status = Home::status();
    let mut ambiguous = status.clone();
    ambiguous["Peer"]["nodekey:fixture-b"]["ID"] = json!(FIRST_NODE);
    let mut offline = status.clone();
    offline["Peer"]["nodekey:fixture-a"]["Online"] = json!(false);
    let mut wrong_family = status.clone();
    wrong_family["Peer"]["nodekey:fixture-a"]["TailscaleIPs"] = json!(["fd7a:115c:a1e0::3"]);
    let mut disconnected = status;
    disconnected["BackendState"] = json!("Stopped");
    for (rejected_status, error) in [
        (ambiguous, "ambiguous Tailscale stable node ID"),
        (offline, "Tailscale worker is offline"),
        (wrong_family, "scheduler bind address family"),
        (disconnected, "local Tailscale backend is not online"),
    ] {
        home.write_status(&rejected_status);
        home.link(FIRST_NODE, &peer, PORT)
            .assert()
            .failure()
            .stderr(predicate::str::contains(error));
        assert_eq!(fs::read_to_string(home.config()).unwrap(), CONFIG);
    }
}

#[test]
fn refuses_conflicting_node_peer_and_port_associations() {
    let home = Home::new();
    let first_peer = Peer::generate();
    let second_peer = Peer::generate();
    home.trust(&first_peer);
    home.trust(&second_peer);
    home.link(FIRST_NODE, &first_peer, PORT).assert().success();
    let linked = fs::read(home.config()).unwrap();

    for (node, peer, port) in [
        (FIRST_NODE, &second_peer, PORT),
        (SECOND_NODE, &first_peer, PORT),
        (FIRST_NODE, &first_peer, "7444"),
    ] {
        home.link(node, peer, port)
            .assert()
            .failure()
            .stderr(predicate::str::contains("mapping conflicts"));
        assert_eq!(fs::read(home.config()).unwrap(), linked);
    }
}

#[test]
fn refuses_invalid_port_or_existing_config_without_rewriting() {
    let home = Home::new();
    let peer = Peer::generate();
    home.trust(&peer);

    for port in ["0", "65536"] {
        home.link(FIRST_NODE, &peer, port).assert().failure();
        assert_eq!(fs::read_to_string(home.config()).unwrap(), CONFIG);
    }

    for invalid in ["[scheduler\n", "[scheduler]\ntailnet_peers = 5\n"] {
        fs::write(home.config(), invalid).unwrap();
        home.link(FIRST_NODE, &peer, PORT).assert().failure();
        assert_eq!(fs::read_to_string(home.config()).unwrap(), invalid);
    }
}

#[test]
fn refuses_local_identity_and_symlinked_config() {
    let home = Home::new();
    let identity = fs::read_to_string(home.state().join("identity.key")).unwrap();
    let local_key = IdentityKeyPair::from_pem(&identity).unwrap();
    let public = local_key.public();
    let local_peer = Peer {
        id: PeerId::from_public_key_bytes(public.as_bytes()).to_hex(),
        key: hex::encode(public.as_bytes()),
    };
    home.trust(&local_peer);
    home.link(FIRST_NODE, &local_peer, PORT)
        .assert()
        .failure()
        .stderr(predicate::str::contains("own Entanglement identity"));
    assert_eq!(fs::read_to_string(home.config()).unwrap(), CONFIG);

    let other = Peer::generate();
    home.trust(&other);
    let original_path = home.0.path().join("original.toml");
    fs::rename(home.config(), &original_path).unwrap();
    symlink(&original_path, home.config()).unwrap();

    home.link(FIRST_NODE, &other, PORT).assert().failure();
    assert_eq!(fs::read_link(home.config()).unwrap(), original_path);
    assert_eq!(fs::read_to_string(&original_path).unwrap(), CONFIG);
}

#[test]
fn competing_writer_refusal_is_non_destructive_and_retry_succeeds() {
    let home = Home::new();
    let peer = Peer::generate();
    home.trust(&peer);

    // Hold the actual OS lock from another process's point of view before
    // starting the command. This exercises contention without scheduler races.
    let writer = fs::File::open(home.state()).unwrap();
    writer.try_lock().unwrap();
    home.link(FIRST_NODE, &peer, PORT)
        .assert()
        .failure()
        .stderr(predicate::str::contains(BUSY));
    assert_eq!(fs::read_to_string(home.config()).unwrap(), CONFIG);
    drop(writer);

    home.link(FIRST_NODE, &peer, PORT).assert().success();
    assert_eq!(home.routes().len(), 1);
}

#[test]
fn simultaneous_distinct_links_never_lose_a_successful_write() {
    let home = Home::new();
    let first_peer = Peer::generate();
    let second_peer = Peer::generate();
    home.trust(&first_peer);
    home.trust(&second_peer);
    let links = [(FIRST_NODE, &first_peer), (SECOND_NODE, &second_peer)];
    let start = Barrier::new(2);

    let outputs = thread::scope(|scope| {
        links
            .map(|(node, peer)| {
                let home = &home;
                let start = &start;
                scope.spawn(move || {
                    let mut cmd = home.link(node, peer, PORT);
                    start.wait();
                    cmd.output().unwrap()
                })
            })
            .map(|worker| worker.join().unwrap())
    });

    assert!(outputs.iter().any(|out| out.status.success()));
    let accepted = home.routes();
    for ((node, peer), result) in links.into_iter().zip(outputs) {
        if result.status.success() {
            assert!(accepted
                .iter()
                .any(|route| route.node_id == node && route.public_key == peer.key));
        } else {
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(stderr.contains(BUSY), "unexpected writer failure: {stderr}");
            home.link(node, peer, PORT).assert().success();
        }
    }
    let final_routes = home.routes();
    assert_eq!(final_routes.len(), 2);
    for (node, peer) in links {
        assert!(final_routes
            .iter()
            .any(|route| route.node_id == node && route.public_key == peer.key));
    }
}
