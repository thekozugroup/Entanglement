//! CLI integration tests for the `entangle mesh` subcommand.
//!
//! Tests avoid mDNS / multicast — all network-dependent paths are covered by
//! daemon-not-running assertions or direct on-disk file writes.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

// ── helpers ──────────────────────────────────────────────────────────────────

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd
}

/// Generate a valid 32-byte Ed25519 public key and return (peer_id_hex, pubkey_hex).
/// The peer_id is the PeerId::from_public_key_bytes hex (16 bytes = 32 hex chars).
fn make_test_peer() -> (String, String) {
    use entangle_signing::IdentityKeyPair;
    use entangle_types::peer_id::PeerId;
    let kp = IdentityKeyPair::generate();
    let verifying = kp.public();
    let pub_bytes = verifying.as_bytes();
    let peer_id = PeerId::from_public_key_bytes(pub_bytes);
    (peer_id.to_hex(), hex::encode(pub_bytes))
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Without a running daemon and without --allow-local, `mesh peers` must fail
/// with a message mentioning "daemon not running".
#[test]
fn mesh_peers_with_no_daemon_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["mesh", "peers"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("daemon not running"));
}

/// Without a running daemon and without --allow-local, `mesh status` must fail
/// with a message mentioning "daemon not running".
#[test]
fn mesh_status_with_no_daemon_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["mesh", "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("daemon not running"));
}

/// `entangle mesh trust <peer_id> --public-key-hex <hex> --display-name "test"`
/// must write a peers.toml in the HOME/.entangle directory.
#[test]
fn mesh_trust_writes_peers_toml() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let (peer_id, pub_hex) = make_test_peer();

    entangle(&tmp)
        .args([
            "mesh",
            "trust",
            &peer_id,
            "--public-key-hex",
            &pub_hex,
            "--display-name",
            "test-node",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("trusted"));

    let peers_toml = tmp.path().join(".entangle").join("peers.toml");
    assert!(peers_toml.exists(), "peers.toml was not created");

    let contents = std::fs::read_to_string(&peers_toml).unwrap();
    assert!(
        contents.contains("test-node"),
        "display_name not found in peers.toml: {contents}"
    );
}

/// Round-trip: trust then untrust removes the peer from peers.toml.
#[test]
fn mesh_untrust_removes_peer() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let (peer_id, pub_hex) = make_test_peer();

    // Trust the peer.
    entangle(&tmp)
        .args([
            "mesh",
            "trust",
            &peer_id,
            "--public-key-hex",
            &pub_hex,
            "--display-name",
            "to-remove",
        ])
        .assert()
        .success();

    let peers_toml = tmp.path().join(".entangle").join("peers.toml");
    let before = std::fs::read_to_string(&peers_toml).unwrap();
    assert!(before.contains("to-remove"), "peer not written");

    // Untrust the peer.
    entangle(&tmp)
        .args(["mesh", "untrust", &peer_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    let after = std::fs::read_to_string(&peers_toml).unwrap();
    assert!(
        !after.contains("to-remove"),
        "peer still present after untrust: {after}"
    );
}

/// `mesh trust` must reject a peer_id/public_key pair that does not correspond:
/// the id derived from the key must equal the supplied peer_id.
#[test]
fn mesh_trust_rejects_mismatched_id_and_key() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    // Two independent peers; cross the id of one with the pubkey of the other.
    let (peer_id_a, _pub_a) = make_test_peer();
    let (_peer_id_b, pub_b) = make_test_peer();

    entangle(&tmp)
        .args([
            "mesh",
            "trust",
            &peer_id_a,
            "--public-key-hex",
            &pub_b,
            "--display-name",
            "forged",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mismatch"));

    // Nothing should have been persisted.
    let peers_toml = tmp.path().join(".entangle").join("peers.toml");
    if peers_toml.exists() {
        let contents = std::fs::read_to_string(&peers_toml).unwrap();
        assert!(
            !contents.contains("forged"),
            "forged peer must not be written: {contents}"
        );
    }
}

/// `mesh peers --json` must emit output that parses as JSON.
#[test]
fn mesh_peers_json_parses_with_allow_local() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let out = entangle(&tmp)
        .args(["--allow-local", "mesh", "peers", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "mesh peers --json should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("mesh peers --json must emit valid JSON");
    assert!(
        value.get("peers").and_then(|p| p.as_array()).is_some(),
        "expected a `peers` array: {stdout}"
    );
}

/// `--allow-local` flag causes `mesh peers` to succeed even with no daemon.
#[test]
fn mesh_peers_with_allow_local_falls_back() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    entangle(&tmp)
        .args(["--allow-local", "mesh", "peers"])
        .assert()
        .success();
}
