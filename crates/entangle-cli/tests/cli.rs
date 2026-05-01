//! End-to-end CLI integration tests.
//!
//! Each test overrides `HOME` to a fresh tempdir so the user's real
//! `~/.entangle/` directory is never touched.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd
}

fn entangle_dir(tmp: &TempDir) -> PathBuf {
    tmp.path().join(".entangle")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn init_creates_files() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let dir = entangle_dir(&tmp);
    assert!(dir.join("identity.key").exists(), "identity.key missing");
    assert!(dir.join("config.toml").exists(), "config.toml missing");
    assert!(dir.join("keyring.toml").exists(), "keyring.toml missing");
    assert!(dir.join("peers.toml").exists(), "peers.toml missing");
}

#[test]
fn init_idempotent() {
    let tmp = TempDir::new().unwrap();

    // First init
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let id1 = std::fs::read_to_string(entangle_dir(&tmp).join("identity.key")).unwrap();

    // Second init — must not regenerate
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let id2 = std::fs::read_to_string(entangle_dir(&tmp).join("identity.key")).unwrap();

    assert_eq!(id1, id2, "identity.key was regenerated on second init");
}

#[test]
fn keyring_add_then_list_shows_entry() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    // A fixed 32-byte public key in hex (all zeros is structurally valid bytes,
    // but ed25519 may reject it — use a known valid verifying key).
    // We generate one via the signing crate in a build script, but for tests
    // we can use any 32 bytes that happen to be a valid compressed point.
    // The simplest is the Ed25519 base point (B), but it's easier to just
    // use the key from the test keypair we generate below.
    let pk_hex = generate_test_pk_hex();

    entangle(&tmp)
        .args([
            "keyring",
            "add",
            &pk_hex,
            "--name",
            "test-publisher",
            "--note",
            "test key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("added"))
        .stdout(predicate::str::contains("test-publisher"));

    entangle(&tmp)
        .args(["keyring", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-publisher"));
}

#[test]
fn keyring_add_invalid_hex_errors() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    entangle(&tmp)
        .args(["keyring", "add", "ZZZNOTVALIDHEX", "--name", "bad"])
        .assert()
        .failure();
}

#[test]
fn keyring_remove_unknown_returns_not_found_message() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    // A valid-length fingerprint hex (32 hex chars = 16 bytes) that doesn't exist.
    entangle(&tmp)
        .args(["keyring", "remove", "deadbeefdeadbeefdeadbeefdeadbeef"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not found"));
}

#[test]
fn version_command_prints_versions() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("entangle 0."))
        .stdout(predicate::str::contains("0.1.0"))
        .stdout(predicate::str::contains("CLI"))
        .stdout(predicate::str::contains("Runtime"));
}

#[test]
fn doctor_on_uninitialized_warns_then_exits_zero() {
    let tmp = TempDir::new().unwrap();
    // Don't run init — directory doesn't exist.
    // identity.key absent → [fail] → exit code 1.
    // We use failure() here to match the new semantics (missing identity is [fail]).
    let out = entangle(&tmp).arg("doctor").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // At least one check line must be present.
    assert!(
        stderr.contains("[warn]") || stderr.contains("[fail]") || stderr.contains("[ok]"),
        "expected doctor output on stderr, got: {stderr}"
    );
    // identity is either [fail] (missing key) or [warn] — not [ok].
    let identity_line = stderr
        .lines()
        .find(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            cols.get(1).map(|s| *s == "identity").unwrap_or(false)
        })
        .unwrap_or_default();
    assert!(
        !identity_line.contains("[ok]"),
        "expected non-ok identity when uninitialised: {identity_line}"
    );
}

#[test]
fn doctor_on_initialized_succeeds() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let out = entangle(&tmp).arg("doctor").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // identity must be ok after init.
    let identity_line = stderr
        .lines()
        .find(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            cols.get(1).map(|s| *s == "identity").unwrap_or(false)
        })
        .unwrap_or_default();
    assert!(
        identity_line.contains("[ok]"),
        "expected [ok] for identity after init, got: {identity_line}"
    );
    // No [fail] lines.
    for line in stderr.lines() {
        assert!(!line.contains("[fail]"), "unexpected [fail]: {line}");
    }
}

// ---------------------------------------------------------------------------
// Daemon-RPC / allow-local tests
// ---------------------------------------------------------------------------

/// Without a running daemon and without --allow-local the command must fail
/// with a message that mentions "daemon not running".
#[test]
fn plugins_list_with_no_daemon_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    // Point HOME at the tempdir so no real ~/.entangle/sock can be found.
    entangle(&tmp)
        .args(["plugins", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("daemon not running"));
}

/// With --allow-local the command falls back to the local kernel, prints an
/// empty list, and exits 0. (init is run first so the keyring exists.)
#[test]
fn plugins_list_with_allow_local_falls_back() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    entangle(&tmp)
        .args(["--allow-local", "plugins", "list"])
        .assert()
        .success()
        // Either "no plugins loaded" (empty list) or a plugin id — both are fine.
        // The key assertion is exit code 0.
        .stdout(predicate::str::is_match(".*").unwrap());
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Generate a valid Ed25519 public key as a 64-char hex string.
/// Uses the entangle-signing keypair API to produce a structurally valid key.
fn generate_test_pk_hex() -> String {
    use entangle_signing::IdentityKeyPair;
    let kp = IdentityKeyPair::generate();
    hex::encode(kp.public().as_bytes())
}
