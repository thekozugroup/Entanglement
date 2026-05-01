//! Integration tests for `entangle version`.
//!
//! Each test sets HOME to a fresh tempdir so the real ~/.entangle/ is never touched.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `version` prints all crate section headers and a version string.
#[test]
fn version_prints_all_crate_versions() {
    let tmp = TempDir::new().unwrap();

    let assert = entangle(&tmp).arg("version").assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Header line
    assert!(
        stdout.contains("entangle 0."),
        "Missing top-level version header: {stdout}"
    );

    // Crate table rows
    for name in &[
        "CLI",
        "Runtime",
        "Types",
        "Manifest",
        "Signing",
        "Wit",
        "RPC",
        "Pairing",
        "Biscuits",
        "Scheduler",
        "Mesh-local",
        "Peers",
    ] {
        assert!(
            stdout.contains(name),
            "Missing crate row '{name}': {stdout}"
        );
    }

    // Section headers
    for section in &["Daemon", "Build", "Identity"] {
        assert!(
            stdout.contains(section),
            "Missing section '{section}': {stdout}"
        );
    }
}

/// Without a daemon socket, `version` still exits 0 and says "(not reachable)".
#[test]
fn version_with_no_daemon_says_not_reachable() {
    let tmp = TempDir::new().unwrap();
    // No daemon running; socket file will be absent.

    entangle(&tmp)
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("not reachable"));
}

/// Without identity.key, `version` says "(not configured)" for fingerprint.
#[test]
fn version_with_no_identity_says_not_configured() {
    let tmp = TempDir::new().unwrap();
    // Skip init — no identity.key present.

    entangle(&tmp)
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("not configured"));
}
