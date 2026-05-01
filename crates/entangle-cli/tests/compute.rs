//! CLI integration tests for the `entangle compute` subcommand.

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

/// `entangle compute dispatch --help` must list all expected flags.
#[test]
fn compute_dispatch_help_lists_all_flags() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["compute", "dispatch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("integrity"))
        .stdout(predicate::str::contains("replicas"))
        .stdout(predicate::str::contains("allow"))
        .stdout(predicate::str::contains("timeout-ms"))
        .stdout(predicate::str::contains("cpu-cores"))
        .stdout(predicate::str::contains("memory-bytes"))
        .stdout(predicate::str::contains("gpu"));
}

/// Without a daemon running (and without --allow-local), `compute dispatch`
/// must fail with a clear error message.
#[test]
fn compute_dispatch_with_no_daemon_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    // Point the socket at a path that will never exist.
    entangle(&tmp)
        .args(["compute", "dispatch", "pub/nonexistent@0.1.0"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("daemon not running")
                .or(predicate::str::contains("not running")),
        );
}

/// The `compute` subcommand itself should require a subcommand.
#[test]
fn compute_subcommand_required() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp).arg("compute").assert().failure();
}

/// `entangle compute --help` should mention dispatch.
#[test]
fn compute_help_mentions_dispatch() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["compute", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dispatch"));
}
