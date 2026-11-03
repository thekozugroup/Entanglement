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
        .stdout(predicate::str::contains("gpu"))
        .stdout(predicate::str::contains("semantic-equivalent"))
        .stdout(predicate::str::contains("--metric"))
        .stdout(predicate::str::contains("--metric-dir"))
        .stdout(predicate::str::contains("--threshold"))
        .stdout(predicate::str::contains("--quorum"))
        .stdout(predicate::str::contains("--json"));
}

/// `semantic-equivalent` needs a metric and a threshold; the CLI says so
/// before contacting anything.
#[test]
fn semantic_equivalent_requires_metric_and_threshold() {
    let tmp = TempDir::new().unwrap();
    let plugin = "0123456789abcdef0123456789abcdef/demo@0.1.0";
    let metric = "0123456789abcdef0123456789abcdef/metric-bleu-4@0.1.0";
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            plugin,
            "--integrity",
            "semantic-equivalent",
        ])
        .args(["--threshold", "0.2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--metric"));
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            plugin,
            "--integrity",
            "semantic-equivalent",
        ])
        .args(["--metric", metric])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--threshold"));
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            plugin,
            "--integrity",
            "semantic-equivalent",
        ])
        .args(["--metric", metric, "--threshold", "0.2", "--replicas", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--replicas 2"));
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            plugin,
            "--integrity",
            "semantic-equivalent",
        ])
        .args(["--metric", metric, "--threshold", "nan"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--threshold"));
}

/// A well-formed semantic-equivalent request gets as far as the daemon: the
/// remaining error is the usual "daemon not running", not a flag problem.
#[test]
fn semantic_equivalent_flags_parse_through_to_the_daemon_call() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            "0123456789abcdef0123456789abcdef/demo@0.1.0",
            "--integrity",
            "semantic-equivalent",
            "--metric",
            "0123456789abcdef0123456789abcdef/metric-bleu-4@0.1.0",
            "--threshold",
            "0.15",
            "--replicas",
            "3",
            "--quorum",
            "2",
            "--json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not running"));
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
